#!/usr/bin/env python3
"""Network probe for App Platform cross-tenant reachability testing."""
import http.server
import json
import socket
import subprocess
import os
import urllib.parse

class ProbeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == '/':
            # Basic info
            hostname = socket.gethostname()
            try:
                local_ip = subprocess.check_output(
                    "hostname -I", shell=True, timeout=5
                ).decode().strip()
            except:
                local_ip = "unknown"
            try:
                dns_servers = open('/etc/resolv.conf').read()
            except:
                dns_servers = "unknown"
            result = {
                "hostname": hostname,
                "local_ip": local_ip,
                "resolv_conf": dns_servers,
                "env_keys": sorted(os.environ.keys()),
            }
            self._respond(200, result)

        elif parsed.path == '/probe':
            # TCP probe: /probe?host=IP&port=PORT
            host = params.get('host', [''])[0]
            port = int(params.get('port', ['80'])[0])
            timeout = float(params.get('timeout', ['3'])[0])
            result = self._tcp_probe(host, port, timeout)
            self._respond(200, result)

        elif parsed.path == '/scan':
            # Scan a range: /scan?base=100.127.13&start=1&end=20&port=8080
            base = params.get('base', ['100.127.13'])[0]
            start = int(params.get('start', ['1'])[0])
            end = int(params.get('end', ['20'])[0])
            port = int(params.get('port', ['8080'])[0])
            timeout = float(params.get('timeout', ['2'])[0])
            results = []
            for i in range(start, end + 1):
                ip = f"{base}.{i}"
                r = self._tcp_probe(ip, port, timeout)
                results.append(r)
            self._respond(200, {"scan": results})

        elif parsed.path == '/http':
            # HTTP fetch: /http?url=http://IP:PORT/path
            url = params.get('url', [''])[0]
            timeout = float(params.get('timeout', ['5'])[0])
            result = self._http_fetch(url, timeout)
            self._respond(200, result)

        elif parsed.path == '/dns':
            # DNS lookup: /dns?name=HOST&type=PTR
            name = params.get('name', [''])[0]
            qtype = params.get('type', ['A'])[0]
            try:
                out = subprocess.check_output(
                    ["dig", "+short", qtype, name], timeout=5
                ).decode().strip()
                result = {"name": name, "type": qtype, "result": out}
            except Exception as e:
                result = {"name": name, "type": qtype, "error": str(e)}
            self._respond(200, result)

        elif parsed.path == '/health':
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "not found"})

    def _tcp_probe(self, host, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result_code = sock.connect_ex((host, port))
            if result_code == 0:
                # Try to read banner
                try:
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
                    sock.settimeout(2)
                    banner = sock.recv(1024).decode('utf-8', errors='replace')
                except:
                    banner = "(connected, no banner)"
                sock.close()
                return {"host": host, "port": port, "open": True, "banner": banner[:500]}
            else:
                sock.close()
                return {"host": host, "port": port, "open": False, "error": f"connect_ex={result_code}"}
        except socket.timeout:
            return {"host": host, "port": port, "open": False, "error": "timeout"}
        except Exception as e:
            return {"host": host, "port": port, "open": False, "error": str(e)}

    def _http_fetch(self, url, timeout=5):
        import urllib.request
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "probe/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(2048).decode('utf-8', errors='replace')
                return {"url": url, "status": resp.status, "headers": dict(resp.headers), "body": body[:1000]}
        except Exception as e:
            return {"url": url, "error": str(e)}

    def _respond(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def log_message(self, format, *args):
        pass  # Quiet

if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8080'))
    server = http.server.HTTPServer(('0.0.0.0', port), ProbeHandler)
    print(f"Probe server on port {port}")
    server.serve_forever()
