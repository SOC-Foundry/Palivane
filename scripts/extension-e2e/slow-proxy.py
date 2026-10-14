#!/usr/bin/env python3
"""Forwards to the Palivane server after a fixed delay: a stand-in for a slow or cold backend."""
import argparse, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_handler(target, delay):
    class P(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def _go(self):
            n = int(self.headers.get('content-length') or 0)
            body = self.rfile.read(n) if n else None
            time.sleep(delay)
            req = urllib.request.Request(target + self.path, data=body, method=self.command,
                                         headers={k: v for k, v in self.headers.items() if k.lower() not in ('host', 'content-length')})
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    code, data, ct = r.status, r.read(), r.headers.get('content-type', 'application/json')
            except urllib.error.HTTPError as e:
                code, data, ct = e.code, e.read(), e.headers.get('content-type', 'application/json')
            self.send_response(code); self.send_header('content-type', ct); self.send_header('content-length', str(len(data)))
            self.send_header('access-control-allow-origin', '*'); self.end_headers(); self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _go

        def do_OPTIONS(self):
            self.send_response(204); self.send_header('access-control-allow-origin', '*')
            self.send_header('access-control-allow-headers', '*'); self.send_header('access-control-allow-methods', '*'); self.end_headers()
    return P


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True); ap.add_argument('--target', required=True); ap.add_argument('--delay', type=float, default=5.0)
    a = ap.parse_args()
    ThreadingHTTPServer(('127.0.0.1', a.port), make_handler(a.target.rstrip('/'), a.delay)).serve_forever()
