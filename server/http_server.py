#!/usr/bin/env python3
"""
Minimal HTTP server with HTTP Basic Authentication, used as the "victim
server" for the packet-sniffing demo. Intentionally plain HTTP (no TLS) so
the Authorization header travels in the clear on the wire, as required by
the attack being demonstrated.

Usage:
    python3 http_server.py [port]

Default demo credentials: bob / hunter2
"""

import base64
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

USERNAME = "bob"
PASSWORD = "hunter2"
REALM = "CSE406 Demo Server"


class BasicAuthHandler(BaseHTTPRequestHandler):
    def _valid_auth(self) -> bool:
        header = self.headers.get("Authorization")
        if not header or not header.startswith("Basic "):
            return False
        b64_cred = header.split(" ", 1)[1]
        try:
            decoded = base64.b64decode(b64_cred).decode()
        except Exception:
            return False
        return decoded == f"{USERNAME}:{PASSWORD}"

    def _require_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", f'Basic realm="{REALM}"')
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Authentication required.\n")

    def do_GET(self):
        if not self._valid_auth():
            self._require_auth()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Welcome, authenticated user.\n")

    def log_message(self, fmt, *args):
        print(f"[http_server] {self.address_string()} - {fmt % args}")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    server = HTTPServer(("0.0.0.0", port), BasicAuthHandler)
    print(f"HTTP Basic-Auth server listening on :{port} "
          f"(demo user: {USERNAME}:{PASSWORD})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
