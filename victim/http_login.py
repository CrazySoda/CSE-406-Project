#!/usr/bin/env python3
"""
Victim-side script: performs an HTTP Basic-Auth login against the demo
server, generating the plaintext Authorization header that the sniffer is
meant to recover.

Usage:
    python3 http_login.py <server-ip> [username] [password] [port]
"""

import sys
import urllib.request


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <server-ip> [username] [password] [port]",
              file=sys.stderr)
        sys.exit(1)

    server_ip = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else "bob"
    password = sys.argv[3] if len(sys.argv) > 3 else "hunter2"
    port = sys.argv[4] if len(sys.argv) > 4 else "80"

    url = f"http://{server_ip}:{port}/"

    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, url, username, password)
    handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
    opener = urllib.request.build_opener(handler)

    print(f"[victim] Logging in to {url} as {username}...")
    with opener.open(url, timeout=5) as resp:
        body = resp.read().decode(errors="replace")
        print(f"[victim] Server responded {resp.status}: {body.strip()}")


if __name__ == "__main__":
    main()
