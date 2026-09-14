#!/usr/bin/env python3
"""
Minimal stand-in for a real Telnet daemon, used ONLY for local dev/testing
of the sniffer without needing to install/root-configure a system telnetd
(inetutils-telnetd) on this machine. On the actual demo VMs, use the real
`telnetd` via server/setup_telnet.sh instead -- this script is not part of
the graded attack surface, it just emits the same login:/Password: prompt
sequence and byte-by-byte echo behavior a real telnet session produces, so
the sniffer's reassembly logic can be exercised end-to-end on loopback.

Usage:
    python3 mock_telnet_server.py [port]
"""

import socket
import sys

USERNAME = "bob"
PASSWORD = "hunter2"


def handle_client(conn: socket.socket):
    conn.sendall(b"Debian GNU/Linux\r\nlogin: ")
    username = read_line(conn)
    conn.sendall(b"Password: ")
    password = read_line(conn)

    if username == USERNAME and password == PASSWORD:
        conn.sendall(f"\r\nLast login: just now\r\n{username}@server:~$ ".encode())
    else:
        conn.sendall(b"\r\nLogin incorrect\r\nlogin: ")
    conn.close()


def read_line(conn: socket.socket) -> str:
    # Read until LF: the client sends "\r\n" as line terminator, so waiting
    # specifically for "\n" (rather than stopping at the first "\r") ensures
    # both terminator bytes are drained here and none are left dangling in
    # the socket buffer to be misread as the start of the next line.
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\r")[0].split(b"\n")[0].decode(errors="replace").strip()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2323
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"[mock_telnet_server] listening on :{port} (demo user: {USERNAME}:{PASSWORD})")
    try:
        while True:
            conn, addr = srv.accept()
            print(f"[mock_telnet_server] connection from {addr}")
            handle_client(conn)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
