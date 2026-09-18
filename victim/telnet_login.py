#!/usr/bin/env python3
"""
Victim-side script: a minimal raw-socket Telnet client (no `telnetlib`,
which is removed in Python 3.13+) that logs in to the demo server and types
the username/password one character at a time, so that the traffic on the
wire matches a real interactive telnet session (near-per-keystroke TCP
segments) -- this is what the sniffer's reassembly logic is built to handle.

Usage:
    python3 telnet_login.py <server-ip> [username] [password] [port]
"""

import socket
import sys
import time

RECV_CHUNK = 4096

# Minimal Telnet IAC (RFC 854) option-negotiation handling. A real telnetd
# (unlike the local mock server) sends IAC WILL/DO option requests before
# anything else and waits for a response before showing the login banner.
# We don't need to actually support any option -- refusing everything
# (DONT/WONT) is a valid client response that unblocks the server.
IAC, WILL, WONT, DO, DONT = 255, 251, 252, 253, 254


def strip_and_answer_iac(sock: socket.socket, data: bytes) -> bytes:
    """Remove IAC negotiation sequences from data, replying to each
    WILL/DO request with DONT/WONT so the server proceeds. Returns the
    remaining plain-text bytes."""
    clean = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            cmd, opt = data[i + 1], data[i + 2]
            if cmd == WILL:
                sock.sendall(bytes([IAC, DONT, opt]))
            elif cmd == DO:
                sock.sendall(bytes([IAC, WONT, opt]))
            # WONT/DONT from the server need no reply.
            i += 3
        else:
            clean.append(data[i])
            i += 1
    return bytes(clean)


def read_until(sock: socket.socket, marker: bytes, timeout=5.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    start = time.time()
    while marker.lower() not in buf.lower():
        if time.time() - start > timeout:
            break
        try:
            data = sock.recv(RECV_CHUNK)
        except socket.timeout:
            break
        if not data:
            break
        buf += strip_and_answer_iac(sock, data)
    return buf


def type_slowly(sock: socket.socket, text: str, delay: float = 0.05):
    """Send one byte per TCP write, like a real interactive telnet client."""
    for ch in text:
        sock.sendall(ch.encode())
        time.sleep(delay)
    sock.sendall(b"\r\n")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <server-ip> [username] [password] [port]",
              file=sys.stderr)
        sys.exit(1)

    server_ip = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else "arian"
    password = sys.argv[3] if len(sys.argv) > 3 else "2105143"
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 23

    print(f"[victim] Connecting to telnet://{server_ip}:{port} ...")
    with socket.create_connection((server_ip, port), timeout=5) as sock:
        banner = read_until(sock, b"login:")
        print(f"[victim] Server: {banner.decode(errors='replace').strip()}")

        print(f"[victim] Typing username: {username}")
        type_slowly(sock, username)

        prompt = read_until(sock, b"password:")
        print(f"[victim] Server: {prompt.decode(errors='replace').strip()}")

        print("[victim] Typing password: ****")
        type_slowly(sock, password)

        result = read_until(sock, b"$", timeout=3.0)
        print(f"[victim] Server: {result.decode(errors='replace').strip()}")


if __name__ == "__main__":
    main()
