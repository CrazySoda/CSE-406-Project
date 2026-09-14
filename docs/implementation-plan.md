# Implement: Packet Sniffing Attack (HTTP/Telnet password sniffer) — CSE406 Group 10

## Context

The Design Report (Group 10) specifies a passive packet-sniffing attack: an attacker VM in
promiscuous mode captures raw Ethernet frames on a shared LAN segment, manually parses
Ethernet → IPv4 → TCP with Python's `struct`, and extracts clear-text credentials from HTTP
Basic-Auth and Telnet sessions between a victim and a server VM. The design report is done
(11th week deliverable); this implementation is the code + demo setup needed for the Final
Report/Demo (13th-14th week), per the course requirement that the tool be **entirely
self-written** — no scapy/Wireshark-as-a-library/etc., raw sockets and manual header parsing
only.

Environment: 3 VirtualBox VMs (victim, server, attacker) on one VirtualBox **Internal Network**,
matching the report's hub/mirrored-segment assumption.

## Directory layout (under `Project/`)

```
sniffer/sniffer.py        # attacker: raw-socket sniffer + credential extractor
server/http_server.py     # server: minimal HTTP server with Basic Auth on :80
server/setup_telnet.sh    # server: installs/enables a telnet daemon on :23
victim/http_login.py      # victim: scripted HTTP Basic-Auth login (generates traffic)
victim/telnet_login.py    # victim: scripted Telnet login (generates traffic)
SETUP.md                  # VM networking + run steps for the demo
docs/implementation-plan.md  # this file
```

## 1. VirtualBox networking (see `SETUP.md`)

- Create 3 VMs (victim, server, attacker), each with a second NIC attached to the same
  **Internal Network** name (e.g. `intnet0`) — first NIC stays NAT for internet/package installs.
- Internal Network in VirtualBox switches on learned MAC addresses like a real switch, so the
  attacker will *not* see victim↔server unicast frames by default. Fix: on the attacker VM's
  `intnet0` adapter, set **Promiscuous Mode → Allow All** in VM settings (Network → Advanced).
  This makes VirtualBox's virtual switch deliver all frames on that segment to the attacker,
  reproducing the report's hub/mirrored-port assumption without needing a real hub.
- Static IPs on the `intnet0` subnet (e.g. 192.168.56.11 victim, .12 server, .13 attacker) so
  scripts don't depend on DHCP.

## 2. Server (`server/`)

- `http_server.py`: Python 3 `http.server.BaseHTTPRequestHandler` subclass that returns 401 with
  `WWW-Authenticate: Basic` until it sees a valid `Authorization: Basic <b64>` header, then serves
  a simple page. One hardcoded demo user (`bob:hunter2`).
- `setup_telnet.sh`: installs `inetutils-telnetd` (or `telnetd` + `xinetd`) via apt, enables the
  service on port 23, and creates a demo Linux user account (`bob`) for the telnet login.

## 3. Victim (`victim/`)

- `http_login.py`: uses `urllib.request` (stdlib) to hit `http://<server-ip>/` with Basic Auth
  credentials, so it actually sends the `Authorization: Basic` header in the clear.
- `telnet_login.py`: a tiny raw-socket telnet client (stdlib `socket` only, since `telnetlib`
  is removed in Python 3.13+) that connects to the server and types username/password one
  keystroke at a time — mirroring how a real telnet client sends near-per-keystroke TCP
  segments, which the sniffer's reassembly logic needs to handle.

## 4. Sniffer (`sniffer/sniffer.py`) — the core deliverable

- Opens `socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))` bound to the
  given interface; no `libpcap`/scapy.
- Manual struct unpacking:
  - Ethernet: `struct.unpack("!6s6sH", frame[0:14])` → dst MAC, src MAC, EtherType; continue only
    if EtherType == `0x0800`.
  - IPv4: unpack the 20-byte base header (`!BBHHHBBH4s4s`), read IHL for options length,
    confirm Protocol == 6 (TCP), extract src/dst IP.
  - TCP: unpack the 20-byte base header (`!HHLLBBHHH`), read Data Offset to find payload start,
    extract src/dst port.
  - Only process frames where port 80 or 23 is involved; else skip.
- HTTP path: buffer bytes per TCP 4-tuple until a full line boundary, search for
  `Authorization: Basic <b64>`, base64-decode it, split on `:` → username/password.
- Telnet path: per-connection buffer keyed by the 4-tuple (both directions); accumulate bytes,
  watch for `login:` / `Password:` prompts to know which buffered line is username vs password
  (per-keystroke reassembly since Telnet often sends 1 byte per TCP segment).
- Output: live console line per capture (timestamp, src/dst MAC+IP+port, protocol) plus a
  highlighted line whenever a credential pair is recovered; also appends to a session log file.
- Must run as root (`sudo python3 sniffer.py <iface>`) for `AF_PACKET`/promiscuous capture.

## 5. Verification (end-to-end)

1. Bring up all 3 VMs, confirm they can ping each other on `intnet0`.
2. Start `tcpdump -i intnet0` on the attacker VM in parallel with the sniffer, to cross-check
   packet counts/fields.
3. Start `server/http_server.py` and the telnet daemon on the server VM.
4. Start `sniffer/sniffer.py` on the attacker VM.
5. Run `victim/http_login.py` — confirm the sniffer prints the correct decoded
   `username:password`.
6. Run `victim/telnet_login.py` — confirm the sniffer reconstructs the correct username and
   password from the per-keystroke segments.
7. Confirm timing: victim/server logins complete normally and at the same speed whether or not
   the sniffer is running (non-interference criterion).
