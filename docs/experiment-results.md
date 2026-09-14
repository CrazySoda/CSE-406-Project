# Experiment Results — Packet Sniffing Attack

**Setup:** 3 VirtualBox VMs (Ubuntu Server 24.04.5) — `victim` (192.168.56.11), `server`
(192.168.56.12), `attacker` (192.168.56.13) — on one Internal Network, attacker's adapter in
Promiscuous Mode "Allow All". Server ran `http_server.py` (HTTP Basic-Auth, :80) and the real
system `telnetd` (:23), demo account `bob:hunter2`. Attacker ran `sniffer.py enp0s8` as root, a
purely passive raw-socket capture — no packets sent toward victim or server.

## Run

1. `victim` performed a normal HTTP Basic-Auth login and a normal interactive Telnet login to
   `server`, both succeeding exactly as they would with no sniffer present.
2. `attacker`'s sniffer, listening the whole time, printed a line per captured HTTP/Telnet frame
   and recovered both credential pairs:

   ```
   *** HTTP credentials recovered: bob:hunter2 ***
   *** Telnet credentials recovered: bob:hunter2 ***
   ```

3. A parallel `tcpdump -i enp0s8 'port 80 or port 23'` capture on the attacker (`capture.pcap`,
   110 packets) cross-checks the same window: identical source/destination IPs, ports, and
   timestamps as the sniffer's own log — confirming the sniffer isn't fabricating results and is
   reading the same wire traffic Wireshark would show.

## Outcome

| Criterion | Result |
|---|---|
| Correctness | Recovered `bob:hunter2` exactly for both HTTP and Telnet, matching what the victim typed |
| Non-interference | Victim's HTTP request and Telnet session completed normally (200 OK / shell prompt) with the sniffer running throughout |
| Passivity | Sniffer only ever called `recvfrom()`; `tcpdump` confirms zero frames sourced from the attacker's MAC toward victim or server |

## Artifacts

- `docs/captures/capture.pcap` — Wireshark-openable trace of the capture window
- `docs/captures/sniffer_session.log` — sniffer's full per-packet log plus the two credential-recovery lines

## Issues hit and fixed during the run

- `sniffer.py` had hardcoded ports 80/23 — made configurable via CLI args (needed for local
  testing on non-privileged ports; VM demo still uses the real 80/23).
- Real `telnetd` sends Telnet IAC option-negotiation bytes before the login banner, which neither
  the original `victim/telnet_login.py` client nor `sniffer.py`'s credential extraction handled —
  both patched to strip/negotiate IAC correctly.
- Ubuntu's `inetutils-telnetd` package ships no `/etc/xinetd.d/telnet` config (unlike some other
  distros) — `server/setup_telnet.sh` now writes one instead of assuming it exists.
