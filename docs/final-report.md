# CSE406 Final Report — Packet Sniffing Attack (Group 10)

Members: 2105128 - Nakib Arman, 2105143 - Fatin Ishrak Arian
*(fill in per-member contribution split before submission)*

## a. Steps of the attack, with screenshots

**Topology:** 3 VirtualBox VMs, Ubuntu Server 24.04, one Internal Network (`sniffnet`,
192.168.56.0/24) — `victim` (.11), `server` (.12, HTTP Basic-Auth on :80 + Telnet on :23),
`attacker` (.13, NIC in Promiscuous Mode "Allow All"). Full setup steps in `docs/SETUP.md`.

1. `server` runs `server/http_server.py` (HTTP Basic-Auth) and the real system `telnetd`,
   demo account `bob:hunter2`.
2. `attacker` runs `sniffer/sniffer.py enp0s8` as root — a raw `AF_PACKET` socket, hand-parsed
   Ethernet/IPv4/TCP headers, watching ports 80 and 23. Purely passive: no packets sent.
3. `victim` performs a normal HTTP Basic-Auth login and a normal interactive Telnet login.

   ![Victim Telnet login](screenshots/victim_telnet_login.png)

4. `attacker`'s sniffer captures both, live, from the shared segment:

   ![Attacker sniffer log](screenshots/attacker_sniffer_log.png)

   Recovered:
   ```
   *** HTTP credentials recovered: bob:hunter2 ***
   *** Telnet credentials recovered: bob:hunter2 ***
   ```

## b. Was the attack successful? Why / why not?

**Yes**, fully successful, on both target protocols:

- **Correctness** — the recovered `bob:hunter2` exactly matches what the victim typed, for both
  HTTP and Telnet, verified over multiple independent runs.
- **Non-interference** — the victim's HTTP request (200 OK) and Telnet session (full shell
  access) completed identically whether or not the sniffer was running; the attacker never
  transmits anything.
- **Why it worked**: HTTP Basic-Auth and Telnet both send credentials as clear text inside the
  TCP payload. Once a NIC receives a copy of those frames (here, via Promiscuous Mode on a
  shared VirtualBox Internal Network — reproducing a hub or mirrored switch port), recovering
  the credentials is just base64-decoding (HTTP) or reassembling per-keystroke TCP segments
  between the `login:`/`Password:` prompts (Telnet). No cryptography is broken and the victim
  never interacts with the attacker.
- Cross-checked against an independent `tcpdump` capture (`docs/captures/capture.pcap`,
  110 packets) over the same window — identical IPs, ports and timestamps, confirming the
  sniffer isn't fabricating output.

## c. Observed output — attacker, victim, server

| PC | Observed output |
|---|---|
| **Attacker** | Per-frame log line (timestamp, src/dst MAC+IP+port, protocol) for every HTTP/Telnet frame on the segment; `*** ... credentials recovered ***` line for each successful login. Full log: `docs/captures/sniffer_session.log`. |
| **Victim** | HTTP login: `Server responded 200: Welcome, authenticated user.` Telnet login: normal banner → `login:` → `Password:` → shell prompt (`docs/screenshots/victim_telnet_login.png`) — no indication anything is being observed. |
| **Server** | Serves both `bob:hunter2` logins normally; `ss -tln` confirms it is simply listening on :80/:23 (and, after the defense was added, :22) with no awareness of the attacker (`docs/screenshots/server_listening_ports.png`). |

## d. Countermeasure (bonus)

Implemented and tested: replacing Telnet with SSH for the same login. Full writeup, capture, and
byte-level proof that the password is unrecoverable in `docs/defense.md` — summary:

```
$ strings ssh_defense_capture.pcap | grep -c hunter2
0
```

versus trivial recovery for the unencrypted case. SSH login still succeeds normally for the
legitimate user (`docs/screenshots/victim_ssh_login2.png`) — the defense blocks the attack, not
the service.

## Artifacts index

- `docs/SETUP.md` — VM creation & networking (VBoxManage, unattended install)
- `docs/RUNNING.md` — local (non-VM) smoke-test instructions
- `docs/experiment-results.md` — condensed technical run summary
- `docs/defense.md` — countermeasure design, implementation, and proof
- `docs/captures/` — `capture.pcap` (HTTP+Telnet), `ssh_defense_capture.pcap`, `sniffer_session.log`
- `docs/screenshots/` — victim Telnet/SSH login, attacker sniffer log, server listening ports
