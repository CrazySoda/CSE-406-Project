# CSE406 Final Report — Packet Sniffing Attack (Group 10)

Members: 2105128 - Nakib Arman, 2105143 - Fatin Ishrak Arian
*(fill in per-member contribution split before submission)*

## a. Steps of the attack, with screenshots

**Topology:** 3 VirtualBox VMs, Ubuntu Server 24.04, one Internal Network (`sniffnet`,
192.168.56.0/24) — `victim` (.11), `server` (.12, HTTP Basic-Auth on :80 + Telnet on :23),
`attacker` (.13, NIC in Promiscuous Mode "Allow All"). Full setup steps in `docs/SETUP.md`.

1. `server` runs `server/http_server.py` (HTTP Basic-Auth, account `arzon:2105128`) and the real
   system `telnetd` (account `arian:2105143`) — separate accounts per protocol.
2. `attacker` runs `sniffer/sniffer.py enp0s8` as root — a raw `AF_PACKET` socket, hand-parsed
   Ethernet/IPv4/TCP headers, watching ports 80 and 23. Purely passive: no packets sent.
3. `victim` performs a normal HTTP Basic-Auth login and a normal interactive Telnet login.

   ![Victim Telnet login](screenshots/victim_telnet_login.png)

4. `attacker`'s sniffer captures both, live, from the shared segment:

   ![Attacker sniffer log](screenshots/attacker_sniffer_log.png)

   Recovered:
   ```
   *** HTTP credentials recovered: arzon:2105128 ***
   *** Telnet credentials recovered: arian:2105143 ***
   ```

### How the attacker actually recovers the username and password

The sniffer never sees a "username" or "password" field as such — it only ever sees raw bytes on
the wire. Recovery happens in two different ways depending on protocol, both implemented in
`sniffer/sniffer.py`:

- **HTTP** — the victim's browser/client sends the header `Authorization: Basic <base64>` on
  every request once authenticated. The sniffer's `handle_http()` buffers each TCP stream's bytes,
  regex-searches for that header, and simply **base64-decodes** the value — `arzon:2105128` is
  right there in the decoded text, because Basic-Auth is *encoded*, not encrypted.
- **Telnet** — there is no single "credentials packet" at all. The server sends a `login:` prompt,
  the client's keystrokes for the username arrive as individual TCP segments (often one byte
  each), then the server sends `Password:`, then the password keystrokes arrive the same way. The
  sniffer's `handle_telnet()` watches the server→client direction for those two prompts to know
  which stage it's in, buffers the client→server bytes until a line terminator, and hands the
  first completed line to `telnet_username` and the second to the final recovered pair.

Below is the sniffer's own log, filtered to show exactly this happening: three raw per-frame
capture lines immediately followed by the extraction result, for both protocols in the same run:

![Attacker credentials recovered](screenshots/attacker_credentials_recovered.png)

The `[...]` line is not a separate event — it is the *same frame* as the raw line right above it,
re-printed with the decoded/reassembled credential once the sniffer's parser recognizes it
completes a login. Nothing is guessed or brute-forced; every byte was already sitting in the
payload the attacker's promiscuous NIC received.

**Is the password visible in the raw `tcpdump` capture itself, without the sniffer?** Depends on
the protocol — checked directly against `docs/captures/capture.pcap`:

```
$ strings capture.pcap | grep -i authorization
Authorization: Basic YXJ6b246MjEwNTEyOA==
$ echo YXJ6b246MjEwNTEyOA== | base64 -d
arzon:2105128
```

For **HTTP**, yes — the whole header, `arzon:2105128` included, sits as one contiguous string in
the raw capture. Base64 isn't encryption; any tool that can `strings`/`grep` a pcap and pipe the
match through `base64 -d` recovers it, no custom sniffer required.

```
$ strings capture.pcap | grep -c 2105143
0
```

For **Telnet**, the string `2105143` (the Telnet account's password) never appears as one
contiguous run of bytes anywhere in the capture — real Telnet sends one keystroke per TCP packet,
so the password is scattered as seven separate single-byte packets (`2`, `1`, `0`, `5`, `1`, `4`,
`3`). It *is* fully present in the
capture (nothing is missing — see the raw per-frame lines in the screenshot above, and Wireshark's
**Follow → TCP Stream** will visually reassemble it for a human), but no simple string search
finds it. This is exactly why `sniffer.py`'s `handle_telnet()` exists: it buffers the
client→server bytes packet-by-packet and reassembles them into a line itself, rather than relying
on the credential already being one searchable string the way HTTP's is.

## b. Was the attack successful? Why / why not?

**Yes**, fully successful, on both target protocols:

- **Correctness** — the recovered `arzon:2105128` (HTTP) and `arian:2105143` (Telnet) exactly
  match what the victim typed, verified over multiple independent runs.
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
| **Server** | Serves both the `arzon:2105128` (HTTP) and `arian:2105143` (Telnet) logins normally; `ss -tln` confirms it is simply listening on :80/:23 (and, after the defense was added, :22) with no awareness of the attacker (`docs/screenshots/server_listening_ports.png`). |

## d. Countermeasure (bonus)

Implemented and tested: replacing Telnet with SSH for the same account (`arian:2105143`). Full
writeup, capture, and byte-level proof that the password is unrecoverable in `docs/defense.md` —
summary:

```
$ strings ssh_defense_capture.pcap | grep -c 2105143
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
