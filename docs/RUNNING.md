# How to Run This Project

Two ways to run it:

- **A. Local smoke test** — everything on this one machine, over `lo`. Good for proving the
  code works before touching VirtualBox. This is what I already ran and verified (server +
  victim side); you need to run the sniffer step yourself since it needs `sudo`.
- **B. Real 3-VM demo** — the actual graded setup from `SETUP.md` (victim/server/attacker VMs).

All commands assume you're in the project root:
`cd /home/fatin-ishrak-arian/CSE-406/Project`

Everything is stdlib-only Python, run through `uv` (no manual venv/pip needed — `uv run` creates
and reuses `.venv` automatically).

---

## A. Local smoke test (same machine, loopback interface `lo`)

You'll use **3 terminals**.

### Terminal 1 — start the servers

```bash
# HTTP Basic-Auth demo server on :8080 (unprivileged port, no sudo needed)
uv run python server/http_server.py 8080
```

Leave it running. It prints `HTTP Basic-Auth server listening on :8080 (demo user: bob:hunter2)`.

For Telnet, use the **mock** server (`server/mock_telnet_server.py`) for this local test —
it behaves like a real telnet daemon (login:/Password: prompts, byte-at-a-time reads) without
needing `apt install telnetd` + root. Open a second terminal for it:

```bash
uv run python server/mock_telnet_server.py 2323
```

(On the real VM demo in part B, you use the actual `setup_telnet.sh` + system `telnetd` instead.)

### Terminal 2 — the sniffer (needs root)

```bash
sudo $(which uv) run python sniffer/sniffer.py lo 8080 2323
```

The two extra args tell the sniffer to watch ports 8080/2323 instead of the real 80/23, matching
the non-privileged ports the local servers above use. Omit them (or use the real 80/23) on the
actual VM demo in Part B, where the HTTP/Telnet daemons run on their standard ports.

- `sudo` is required because opening an `AF_PACKET` raw socket needs `CAP_NET_RAW`.
- `$(which uv)` is needed because `sudo` normally resets `PATH` and won't find `uv` otherwise.
- It will prompt for your login password interactively.
- Leave it running; it prints one line per captured HTTP/Telnet frame, plus a `***` line
  whenever it recovers credentials. It also appends everything to `sniffer/sniffer_session.log`.

### Terminal 3 — the victim (generates the plaintext logins)

```bash
# HTTP login against the server started above
uv run python victim/http_login.py 127.0.0.1 bob hunter2 8080
```

Expected in Terminal 3:
```
[victim] Logging in to http://127.0.0.1:8080/ as bob...
[victim] Server responded 200: Welcome, authenticated user.
```

Expected in Terminal 2 (sniffer), among the per-frame lines:
```
*** HTTP credentials recovered: bob:hunter2 ***
```

Now the Telnet login:

```bash
uv run python victim/telnet_login.py 127.0.0.1 bob hunter2 2323
```

Expected in Terminal 3:
```
[victim] Server: Debian GNU/Linux
login:
[victim] Typing username: bob
[victim] Server: Password:
[victim] Typing password: ****
[victim] Server: Last login: just now
bob@server:~$
```

Expected in Terminal 2 (sniffer):
```
Telnet username captured: bob
*** Telnet credentials recovered: bob:hunter2 ***
```

### Cleanup

`Ctrl+C` in all three terminals. Sniffer log is at `sniffer/sniffer_session.log` if you want to
keep it for your report.

**Note on this local test:** loopback (`lo`) frames still carry a 14-byte Ethernet-style header
on Linux (EtherType 0x0800), so the sniffer's real parsing code path is exercised exactly as it
will be on the VMs — this isn't a mocked/faked capture, only the Telnet *daemon* is mocked to
avoid needing root to install a system service on this machine.

---

## B. Real 3-VM demo (the graded setup)

Full detail is in `SETUP.md`; short version:

1. **Create 3 VirtualBox VMs**: victim, server, attacker. Give each a second NIC on the same
   **Internal Network** (e.g. `intnet0`).
2. On the **attacker** VM's `intnet0` adapter only: VM Settings → Network → Advanced →
   **Promiscuous Mode: Allow All**. (Needed because VirtualBox's Internal Network switches on
   MAC like a real switch — without this the attacker never sees the victim↔server traffic.)
3. Assign static IPs: victim `192.168.56.11`, server `192.168.56.12`, attacker `192.168.56.13`.
4. **On the server VM**:
   ```bash
   cd server
   sudo python3 http_server.py 80
   sudo ./setup_telnet.sh bob      # real telnetd this time, not the mock
   ```
5. **On the attacker VM**:
   ```bash
   sudo tcpdump -i eth1 'port 80 or port 23' &     # optional cross-check
   cd sniffer
   sudo python3 sniffer.py eth1
   ```
6. **On the victim VM**:
   ```bash
   cd victim
   python3 http_login.py 192.168.56.12 bob hunter2
   python3 telnet_login.py 192.168.56.12 bob hunter2
   ```
7. Confirm the attacker prints the same `*** ... credentials recovered ***` lines as above, and
   that the packet counts/fields match `tcpdump`'s view of the same traffic.

(No `uv` needed on the VMs unless you want it — plain `python3 script.py` works too, since
everything is stdlib-only.)

---

## Troubleshooting

- **`Must run as root` / `PermissionError`** from the sniffer → you forgot `sudo`, or forgot
  `$(which uv)` after `sudo` (plain `sudo uv run ...` often fails with "uv: command not found").
- **Sniffer sees nothing on the VMs** → double check Promiscuous Mode is "Allow All" on the
  *attacker's* adapter specifically, and that all three VMs' second NICs are on the exact same
  Internal Network name.
- **`Address already in use`** on port 80/8080/23/2323 → a previous run is still up; find it with
  `ps aux | grep http_server` / `grep mock_telnet` / `grep sniffer.py` and kill it, or pick a
  different port.
