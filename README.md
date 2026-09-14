# Packet Sniffing Attack — CSE406 Group 10

Passive packet-sniffing attack tool: captures live HTTP and Telnet logins on a shared LAN
segment and recovers the plaintext credentials, using a raw-socket sniffer with hand-parsed
Ethernet/IPv4/TCP headers (no scapy/libpcap). Built for CSE406 (Cyber Security Sessional),
Attack Tool 2.

- **2105128** – Nakib Arman
- **2105143** – Fatin Ishrak Arian

Full writeup, screenshots, and captures from a real run: **[docs/final-report.md](docs/final-report.md)**
(also as a rendered PDF: `docs/CSE406_Final_Report.pdf`).

## Repo layout

```
sniffer/          attacker: raw-socket sniffer + credential extractor (the core deliverable)
server/           victim's server: HTTP Basic-Auth server, real telnetd setup script,
                   and a local mock telnet server for non-VM testing
victim/           scripted HTTP and Telnet logins used to generate demo traffic
docs/             design report, course spec, setup guides, final report, screenshots, captures
```

## Quick start (2 minutes, no VMs)

Everything is stdlib-only Python, run via [`uv`](https://docs.astral.sh/uv/) (auto-manages the
interpreter/venv — no manual install step).

```bash
git clone https://github.com/CrazySoda/CSE-406-Project.git
cd CSE-406-Project

# Terminal 1 — HTTP demo server (non-privileged port, no sudo)
uv run python server/http_server.py 8080

# Terminal 2 — local telnet stand-in (no root/apt install needed for this quick test)
uv run python server/mock_telnet_server.py 2323

# Terminal 3 — the sniffer itself (needs root for the raw socket; watches ports 8080/2323 here)
sudo $(which uv) run python sniffer/sniffer.py lo 8080 2323

# Terminal 4 — trigger the logins
uv run python victim/http_login.py 127.0.0.1 bob hunter2 8080
uv run python victim/telnet_login.py 127.0.0.1 bob hunter2 2323
```

You should see `*** HTTP credentials recovered: bob:hunter2 ***` and the same for Telnet in
Terminal 2's output. Full details and troubleshooting: **[docs/RUNNING.md](docs/RUNNING.md)**.

## Full 3-VM demo (matches the design report exactly)

Three VirtualBox VMs (`victim`, `server`, `attacker`) on a shared Internal Network, real ports
80/23, attacker's NIC in promiscuous mode. Fully scripted via `VBoxManage` (unattended install,
no clicking through installer screens) — see **[docs/SETUP.md](docs/SETUP.md)** for the complete
copy-pasteable command sequence, including the couple of gotchas we hit (VirtualBox/Secure Boot
module signing, an Ubuntu installer quirk with a second NIC present during install) and their
fixes.

## Defense / bonus

`docs/defense.md` — swapping Telnet for SSH on the same login, with byte-level proof
(`strings capture.pcap | grep -c hunter2` → `0`) that the sniffer recovers nothing once the
transport is encrypted.

## Requirements

- Python 3.9+ and [`uv`](https://docs.astral.sh/uv/) for the quick-start path
- VirtualBox 7.x for the full VM demo (`docs/SETUP.md` covers install/setup from scratch,
  including a fix for the Ubuntu-packaged VirtualBox failing to build its kernel module on newer
  kernels)
- Linux host (the sniffer uses `AF_PACKET`, Linux-only)
