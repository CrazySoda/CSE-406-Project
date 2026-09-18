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
scripts/          one-command wrappers for both the local test and the full 3-VM demo
docs/             design report, course spec, setup guides, final report, screenshots, captures
```

## Quick start (2 minutes, no VMs)

Everything is stdlib-only Python, run via [`uv`](https://docs.astral.sh/uv/) (auto-manages the
interpreter/venv — no manual install step).

```bash
git clone https://github.com/CrazySoda/CSE-406-Project.git
cd CSE-406-Project
./scripts/local_demo.sh
```

Starts the HTTP + mock Telnet servers, the sniffer on loopback (prompts for your `sudo` password
— needed for the raw socket), runs both victim logins, and prints what got recovered:
`*** HTTP credentials recovered: arzon:2105128 ***` and
`*** Telnet credentials recovered: arian:2105143 ***`. Full details,
troubleshooting, and the equivalent commands run by hand: **[docs/RUNNING.md](docs/RUNNING.md)**.

## Full 3-VM demo (matches the design report exactly)

Three VirtualBox VMs (`victim`, `server`, `attacker`) on a shared Internal Network, real ports
80/23, attacker's NIC in promiscuous mode.

```bash
./scripts/vm_create.sh      # one-time: creates + installs all 3 VMs (~15-20 min)
./scripts/vm_bootstrap.sh   # one-time: static IPs, deploys the code, installs services
./scripts/vm_run_demo.sh    # the actual demo -- re-run any time the VMs are up
./scripts/vm_stop.sh        # shuts the VMs down when you're done (vm_start.sh brings them back)
```

See **[docs/SETUP.md](docs/SETUP.md)** for what each step does under the hood and the couple of
real gotchas we hit along the way (VirtualBox/Secure Boot module signing, an Ubuntu installer
quirk with a second NIC present during install, a VirtualBox internal-network "cold start" delay
before promiscuous mirroring kicks in) — all of which the scripts already work around.

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
