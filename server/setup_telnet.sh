#!/usr/bin/env bash
# Sets up a Telnet daemon on the "server" VM for the packet-sniffing demo.
# Run with sudo on a Debian/Ubuntu-based VM.
#
# Usage: sudo ./setup_telnet.sh [username] [password]

set -euo pipefail

DEMO_USER="${1:-arian}"
DEMO_PASS="${2:-2105143}"

echo "[*] Installing telnet daemon (inetutils-telnetd + xinetd)..."
apt-get update -qq
apt-get install -y inetutils-telnetd xinetd

# Ubuntu's inetutils-telnetd package ships only the /usr/sbin/telnetd
# binary -- unlike some distros, it does NOT include an /etc/xinetd.d/telnet
# config file, so xinetd has nothing to serve on :23 until we write one.
cat > /etc/xinetd.d/telnet <<'EOF'
service telnet
{
	disable		= no
	flags		= REUSE
	socket_type	= stream
	wait		= no
	user		= root
	server		= /usr/sbin/telnetd
	log_on_failure	+= USERID
}
EOF

echo "[*] Creating demo user '${DEMO_USER}' (if it doesn't already exist)..."
if ! id "${DEMO_USER}" &>/dev/null; then
    useradd -m -s /bin/bash "${DEMO_USER}"
    echo "${DEMO_USER}:${DEMO_PASS}" | chpasswd
    echo "    Created ${DEMO_USER}:${DEMO_PASS}"
else
    echo "    User ${DEMO_USER} already exists, leaving password unchanged."
fi

echo "[*] Restarting xinetd (serves telnet on :23)..."
systemctl restart xinetd
systemctl enable xinetd

echo "[*] Done. Telnet daemon should be listening on port 23."
echo "    Test locally with: telnet localhost"
