#!/usr/bin/env bash
# Runs the actual sniffing demo against already-bootstrapped VMs (run
# vm_create.sh then vm_bootstrap.sh first, once): starts the HTTP/Telnet
# services and the sniffer on attacker, fires both victim logins, and
# prints what the sniffer recovered.
#
# Usage: ./scripts/vm_run_demo.sh

set -euo pipefail
cd "$(dirname "$0")"
source common.sh

echo "[vm_run_demo] (re)starting HTTP server on server..."
gc_run server /usr/bin/pkill -f http_server.py 2>/dev/null || true
gc_start_sudo server "python3 /home/$GUEST_USER/project/http_server.py 80 > /home/$GUEST_USER/http_server.log 2>&1"

echo "[vm_run_demo] (re)starting sniffer on attacker..."
gc_run attacker /usr/bin/pkill -f sniffer.py 2>/dev/null || true
sleep 1
gc_sudo attacker rm -f /sniffer_session.log
gc_start_sudo attacker "python3 /home/$GUEST_USER/project/sniffer.py $GUEST_IFACE > /home/$GUEST_USER/sniffer.log 2>&1"

# VirtualBox's internal-network switch has a real, observed ~60s "cold
# start" delay after a VM boots before it actually begins mirroring
# promiscuous traffic to a newly-started listener -- the sniffer's socket
# is open and bound immediately, but sees nothing until the switch warms
# up. Rather than guess a fixed sleep, retry the logins until the sniffer
# actually reports a capture.
echo "[vm_run_demo] warming up (retrying logins until the sniffer reports a capture)..."
for attempt in $(seq 1 10); do
  gc_run victim /usr/bin/python3 /home/$GUEST_USER/project/http_login.py "$SERVER_IP" "$DEMO_USER" "$DEMO_PASS" > /dev/null
  if gc_sudo attacker grep -aq "credentials recovered" /sniffer_session.log 2>/dev/null; then
    echo "[vm_run_demo] sniffer is warm (took ~$((attempt * 8))s)"
    break
  fi
  sleep 8
done

echo "[vm_run_demo] running victim Telnet login..."
gc_run victim /usr/bin/python3 /home/$GUEST_USER/project/telnet_login.py "$SERVER_IP" "$DEMO_USER" "$DEMO_PASS"

sleep 1
echo ""
echo "[vm_run_demo] === sniffer results (attacker) ==="
gc_sudo attacker grep -a "credentials recovered" /sniffer_session.log \
  || echo "(nothing recovered -- something's wrong)"
