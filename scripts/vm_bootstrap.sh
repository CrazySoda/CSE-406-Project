#!/usr/bin/env bash
# One-time setup on top of freshly-created VMs (run ./scripts/vm_create.sh
# first): passwordless sudo for guestcontrol automation, static IPs on the
# internal network, the project files copied in, and the HTTP/Telnet/SSH
# services installed on the server.
#
# Usage: ./scripts/vm_bootstrap.sh

set -euo pipefail
cd "$(dirname "$0")"
source common.sh

echo "[vm_bootstrap] enabling passwordless sudo for $GUEST_USER on all 3 VMs..."
for vm in victim server attacker; do
  if gc_run "$vm" /usr/bin/sudo sudo whoami >/dev/null 2>&1; then
    echo "[vm_bootstrap] $vm: already has passwordless sudo"
    continue
  fi
  console_login_and_run "$vm" \
    "echo $GUEST_PASS | sudo -S bash -c \"echo '$GUEST_USER ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-nopasswd && chmod 440 /etc/sudoers.d/90-nopasswd\""
  sleep 1
  gc_run "$vm" /usr/bin/sudo sudo whoami >/dev/null \
    && echo "[vm_bootstrap] $vm: passwordless sudo OK" \
    || { echo "[vm_bootstrap] $vm: FAILED to set up sudo, aborting"; exit 1; }
done

echo "[vm_bootstrap] setting static IPs on $GUEST_IFACE..."
set_static_ip () {
  local vm="$1"; local ip="$2"
  gc_sudo "$vm" bash -c "printf 'network:\n  version: 2\n  ethernets:\n    ${GUEST_IFACE}:\n      addresses: [${ip}/24]\n' > /etc/netplan/90-${NET_NAME}.yaml && netplan apply"
}
set_static_ip victim   "$VICTIM_IP"
set_static_ip server   "$SERVER_IP"
set_static_ip attacker "$ATTACKER_IP"

echo "[vm_bootstrap] confirming connectivity..."
gc_run victim /usr/bin/ping -c2 "$SERVER_IP"

echo "[vm_bootstrap] deploying project files..."
for vm in victim server attacker; do
  VBoxManage guestcontrol "$vm" mkdir --username "$GUEST_USER" --password "$GUEST_PASS" \
    --parents /home/$GUEST_USER/project
  VBoxManage guestcontrol "$vm" copyto --username "$GUEST_USER" --password "$GUEST_PASS" \
    --recursive --target-directory=/home/$GUEST_USER/project \
    "$PROJECT_ROOT/server" "$PROJECT_ROOT/victim" "$PROJECT_ROOT/sniffer" 2>&1 \
    || echo "[vm_bootstrap] (copy warning on $vm -- files may already be there; continuing)"
done

echo "[vm_bootstrap] installing Telnet daemon + demo user on server..."
gc_sudo server bash /home/$GUEST_USER/project/setup_telnet.sh "$TELNET_USER" "$TELNET_PASS"

echo "[vm_bootstrap] installing SSH server on server (for the defense demo)..."
gc_sudo server apt-get install -y openssh-server

echo "[vm_bootstrap] done. Run ./scripts/vm_run_demo.sh next."
