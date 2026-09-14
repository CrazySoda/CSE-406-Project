#!/usr/bin/env bash
# Boots all 3 demo VMs headless (they must already exist -- see vm_create.sh).
set -euo pipefail
cd "$(dirname "$0")"
source common.sh

for vm in victim server attacker; do
  VBoxManage startvm "$vm" --type headless
done
for vm in victim server attacker; do
  wait_for_guest "$vm"
done
echo "[vm_start] all 3 VMs up."
