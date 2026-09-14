#!/usr/bin/env bash
# Cleanly shuts down all 3 demo VMs (ACPI power button -- same as a normal
# shutdown, disks/config are preserved). Use vm_start.sh to bring them back.
set -euo pipefail

for vm in victim server attacker; do
  VBoxManage controlvm "$vm" acpipowerbutton 2>/dev/null || echo "[vm_stop] $vm already off"
done
echo "[vm_stop] shutdown signal sent to all 3 VMs (may take a few seconds)."
