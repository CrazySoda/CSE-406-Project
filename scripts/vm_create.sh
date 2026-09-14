#!/usr/bin/env bash
# Creates and installs the 3 demo VMs (victim/server/attacker) from scratch:
# VirtualBox VMs + disks, unattended Ubuntu Server install, then the 2nd
# (Internal Network) NIC added afterward.
#
# Why the 2nd NIC is added AFTER install, not during: Ubuntu 24.04's
# installer can get stuck in an infinite network-event logging loop if a
# 2nd NIC has no carrier/DHCP during install. Installing with only the NAT
# NIC avoids that entirely; the NIC is added back once the OS is already
# installed and booted once.
#
# Prerequisite: VirtualBox actually working on this host -- if `VBoxManage
# --version` fails, or a VM won't boot, see the Secure-Boot / kernel-module
# troubleshooting section in docs/SETUP.md first.
#
# Usage: ./scripts/vm_create.sh [path-to-ubuntu-server.iso]
# (downloads the ISO to ~/Downloads/ubuntu-server.iso if not given/found)

set -euo pipefail
cd "$(dirname "$0")"
source common.sh

ISO="${1:-$HOME/Downloads/ubuntu-server.iso}"

if [ ! -f "$ISO" ]; then
  echo "[vm_create] ISO not found at $ISO, downloading Ubuntu Server 24.04..."
  mkdir -p "$(dirname "$ISO")"
  LATEST=$(curl -s https://releases.ubuntu.com/24.04/ | grep -oE 'ubuntu-24\.04\.[0-9]+-live-server-amd64\.iso' | sort -u | tail -1)
  curl -L -o "$ISO" "https://releases.ubuntu.com/24.04/$LATEST"
fi

echo "[vm_create] creating VMs + disks..."
for vm in victim server attacker; do
  VBoxManage createvm --name "$vm" --ostype Ubuntu_64 --register
  VBoxManage modifyvm "$vm" --memory 2048 --cpus 1 --nic1 nat
  mkdir -p ~/"VirtualBox VMs/$vm"
  VBoxManage createmedium disk --filename ~/"VirtualBox VMs/$vm/$vm.vdi" --size 12000
  VBoxManage storagectl "$vm" --name SATA --add sata --controller IntelAhci
  VBoxManage storageattach "$vm" --storagectl SATA --port 0 --device 0 \
    --type hdd --medium ~/"VirtualBox VMs/$vm/$vm.vdi"
done

echo "[vm_create] running unattended installs (NAT only, no 2nd NIC yet)..."
for vm in victim server attacker; do
  VBoxManage unattended install "$vm" \
    --iso="$ISO" \
    --user="$GUEST_USER" --password="$GUEST_PASS" \
    --admin-password="$GUEST_PASS" \
    --full-user-name="Ubuntu" \
    --hostname="$vm.local" \
    --install-additions \
    --start-vm=headless
done

for vm in victim server attacker; do
  wait_for_guest "$vm"
done

echo "[vm_create] powering off to add the internal-network NIC..."
for vm in victim server attacker; do
  VBoxManage controlvm "$vm" poweroff
done
sleep 3

for vm in victim server attacker; do
  VBoxManage modifyvm "$vm" --nic2 intnet --intnet2 "$NET_NAME"
done
VBoxManage modifyvm attacker --nicpromisc2 allow-all

echo "[vm_create] booting all 3 with both NICs..."
for vm in victim server attacker; do
  VBoxManage startvm "$vm" --type headless
done
for vm in victim server attacker; do
  wait_for_guest "$vm"
done

echo "[vm_create] done. Run ./scripts/vm_bootstrap.sh next."
