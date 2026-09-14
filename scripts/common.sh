# Shared config, sourced by the other scripts/*.sh files. Not meant to be
# run directly.

VICTIM_IP=192.168.56.11
SERVER_IP=192.168.56.12
ATTACKER_IP=192.168.56.13
NET_NAME=sniffnet
GUEST_IFACE=enp0s8   # VirtualBox's usual name for the 2nd NIC on Ubuntu 24.04; verify with
                     # `ip -brief link` inside a guest if this doesn't match on your install.

GUEST_USER=ubuntu
GUEST_PASS=ubuntu
DEMO_USER=bob
DEMO_PASS=hunter2

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

gc_run () {
  # gc_run <vm> <exe> [args...]  -- runs a foreground command in a VM as $GUEST_USER
  local vm="$1"; local exe="$2"; shift 2
  VBoxManage guestcontrol "$vm" run --username "$GUEST_USER" --password "$GUEST_PASS" \
    --exe "$exe" -- "$@"
}

gc_sudo () {
  # gc_sudo <vm> <cmd...> -- runs a command as root via NOPASSWD sudo (set up by
  # vm_bootstrap.sh). Requires that bootstrap step to have already run once.
  local vm="$1"; shift
  VBoxManage guestcontrol "$vm" run --username "$GUEST_USER" --password "$GUEST_PASS" \
    --exe /usr/bin/sudo -- sudo "$@"
}

gc_start_sudo () {
  # gc_start_sudo <vm> <shell-command-string> -- fire-and-forget a background
  # command as root (for long-running processes like the sniffer/servers).
  local vm="$1"; local cmd="$2"
  VBoxManage guestcontrol "$vm" start --username "$GUEST_USER" --password "$GUEST_PASS" \
    --exe /usr/bin/sudo -- sudo bash -c "cd /; nohup $cmd & disown; sleep 1; echo STARTED"
}

console_login_and_run () {
  # Types a login + a command directly into the VM's virtual console via the
  # emulated keyboard -- a fallback for when guestcontrol itself isn't up
  # yet (see wait_for_guest below). Assumes the console is at a fresh
  # `login:` prompt.
  local vm="$1"; local cmd="$2"
  VBoxManage controlvm "$vm" keyboardputstring "$GUEST_USER"
  VBoxManage controlvm "$vm" keyboardputscancode 1c 9c
  sleep 2
  VBoxManage controlvm "$vm" keyboardputstring "$GUEST_PASS"
  VBoxManage controlvm "$vm" keyboardputscancode 1c 9c
  sleep 2
  VBoxManage controlvm "$vm" keyboardputstring "$cmd"
  VBoxManage controlvm "$vm" keyboardputscancode 1c 9c
  sleep 2
}

wait_for_guest () {
  # Polls guestcontrol until it responds. After ~60s of no response, tries
  # the known fix for a real bug we hit: VBoxGuestAdditions' vboxadd-service
  # can start before udev has created /dev/vboxguest, so it fails to start
  # and guestcontrol never comes up on its own -- modprobe + a service
  # restart (typed on the console, since guestcontrol isn't up yet to do it
  # any other way) clears it.
  local vm="$1"
  echo "[wait_for_guest] waiting for $vm ..."
  local waited=0
  until VBoxManage guestcontrol "$vm" run --username "$GUEST_USER" --password "$GUEST_PASS" \
        --exe /bin/true -- true 2>/dev/null; do
    sleep 10
    waited=$((waited + 10))
    if [ "$waited" -eq 60 ]; then
      echo "[wait_for_guest] $vm not responding after 60s -- trying the vboxadd-service fix"
      console_login_and_run "$vm" \
        "echo $GUEST_PASS | sudo -S bash -c 'modprobe vboxguest; systemctl restart vboxadd-service'"
    fi
  done
  echo "[wait_for_guest] $vm ready"
}
