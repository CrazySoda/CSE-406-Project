# Demo Setup — Packet Sniffing Attack (CSE406 Group 10)

Three VirtualBox VMs: **victim**, **server**, **attacker**, all Ubuntu Server 24.04, created
and installed headlessly via `VBoxManage` (no clicking through installer screens). Run every
command in this file on the **host** machine, in your own terminal.

Because these are disposable lab VMs used only for this demo, the unattended install bakes in
passwordless `sudo` for the `ubuntu` user *inside each guest* — this is a guest-only convenience
(not your host password) that lets the rest of this guide run non-interactively via
`VBoxManage guestcontrol`.

## 0. Prerequisites (host)

Ubuntu's own `virtualbox` package (7.0.16) fails to build its `vboxdrv` kernel module on newer
kernels (it references KVM hypervisor symbols that changed upstream) — use Oracle's own repo
instead, which tracks current kernels:

```bash
# Purge the broken 7.0.16 install first, if you already hit the DKMS build error:
sudo apt purge -y virtualbox virtualbox-dkms virtualbox-qt virtualbox-ext-pack
sudo apt autoremove -y
sudo rm -f /var/crash/virtualbox-dkms.0.crash

# Add Oracle's official VirtualBox apt repo (adjust "noble" if not on Ubuntu 24.04):
wget -O- https://www.virtualbox.org/download/oracle_vbox_2016.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/oracle-virtualbox-2016.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/oracle-virtualbox-2016.gpg] https://download.virtualbox.org/virtualbox/debian noble contrib" | \
  sudo tee /etc/apt/sources.list.d/virtualbox.list
sudo apt update

# virtualbox-ext-pack shows a text-mode PUEL license prompt -- pre-accept it:
echo virtualbox-ext-pack virtualbox-ext-pack/license select true | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt install -y virtualbox-7.1

# Confirm the kernel module actually built and loaded this time:
sudo dkms status
sudo modprobe vboxdrv && echo "vboxdrv loaded OK"
```

If `vboxdrv` still fails to build even on 7.1 (i.e. the kernel is newer than VirtualBox
currently supports), the fallback is switching this whole setup to KVM/QEMU + `virt-manager`
instead — say so and I'll rewrite this guide for that.

(If a license dialog appears on screen anyway: Tab/arrow to **`<Yes>`**/"I Agree" and press
Enter, or `y` at a plain Y/n prompt.)

Download the Ubuntu Server 24.04 LTS ISO:

```bash
mkdir -p ~/Downloads
curl -L -o ~/Downloads/ubuntu-server.iso \
  https://releases.ubuntu.com/24.04/ubuntu-24.04.1-live-server-amd64.iso
```

## 1. Create and install the 3 VMs

```bash
ISO=~/Downloads/ubuntu-server.iso

for vm in victim server attacker; do
  VBoxManage createvm --name "$vm" --ostype Ubuntu_64 --register
  VBoxManage modifyvm "$vm" --memory 2048 --cpus 1 --nic1 nat
  VBoxManage modifyvm "$vm" --nic2 intnet --intnet2 sniffnet
  mkdir -p ~/"VirtualBox VMs/$vm"
  VBoxManage createmedium disk --filename ~/"VirtualBox VMs/$vm/$vm.vdi" --size 12000
  VBoxManage storagectl "$vm" --name SATA --add sata --controller IntelAhci
  VBoxManage storageattach "$vm" --storagectl SATA --port 0 --device 0 \
    --type hdd --medium ~/"VirtualBox VMs/$vm/$vm.vdi"
done

# Only the attacker needs Promiscuous Mode: Allow All -- this is what makes
# VirtualBox's Internal Network (which otherwise switches on learned MACs,
# like a real switch) deliver a copy of the victim<->server traffic to the
# attacker, reproducing the design report's hub/mirrored-port assumption.
VBoxManage modifyvm attacker --nicpromisc2 allow-all

for vm in victim server attacker; do
  VBoxManage unattended install "$vm" \
    --iso="$ISO" \
    --user=ubuntu --password=ubuntu \
    --full-user-name="Ubuntu" \
    --hostname="$vm.local" \
    --install-additions \
    --post-install-command="echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-ubuntu-nopasswd && chmod 440 /etc/sudoers.d/90-ubuntu-nopasswd" \
    --start-vm=headless
done
```

Each install takes roughly 10–15 minutes. Check progress / wait for all three to finish booting:

```bash
VBoxManage list runningvms
# Poll until a VM responds to a trivial guest command:
until VBoxManage guestcontrol victim run --username ubuntu --password ubuntu \
  --exe /bin/true -- true 2>/dev/null; do sleep 15; done
echo "victim ready"
# repeat the `until` loop for server and attacker
```

## 2. Static IPs on the internal network (`sniffnet`)

Inside VirtualBox, the internal-network adapter usually shows up as `enp0s8` on Ubuntu Server
24.04 — confirm with `VBoxManage guestcontrol <vm> run --username ubuntu --password ubuntu --exe /usr/sbin/ip -- ip link`
if it differs, and adjust below.

| VM       | IP             |
|----------|----------------|
| victim   | 192.168.56.11  |
| server   | 192.168.56.12  |
| attacker | 192.168.56.13  |

```bash
set_static_ip () {
  vm="$1"; ip="$2"
  VBoxManage guestcontrol "$vm" run --username ubuntu --password ubuntu \
    --exe /usr/bin/bash -- bash -c "sudo tee /etc/netplan/90-sniffnet.yaml >/dev/null <<'EOF'
network:
  version: 2
  ethernets:
    enp0s8:
      addresses: [${ip}/24]
EOF
sudo netplan apply"
}

set_static_ip victim   192.168.56.11
set_static_ip server   192.168.56.12
set_static_ip attacker 192.168.56.13
```

Confirm connectivity:

```bash
VBoxManage guestcontrol victim run --username ubuntu --password ubuntu \
  --exe /usr/bin/ping -- ping -c2 192.168.56.12
```

## 3. Copy the project into each VM

```bash
PROJECT=/home/fatin-ishrak-arian/CSE-406/Project

for vm in victim server attacker; do
  VBoxManage guestcontrol "$vm" mkdir --username ubuntu --password ubuntu \
    --parents /home/ubuntu/project
  VBoxManage guestcontrol "$vm" copyto --username ubuntu --password ubuntu \
    --recursive --target-directory=/home/ubuntu/project \
    "$PROJECT/server" "$PROJECT/victim" "$PROJECT/sniffer" "$PROJECT/docs"
done
```

## 4. Server VM

```bash
VBoxManage guestcontrol server run --username ubuntu --password ubuntu \
  --exe /usr/bin/sudo -- sudo bash -c \
  "nohup python3 /home/ubuntu/project/server/http_server.py 80 > /home/ubuntu/http_server.log 2>&1 &"

VBoxManage guestcontrol server run --username ubuntu --password ubuntu \
  --exe /usr/bin/sudo -- sudo bash /home/ubuntu/project/server/setup_telnet.sh bob
```

## 5. Attacker VM

```bash
# optional cross-check
VBoxManage guestcontrol attacker run --username ubuntu --password ubuntu \
  --exe /usr/bin/sudo -- sudo bash -c \
  "nohup tcpdump -i enp0s8 'port 80 or port 23' -w /home/ubuntu/capture.pcap > /dev/null 2>&1 &"

# the sniffer itself -- run this one in the FOREGROUND so you can watch it live
VBoxManage guestcontrol attacker run --username ubuntu --password ubuntu \
  --exe /usr/bin/sudo -- sudo python3 /home/ubuntu/project/sniffer/sniffer.py enp0s8
```

(That last command blocks and streams output back to your host terminal — leave it running
while you do step 6, then Ctrl+C when you're done capturing.)

## 6. Victim VM

In a separate host terminal (while the sniffer above is still running):

```bash
VBoxManage guestcontrol victim run --username ubuntu --password ubuntu \
  --exe /usr/bin/python3 -- python3 /home/ubuntu/project/victim/http_login.py \
  192.168.56.12 bob hunter2

VBoxManage guestcontrol victim run --username ubuntu --password ubuntu \
  --exe /usr/bin/python3 -- python3 /home/ubuntu/project/victim/telnet_login.py \
  192.168.56.12 bob hunter2
```

## 7. Expected result

On the attacker's terminal (from step 5) / `sniffer_session.log` inside the attacker VM:

- A line per captured HTTP/Telnet frame (timestamp, MAC/IP/port).
- `*** HTTP credentials recovered: bob:hunter2 ***`
- `*** Telnet credentials recovered: bob:hunter2 ***`

Cross-check against `capture.pcap` (copy it out with
`VBoxManage guestcontrol attacker copyfrom --username ubuntu --password ubuntu /home/ubuntu/capture.pcap .`
and open in Wireshark) to confirm packet counts and field values match, and confirm the victim's
logins complete normally whether or not the sniffer is running (non-interference).

## Troubleshooting

- **`guestcontrol` commands hang/fail** → Guest Additions may not have finished installing yet;
  re-run the `until ... guestcontrol ... run --exe /bin/true` wait loop from step 1.
- **Wrong NIC name** (`enp0s8` not found) → run
  `VBoxManage guestcontrol <vm> run --username ubuntu --password ubuntu --exe /usr/sbin/ip -- ip link`
  and substitute the actual second-NIC name everywhere above.
- **Attacker sees nothing** → double check `VBoxManage showvminfo attacker | grep -i promisc`
  shows `allow-all`, and that all three VMs used the exact same `--intnet2 sniffnet` name.
