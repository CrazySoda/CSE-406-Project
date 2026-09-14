# Defense / Countermeasure (Bonus)

## Design (from the Design Report, §6)

Sniffing succeeds only because HTTP and Telnet send credentials as clear text. The direct
defense is protocol-level encryption, not trying to detect the sniffer (a passive listener is
inherently undetectable from the network). Replacing Telnet with SSH makes the payload
unreadable ciphertext to any sniffer on the wire, regardless of whether it can still see the
raw frames.

## Implementation

- Installed `openssh-server` on the `server` VM (already listening on :22 by default once
  installed — no extra config needed, unlike the Telnet daemon).
- Same demo account (`bob:hunter2`) logs in over `ssh bob@192.168.56.12` instead of
  `telnet 192.168.56.12`.
- No changes needed on the attacker side — the same `sniffer.py` and a parallel `tcpdump`
  capture were pointed at the SSH session to test whether the attack still works.

## Result

With the sniffer and a full (unfiltered) `tcpdump -i enp0s8` capture both running throughout an
SSH login (`docs/captures/ssh_defense_capture.pcap`, 44 packets):

- `sniffer.py` recovered **nothing** — it only inspects ports 80/23, so SSH traffic doesn't even
  match its filters.
- More rigorously: searching the *raw captured bytes* of the entire SSH session for the literal
  password and username turned up **zero matches**:
  ```
  $ strings ssh_defense_capture.pcap | grep -c hunter2
  0
  $ strings ssh_defense_capture.pcap | grep -c '^bob$'
  0
  ```
  Compare this to the HTTP/Telnet capture (`docs/captures/capture.pcap`), where both are trivially
  recoverable as clear text. The credential-bearing bytes in the SSH capture are TLS/SSH-protocol
  ciphertext — captured, but useless to the attacker.
- The victim's SSH login still completed normally (`docs/screenshots/victim_ssh_login2.png`),
  confirming the defense doesn't break the legitimate service, only the attack against it.

## Conclusion

Encrypting the transport (SSH in place of Telnet; the same argument applies to HTTPS in place of
HTTP) is a complete, protocol-level defense against this class of passive sniffing attack —
the attacker can still capture every frame, but recovers no usable credentials from it.
