# Troubleshooting log

## Discord voice stuck on "Checking Route" through the exit node
Symptoms: web works, voice never connects, ping 500-900 ms, fine with the exit
node off.
Ruled out, in order:
1. Tailscale relay: tunnel was direct over IPv6.
2. The XDP filter: same result with it detached.
3. nftables: with XDP off, `tcpdump -i ens3 'ip and udp and not port 41641'`
   showed outbound voice packets and **no replies at all**. tcpdump sees traffic
   before nftables, so nftables was not dropping them.
4. A Google STUN test from the VPS timed out too, so it was not Discord-specific.

Root cause: the OVH Edge Network Firewall is stateless. With `Refuse IPv4 all`
as the last rule and nothing allowing UDP replies on high ports, every reply to
outbound UDP was discarded. Tailscale (41641) and TCP established were allowed,
which is why only UDP voice broke.

Fix: `Authorise UDP dst 32768-60999`, and delete the UDP 51820 rules.
Verification: the STUN test printed `REPLY OK`.

Test used (VPS):
    python3 -c 'import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(4);s.sendto(b"\x00\x01\x00\x00\x21\x12\xa4\x42"+os.urandom(12),("stun.l.google.com",19302));print("REPLY OK",len(s.recv(999)))'

Remaining: ~420-480 ms between client and VPS on the Tailscale path, same with
the filter on or off, so the delay is on the access network, not the host.

## Other fixes made
| Problem | Cause | Fix |
|---|---|---|
| nft boot failed, "unexpected table" | file without trailing newline | append newline |
| XDP not persisting | service inactive after reboot | unit with ExecStartPre detach |
| Exit node: forwarding refused | no forward accept tailscale0 -> ens3 | zz-tsexit.nft |
| Tailscale masquerade lost | lived only in iptables | moved to ovh-nat.nft |
| xdp-stats crash after reboot | raw syscall map reader | read via bpftool |
| ACK flood to tcp/51820 passing | conntrack loose mode | nf_conntrack_tcp_loose=0 + wg-flood-block |
| DHCP dropped as bogon | private source | DHCP check before bogon check |
| Upload ACKs at 58% | ACK rate too low | 8000/s, burst 16000 |

## Known gaps
- nftables `wan_udp4` meter limits each source to 200 pps in the ingress chain;
  heavy single-server UDP (video) may hit it.
- A conntrack-fed trust map would let your own UDP flows survive a UDP flood.
