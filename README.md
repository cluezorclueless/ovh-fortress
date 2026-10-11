# ovh-fortress

DDoS hardening for a small OVH VPS (2 vCPU, virtio_net) that doubles as a
Tailscale exit node. Two layers on the host, plus the provider's edge firewall:

| Layer | Where | Job |
|---|---|---|
| OVH Edge Network Firewall | OVH panel | Coarse stateless allow-list before traffic reaches the VPS |
| XDP / eBPF (`xdp/fortress_xdp.c`) | `ens3`, generic mode | Stateless token-bucket pre-filter, runs before the kernel stack |
| nftables (`nftables.d/`) | `inet ovh_fortress` | Stateful rules: netdev ingress, input, forward, bait ports |

`monitor/clueless.py` is a terminal dashboard that polls the VPS over SSH and
shows what each layer is dropping.

## What the XDP filter does (v8)
- Drops bogons, fragments, bad TCP flags, TCP NULL/XMAS, privileged-port junk.
- Per-source and shared token buckets for UDP, bare ACKs, SYN sampling, ICMP.
- Class valves: UDP replies (sport 53/123/443/3478) vs other unsolicited UDP.
- Tailscale fast lane on UDP 41641, gated by a WireGuard/disco/STUN shape check.
- DHCP/DHCPv6 exempt. Bait ports drop and feed the nftables scanner set.

Generic XDP only: virtio_net on this VPS has one queue and no native XDP.

## Tested (BPF_PROG_TEST_RUN, forked workers, 650-800k pps)
| Flood | Dropped before nftables |
|---|---|
| TCP NULL | 100% |
| UDP random ports | 95.7% |
| UDP single source | 99.1% |
| UDP to 41641 | 95.8% |
| SYN | 99.9% |
| Bare ACK | 94.2% |

Legitimate tunnel, TCP data and DNS flows were unaffected (100% delivered).
Voice-style UDP drops to ~5% delivered *during* a distributed UDP flood; see
docs/TROUBLESHOOTING.md. 31/31 single-packet correctness cases pass.

## Limits (be honest about them)
- One VPS cannot absorb terabit floods. Volumetric protection is OVH's VAC.
- OVH's edge firewall only sees traffic from outside OVH. An attacker hosted
  inside OVH bypasses it, so the host layers matter.
- Edge firewall: 20 rules per IP, IPv4 only, stateless.

## Layout
    xdp/            fortress_xdp.c, Makefile, load.sh (timed rollback), xdp-stats, ftest.py
    nftables.d/     ovh-fortress.nft + persistence snippets (zz-*.nft, ovh-nat.nft)
    systemd/        fortress-xdp.service
    sysctl/         kernel hardening, conntrack loose mode off
    monitor/        clueless.py dashboard, fortress-report (runs on the VPS)
    docs/           DEPLOY.md, TROUBLESHOOTING.md

All addresses in this repo are placeholders (203.0.113.10 = VPS public IP,
100.64.0.x = tailnet). Replace them with your own.
