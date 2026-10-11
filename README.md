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
These numbers come from `xdp/ftest.py`, which loads the compiled object through the
real kernel verifier and replays synthetic packets with `BPF_PROG_TEST_RUN`. That
measures the program's drop decisions at high packet rates. It is **not** a test
on a live network or against a real stresser, and it does not include NIC or
driver cost in generic XDP mode.

| Flood (5 s each) | Attack rate | Dropped in XDP | Your traffic during the flood |
|---|---|---|---|
| TCP NULL | 703k pps | 100.00% | all flows 100% |
| UDP, random ports | 575k pps | 95.18% | voice-style UDP 6.0% (degraded) |
| UDP, one source | 648k pps | 98.92% | all flows 100% |
| UDP to 41641 | 555k pps | 95.02% | voice-style UDP 8.9% (degraded) |
| SYN, forged sources | 662k pps | 99.89% | all flows 100% |
| Bare ACK | 614k pps | 93.27% | upload ACKs 9.1% (degraded) |

Full output: `docs/test-logs/ftest-v8.log` (kernel, compiler, SHA-256 of source and
object are recorded at the top). Reproduce with the commands below.

Honest reading: the filter drops 93-100% of attack traffic at 555k-703k pps, and
tunnel, TCP download and DNS stay at 100%. During distributed UDP and ACK floods
the ~5-7% that passes is shared between attack and legitimate traffic, so
voice-style UDP and upload ACKs degrade. Fixing that needs a conntrack-fed trust
map (listed under known gaps).

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

## Verification status
| Item | Status |
|---|---|
| `fortress_xdp.c` compiles clean with `-Wall` | checked |
| Verifier accepts the program | checked (1959 instructions) |
| 31 single-packet correctness cases | passed |
| `nft -c` on `ovh-fortress.nft`, alone and with `zz-wgblock.nft` | passed |
| Python and shell syntax | checked |
| systemd unit and sysctl files | run on the live VPS, not re-tested from this repo |
| Real-world flood mitigation | observed on the VPS, not benchmarked |

## Build and test
    cd xdp && make                        # needs clang, libbpf-dev, linux-libc-dev
    sudo python3 ftest.py v8 fortress_xdp.o   # needs root and bpf(2)

## License
MIT. See LICENSE.
