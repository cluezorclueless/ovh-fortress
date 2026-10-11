# Incident report: volumetric DDoS against an internet-exposed VPS (October 2026)

Format follows NIST SP 800-61 (preparation, detection and analysis, containment,
eradication, recovery, post-incident).

## Summary
| | |
|---|---|
| Asset | OVH VPS, 2 vCPU, virtio_net (1 queue), public IPv4, Tailscale exit node |
| Threat | Commercial booter/stresser, source inside the provider network (AS16276) |
| Vectors | UDP flood, TCP NULL, TCP ACK flood to 51820/tcp. Provider Anti-DDoS labels: `UDP`, `TCP_NULL`, `OTHER` |
| Reported scale | ~200 Mbit/s, ~200k pps, ~285k pps accepted despite provider mitigation |
| Impact | Availability: service went down |
| ATT&CK | TA0040 Impact. T1498 Network Denial of Service, T1498.001 Direct Network Flood |
| Attribution | Not pursued. No attacker identity or addresses are recorded here |

## Evidence types
| Type | Where | Shows |
|---|---|---|
| Live incident | this report, `docs/evidence/` | Real attack on the real asset |
| Replay test | `docs/test-logs/ftest-v8.log` | Filter decisions at 555k-703k pps |

The 555k-703k figures are from the replay test, not the live attack.

## Preparation (state before the incident)
Default-drop nftables policy, SSH restricted, Tailscale exit node, XDP not yet deployed
in its final form. Provider edge firewall enabled with a deny-all tail rule.

## Detection and analysis
- Provider Anti-DDoS dashboard classified the traffic and showed mitigation active.
- Host-side: XDP per-reason counters (`xdp-stats`) and the `clueless` dashboard showed
  2,134 drops and ~134k pps inbound at one reading.
- `tcpdump` on the WAN interface showed a TCP ACK flood of 1,268-byte segments to
  51820/tcp. The explicit drop rule counted 12,431 packets.
- **Key finding:** the sources were inside the provider network. The provider's edge
  firewall only handles traffic from outside it, so it was not a dependable control and
  the host layers carried the defence.
- **Analysis error corrected:** my dashboard counted packets XDP passed on as "reaching
  the host". It overstated exposure. Relabelled and split into drops and passes.
- **Root cause of the ACK flood passing:** `nf_conntrack_tcp_loose=1` let mid-stream
  ACKs create conntrack state.

## Containment
- XDP v7, then v8, on the WAN interface (generic mode): malformed and bogon drops,
  NULL-flag drop, per-source and per-class UDP token buckets, ACK rate limit, SYN
  sampling, global ceiling. Loaded with an automatic rollback timer so a bad version
  could not lock out SSH.
- Explicit drop for the flooded port.

## Eradication
- `nf_conntrack_tcp_loose=0`: mid-stream ACK floods become invalid and are dropped.
- Unused WireGuard accept rules removed.

## Recovery
- Persistence through systemd and `/etc/nftables.d/` drop-ins, verified after a cold
  reboot.
- Provider edge firewall rewritten as an allow-list (see `DEPLOY.md`).
- Exit-node forwarding and NAT restored and made persistent.

## Post-incident: defects in my own controls
| Step | Defect | Cause | Fix |
|---|---|---|---|
| 4 | v7 broke DHCP | Bogon rule dropped private-source DHCP | DHCP check before the bogon check |
| 5 | v8 dropped 58% of legitimate upload ACKs | ACK limit too low | 8,000/s, burst 16,000 |
| 6 | Tripwire on 1337/tcp would go blind | Dropping every bare SYN | 500/s shared sample valve |
| 7 | UDP replies lost, voice broken via exit node | Stateless provider firewall, deny-all tail, no rule for UDP replies | Authorise UDP to 32768-60999 |

## Evidence status
| Claim | Backing |
|---|---|
| A real attack occurred | Provider dashboard, my screenshots |
| ~200 Mbit/s, ~200k pps, ~285k pps accepted | Analyst reading of the provider dashboard. Attach the screenshot |
| XDP dropping during the attack (2,134 drops, ~134k pps) | Dashboard screenshot, to attach |
| 12,431 packets on the 51820 drop rule | Screenshot and `tcpdump`, to attach |
| v8 drops 93-100% in replay | `docs/test-logs/ftest-v8.log` |
| **v8 mitigated the live attack end to end** | **Not shown.** v8 went on after the main burst. Later readings were quiet |
| Voice restored | UDP reply test passed. ~450 ms client-to-VPS delay remained |

## Limits
- Live scale figures come from dashboards, not a host packet capture.
- Generic XDP adds per-packet cost that the replay test excludes.
- A single VPS cannot absorb a terabit flood.

## Indicators
No attacker addresses are published. Observable patterns, useful for detection:
- Large volumes of NULL-flag TCP.
- Mid-stream ACKs with no matching connection, 1,268-byte payloads, to 51820/tcp.
- High-rate UDP from many sources to random high ports.

## Evidence to attach
Black out public IPs and put these in `docs/evidence/`:
1. Provider Anti-DDoS dashboard during the attack
2. `clueless` screenshot with drop counters
3. First 20 lines of the 51820/tcp `tcpdump`
4. `sudo xdp-stats` and nftables counters
5. Provider mitigation history for the IP
