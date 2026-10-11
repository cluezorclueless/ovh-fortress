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
| A real attack occurred | `docs/evidence/01`, `02`, `03` (provider Anti-DDoS portal) |
| Attack mixed NULL/SYN/RST/FIN/PSH/ACK/UDP/other floods | `02` (vector lists per mitigation event) |
| 3.45 M packets rejected by the provider on the period viewed | `03` |
| XDP dropping during the attack (2,134 drops, ~134k pps) | `04`. The dashboard shows the earlier filter still passing about 98% of that rate |
| 12,431 packets hit the 51820 drop rule, 1,268-byte ACKs | `06` |
| 98.5% of 54.2 M packets seen by XDP were dropped | `05`. Counters are cumulative since the program was loaded, not one event |
| Provider firewall had no allow for UDP replies, then fixed | `07` shows the rule table. The fix is the added UDP 32768-60999 rule |
| v8 drops 93-100% in replay | `docs/test-logs/ftest-v8.log` (synthetic, not the live attack) |
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

## Evidence files
All taken Oct 3-6, 2026. Public IPs, attacker addresses and hostnames are blacked out. Photos of a screen are blurry in places and left as taken.

| File | What it shows | Caveat |
|---|---|---|
| `01-ovh-antiddos-scrubbing-log.png` | Provider mitigation log for the VPS address | Address hidden |
| `02-ovh-attack-vectors-list.png` | Attack vectors per event: OTHER, TCP_SYN, TCP_RST, TCP_FIN, TCP_PSH, TCP_ACK, UDP | Cropped on the left by the phone view |
| `03-ovh-traffic-graph-packets-rejected.png` | 3.45 M packets rejected, traffic spike on 10/4/26 (UTC-5) | The tooltip shows a quiet moment, not the peak |
| `04-clueless-dashboard-live-attack.jpg` | My dashboard during the attack, drop counters rising | Earlier filter, before v8 |
| `05-xdp-stats-cumulative-drops.jpg` | `sudo xdp-stats`: 53,427,836 dropped, 98.5% of 54,241,893 seen | Cumulative since load |
| `06-wg-flood-block-and-attacker-capture.jpg` | nftables `wg-flood-block` at 12,431 packets, then `tcpdump` of 1,268-byte ACKs to 51820/tcp | Phone-quality photo of a terminal |
| `07-ovh-edge-firewall-rules.png` | Provider edge firewall rules, ending in "Refuse IPv4 all" | Rule details cut off at the right edge |
