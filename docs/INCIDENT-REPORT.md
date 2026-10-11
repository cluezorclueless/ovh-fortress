# Incident report: DDoS against my VPS, October 2026

## Short version
Someone used a commercial stresser hosted inside OVH to flood my server's public IP.
OVH's dashboard labeled the traffic UDP, TCP NULL and "other". I was told about 200
Mbit/s and 200,000 packets per second were arriving, and about 285,000 packets per
second were getting through while OVH's protection was on. The server went down. I
built and tuned a host-side filter while the attack was still going on.

## Two kinds of evidence
| Kind | Where | Shows |
|---|---|---|
| Live incident | this report and `docs/evidence/` | A real attack on the real server |
| Replay test | `docs/test-logs/ftest-v8.log` | The filter's decisions at 555,000-703,000 packets per second |

The 555,000-703,000 figures come from the replay test, not from the live attack.

## Setup
- OVH VPS, 2 vCPUs, one network queue, Tailscale exit node.
- Layers: OVH network protection, XDP filter, nftables, connection tracking.
- Monitoring: `monitor/clueless.py` and `xdp-stats`.

## The attacker was inside OVH
OVH's edge firewall only handles traffic from outside OVH. The source addresses
belonged to OVH's own network, so the edge firewall could not be relied on and my
server had to do the work.

## Timeline
| Step | What I saw | What I did |
|---|---|---|
| 1 | Dashboard showed 2,134 packets dropped by XDP and about 134,000 packets per second arriving, but the service was still being hit | Found my dashboard's "coming through" number counted packets XDP had passed on, not packets that reached the server. Relabeled it |
| 2 | A flood of 1,268-byte TCP ACK packets aimed at port 51820 got through. The block rule I added counted 12,431 of them | Added an explicit drop for that port. The real cause was `nf_conntrack_tcp_loose=1`, which let stray ACKs create connection state. I set it to 0 |
| 3 | OVH's dashboard showed UDP, TCP NULL and "other" traffic, and the service went down | Wrote XDP v7, then v8, with NULL-flag drops, per-source and per-type UDP limits, ACK and SYN limits and an overall ceiling |
| 4 | v7 broke DHCP | Moved the DHCP check ahead of the private-source check |
| 5 | v8's first version dropped 58% of my own upload ACKs | Raised the ACK limit to 8,000 per second |
| 6 | Dropping every SYN would have blinded my bait-port alarm on port 1337 | Switched to sampling 500 per second |
| 7 | v8 attached and counters readable | Made it survive reboots and checked it after a cold start |

## What changed
- XDP v8 in `xdp/fortress_xdp.c`, loaded with an automatic rollback
- Drop rules for the flooded port, the bait port alarm, and the exit-node forwarding fix
- Strict connection tracking
- A dashboard that separates XDP drops, nftables drops and passed traffic
- OVH edge firewall reduced to an allow-list (see `DEPLOY.md`)

## What I can and can't prove
| Claim | Backing |
|---|---|
| A real attack hit the server | OVH dashboard and my screenshots |
| About 200 Mbit/s, 200,000 pps, 285,000 pps getting through | My reading of OVH's dashboard. The original screenshot should be attached |
| XDP was dropping during the attack (2,134 dropped, about 134,000 pps in) | My dashboard screenshot, to attach |
| ACK flood to port 51820, 12,431 packets on the block rule | Screenshot and `tcpdump` capture, to attach |
| v8 drops 93-100% in the replay test | `docs/test-logs/ftest-v8.log` |
| **v8 stopped the live attack from start to finish** | **Not shown.** v8 went on after the main burst, and later readings were quiet |
| Discord voice works through the VPN | The UDP reply test passed. About 450 ms of delay remained |

## Limits
- The live packet and bit rates come from dashboards and my reading of them, not a
  capture on the server.
- XDP in generic mode costs more than the replay test shows.
- One small server cannot absorb terabit floods.

## Evidence to attach
Put these in `docs/evidence/` with public IPs blacked out, then list them here:
1. OVH Anti-DDoS dashboard during the attack
2. `clueless` screenshot with the drop counters
3. First 20 lines of the port 51820 `tcpdump`
4. `sudo xdp-stats` and the nftables counters
5. OVH's mitigation history for the IP
