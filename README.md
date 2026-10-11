# ovh-fortress

Host-based DDoS mitigation for an internet-exposed Linux VPS, built and tuned during a
live volumetric attack. Layered controls: provider edge filtering, an eBPF/XDP
pre-filter, stateful nftables policy, and a monitoring dashboard.

## Incident summary
| | |
|---|---|
| Asset | OVH VPS, 2 vCPU, virtio_net (single queue), public IPv4, Tailscale exit node |
| Attack | Volumetric and protocol flood from a commercial booter/stresser |
| Source | Inside the provider's own network (AS16276), so provider edge filtering did not apply |
| Vectors | UDP flood, TCP NULL (no flags), TCP ACK flood to 51820/tcp; OVH Anti-DDoS classified traffic as `UDP`, `TCP_NULL`, `OTHER` |
| Reported scale | ~200 Mbit/s, ~200k pps; ~285k pps accepted while provider mitigation was active (analyst reading of the provider dashboard) |
| Impact | Service unavailable (availability) |
| ATT&CK | Impact (TA0040): T1498 Network Denial of Service, T1498.001 Direct Network Flood |
| Outcome | Host-side filter deployed and tuned; v8 tested to 555k-703k pps in replay |

Full timeline, decisions and an evidence table are in `docs/INCIDENT-REPORT.md`.

## Response, by IR phase (NIST SP 800-61)
| Phase | What I did |
|---|---|
| Preparation | Default-drop nftables policy, SSH restricted, conntrack tuned, monitoring dashboard (`monitor/clueless.py`) |
| Detection and analysis | Provider Anti-DDoS dashboard, `xdp-stats` per-reason drop counters, `tcpdump` on the WAN interface. Found the attacker was internal to the provider, so edge filtering could not be relied on |
| Containment | XDP/eBPF filter on the WAN interface: bogon and malformed-packet drops, per-source and per-class token buckets, SYN sampling, ACK rate limiting, global ceiling. Explicit drop for the flooded port |
| Eradication | Set `nf_conntrack_tcp_loose=0` so mid-stream ACK floods go invalid instead of creating state. Closed the unused WireGuard port |
| Recovery | Persistence through systemd and nftables drop-ins, verified after a cold reboot. Reduced the provider edge firewall to an explicit allow-list |
| Lessons learned | Defects found in my own controls and fixed (below) |

## Detection engineering and false positives
Every control change was checked for collateral damage. Defects found and fixed:

| Defect | Cause | Fix |
|---|---|---|
| DHCP broken | Bogon rule dropped private-source DHCP | DHCP exemption ahead of the bogon check |
| 58% of legitimate upload ACKs dropped | ACK limit set too low | 8,000/s, burst 16,000 |
| Bait-port tripwire would go blind | Dropping all bare SYNs | 500/s shared sample valve instead |
| Dashboard understated risk | Counted XDP *passes* as "reaching the host" | Relabelled, split XDP drops, nftables drops and passes |
| UDP replies blocked, voice broken through the exit node | Stateless provider firewall with a final refuse-all and no rule for UDP replies | Authorise UDP to ephemeral ports |
| Flood passing on 51820/tcp | Conntrack loose mode | Strict mode plus explicit drop |

## Results
Two evidence types, kept separate.

**Live incident:** real attack on the real asset. See the incident report. v8 was
deployed after the main burst, so I do not claim it was proven against that attack.

**Replay test:** compiled object loaded through the kernel verifier, synthetic floods
via `BPF_PROG_TEST_RUN`, 5 s each. Log: `docs/test-logs/ftest-v8.log`.

| Flood | pps | Dropped in XDP |
|---|---|---|
| TCP NULL | 703k | 100.00% |
| SYN, forged sources | 662k | 99.89% |
| UDP, single source | 648k | 98.92% |
| UDP, random ports | 575k | 95.18% |
| UDP to 41641 (Tailscale) | 555k | 95.02% |
| Bare ACK | 614k | 93.27% |

Legitimate tunnel, TCP download and DNS flows stayed at 100% delivery in every run.
Voice-style UDP fell to 6-9% during the distributed UDP floods, and upload ACKs to 9%
during the ACK flood. That is a known weakness of a stateless pre-filter.

The replay test measures the filter's drop decisions. It excludes NIC and driver cost
in generic XDP mode, and it is not a capture of the live attack.

## Control layers
    provider VAC + edge firewall -> NIC -> XDP pre-filter -> nftables ingress
      -> conntrack -> nftables input/forward -> host

| Layer | Strength | Limitation |
|---|---|---|
| Provider edge firewall | Drops upstream | Stateless, does not see internal sources |
| XDP (generic mode) | Cheapest host-side drop | Stateless, generic mode only on virtio_net |
| nftables + conntrack | Stateful policy, scanner and flooder sets, bait ports | Runs after kernel allocation |

Design notes: `docs/ARCHITECTURE.md`.

## Deception
Bait ports (including 1337/tcp) feed a scanner set. Contact is logged and the source
is dropped. Bare SYNs are sampled rather than dropped so the tripwire stays live.

## Limits
- A single VPS cannot absorb a terabit volumetric flood. That is the provider's role.
- The edge firewall has 20 rules per IP, IPv4 only, and is stateless.
- Generic XDP adds per-packet cost that native mode would not.
- Distributed UDP floods degrade my own real-time UDP. Next step is a conntrack-fed
  trust map so established flows bypass the buckets.

## Layout
    xdp/           fortress_xdp.c, load.sh (timed rollback), xdp-stats, ftest.py, Makefile
    nftables.d/    ovh-fortress.nft and persistence drop-ins
    systemd/       fortress-xdp.service
    sysctl/        kernel hardening
    monitor/       clueless.py dashboard, fortress-report
    docs/          INCIDENT-REPORT, ARCHITECTURE, DEPLOY, TROUBLESHOOTING, GLOSSARY, test-logs, evidence

## Build and test
    cd xdp && make                            # clang, libbpf-dev, linux-libc-dev
    sudo python3 ftest.py v8 fortress_xdp.o   # root, bpf(2)

Deployment: `docs/DEPLOY.md`.

## Checked
| Item | Status |
|---|---|
| Compiles with `-Wall`, no warnings | yes |
| Kernel verifier accepts it | yes (1,959 instructions) |
| 31 single-packet correctness cases | pass |
| `nft -c` on the ruleset | pass |
| Scripts parse | yes |
| systemd and sysctl files | running on the asset, not re-tested from this repo |

## For non-specialists
Think of the VPS as an apartment building and the internet as the street. A DDoS is a
crowd sent to jam the front door. The provider's network protection is a barricade on
the road. The XDP filter is a bouncer who checks each visitor in an instant, and
nftables is the front desk with the guest list. The attacker was already inside the
city walls, so the barricade never saw them. `docs/GLOSSARY.md` explains each term
this way.

## Notes
Addresses are placeholders. I deployed, operated and debugged this on my own infrastructure.
