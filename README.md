# ovh-fortress

I run a small cloud server (a VPS at OVH) that I use as a VPN exit point. Someone
rented a stresser service and started flooding it with junk traffic, hoping to knock
it offline. I used the attack as a live problem to solve: I wrote a packet filter
that runs inside the Linux kernel, tightened the firewall rules around it, built a
dashboard to watch it all, and tested each change against floods of more than
500,000 packets per second.

This repo is the code, the configs, my notes from the incident, and the test logs.

## What happened, in plain terms
- The attack came from inside OVH's own network, so OVH's edge firewall could not
  see it as "outside" traffic. Most of the defense had to run on my server.
- OVH's dashboard labeled the traffic as UDP floods, TCP NULL packets and "other".
  I was told roughly 200 Mbit/s and 200,000 packets per second were hitting the
  server, and that about 285,000 packets per second were getting through even with
  OVH's own protection on.
- I wrote an eBPF/XDP filter that throws away bad packets before the operating
  system spends any effort on them, and put nftables firewall rules behind it for
  the traffic that needs tracking.
- Along the way I found and fixed bugs in my own work. One version broke DHCP, one
  dropped real upload traffic, and the OVH firewall was quietly blocking all UDP
  replies, which broke Discord voice through the VPN. The full list is in
  `docs/TROUBLESHOOTING.md`.

## Results
I have two kinds of evidence, and I keep them separate on purpose.

**1. The live attack.** Real, on the real server. Details and what I can and cannot
prove are in `docs/INCIDENT-REPORT.md`. One thing to be clear about: my final filter
(v8) went on after the biggest burst, so I do not claim it was proven against that
specific attack.

**2. A replay test.** I loaded the compiled filter into the kernel and fired
synthetic floods at it, five seconds each. Full output is in
`docs/test-logs/ftest-v8.log`.

| Flood | Packets per second | Dropped before reaching the firewall |
|---|---|---|
| TCP NULL | 703,000 | 100.00% |
| SYN, forged sources | 662,000 | 99.89% |
| UDP, one source | 648,000 | 98.92% |
| UDP, random ports | 575,000 | 95.18% |
| UDP to the VPN port | 555,000 | 95.02% |
| Bare ACK | 614,000 | 93.27% |

My own tunnel traffic, downloads and DNS kept working at 100% during every flood.
During the spread-out UDP floods, voice-style traffic dropped to 6-9% delivered,
and upload acknowledgements fell to 9% during the ACK flood. That is the weak spot
in this version, and fixing it is the next piece of work (see `docs/TROUBLESHOOTING.md`).

The replay test measures the filter's decisions. It does not include the cost of the
network card, and it is not a capture of the live attack.

## What each piece does
| Folder | What's in it |
|---|---|
| `xdp/` | The kernel packet filter (`fortress_xdp.c`), a script that loads it with an automatic rollback, a counter reader, and the test harness |
| `nftables.d/` | The firewall rules and the small files that keep my changes after a reboot |
| `systemd/` | The service that loads the filter at boot |
| `sysctl/` | Kernel network settings |
| `monitor/` | `clueless.py`, a terminal dashboard that shows what each layer is dropping |
| `docs/` | Architecture, setup steps, incident report, troubleshooting log, test logs |

## How the defense is layered
Traffic passes through four layers, and each one drops what it can so the next has
less to do:

1. OVH's network protection and edge firewall
2. My XDP filter, which is fast but remembers nothing
3. nftables, which tracks connections and handles scanners
4. The server itself

`docs/ARCHITECTURE.md` explains the order and why I made each choice.

## What it cannot do
- One small server cannot absorb a terabit-scale flood. That is the provider's job.
- The XDP filter runs in "generic" mode because this VPS's network driver does not
  support the faster native mode.
- A flood still costs some of my own legitimate UDP traffic, as the table above shows.

## Build and test
    cd xdp && make                            # needs clang, libbpf-dev, linux-libc-dev
    sudo python3 ftest.py v8 fortress_xdp.o   # needs root

Setup on a server is in `docs/DEPLOY.md`.

## Checked so far
| Item | Status |
|---|---|
| Filter compiles with no warnings | yes |
| Kernel verifier accepts it | yes (1,959 instructions) |
| 31 single-packet correctness cases | all pass |
| nftables file passes `nft -c` | yes |
| Python and shell scripts parse | yes |
| Service and sysctl files | running on my server, not re-tested from this repo |

## Notes
Addresses are placeholders. I deployed, operated and debugged this on my own infrastructure.

MIT licensed.
