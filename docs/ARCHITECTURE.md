# Architecture

## Packet path (inbound on `ens3`)
    internet
      -> OVH VAC (provider scrubbing, volumetric)
      -> OVH Edge Network Firewall   stateless allow-list, 20 rules, IPv4 only
      -> NIC (virtio_net, 1 queue)
      -> XDP, generic mode           fortress_xdp.c, stateless, token buckets
      -> netdev ingress (nftables)   chain wan_ingress, priority -500
      -> conntrack
      -> input / forward (nftables)  stateful, policy drop

Each layer drops cheaply what it can and leaves the rest to the next one.
The earlier a packet dies, the less CPU it costs on a 2 vCPU host.

## Why each layer exists
| Layer | Strength | Blind spot |
|---|---|---|
| OVH edge firewall | Drops before the VPS sees it | Stateless; does not see attackers inside OVH |
| XDP | Cheapest host-side drop, per-source and shared rate limits | Stateless; generic mode only on virtio_net |
| nftables | Stateful: conntrack, scanner and flooder sets, bait ports | Runs after the stack allocates the packet |

## XDP decision order (`fortress_xdp.c`)
1. Truncated, fragment, bogon source, non-TCP/UDP/ICMP: drop.
2. DHCP and DHCPv6 exempt (checked before the bogon rule).
3. UDP: port 0 drop, shaped fast lane for 41641, bait ports drop,
   per-source bucket, class valve (replies vs other), global ceiling.
4. TCP: allowlisted SSH and game ports pass, RCON/bait/privileged ports drop,
   bare SYN sampled, zero-payload segments rate limited, global ceiling.
5. Everything else passes to nftables.

Token buckets use LRU hash maps for per-source state and a small array for
the shared "valves". Counters are per-CPU and read with `xdp-stats`.

## Design decisions
- **Fail soft on shape checks.** A packet that fails the Tailscale shape check
  is treated as ordinary unsolicited UDP, not dropped outright.
- **Generic XDP.** Native mode is not available on this virtio_net setup.
- **Bait ports.** Touching a bait port puts the source into `scanners4`.
- **Conntrack strict.** `nf_conntrack_tcp_loose=0` turns mid-stream ACK floods
  into invalid packets, which are dropped.
- **Rollback-first deploys.** `load.sh on` auto-detaches unless confirmed, so a
  bad filter cannot lock out SSH.
- **Persistence by drop-in.** Runtime changes live in `/etc/nftables.d/zz-*.nft`
  using `insert rule` / `add element`, so the base file stays clean.

## Threat model
Covered: floods of UDP, SYN, bare ACK and NULL packets; port scans; spoofed
bogon sources. Not covered: terabit volumetric floods (provider scrubbing
only), application-layer attacks, attackers inside the provider network that
bypass the edge firewall.
