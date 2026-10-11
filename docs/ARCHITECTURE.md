# How it works

Layered inbound controls for a single internet-exposed host. For a plain-language
version of the same picture, see the README.


## The path a packet takes
    internet
      -> OVH network protection and edge firewall
      -> the network card
      -> my XDP filter (fortress_xdp.c)
      -> nftables early rules (chain wan_ingress)
      -> connection tracking
      -> nftables input and forward rules
      -> the server

Each layer turns away the visitors it can and lets the rest through to the next one. The earlier a bad packet
dies, the less work my small 2-CPU server does for it.

## Why four layers
| Layer | Good at | Can't do |
|---|---|---|
| OVH edge firewall | Stops traffic before it reaches me | It is stateless, and it does not see attackers inside OVH |
| XDP filter | Cheapest way to drop packets on the host | It has no memory of connections |
| nftables | Tracks connections, flags scanners | Runs after the kernel has already handled the packet |
| The server | Final say | Weakest place to fight a flood |

## What the XDP filter checks, in order
1. Damaged, fragmented or oddly-sourced packets are dropped (private and reserved
   source addresses, unknown protocols).
2. DHCP is let through first, because it legitimately comes from private addresses.
3. UDP: port zero is dropped, my VPN port gets a fast lane (only for packets that
   look like real tunnel traffic), bait ports are dropped, then each source and
   each type of UDP gets a rate limit, then an overall ceiling.
4. TCP: allowed services pass, remote-admin and bait ports are dropped, SYNs are
   sampled, empty acknowledgements are rate limited, then the overall ceiling.
5. Whatever is left goes to nftables.

Rate limits are token buckets: each source gets a small allowance that refills at a
steady rate. Counters are kept per CPU and read with `xdp-stats`.

## Choices I made and why
- **Soft failure on the tunnel check.** A packet that fails the shape check is
  treated as ordinary UDP, not dropped. A wrong guess here would cut me off.
- **Generic XDP.** The VPS network driver (virtio_net, one queue) cannot run native
  mode.
- **Bait ports.** Anyone who touches one gets added to a scanner list.
- **Strict connection tracking.** `nf_conntrack_tcp_loose=0` makes mid-stream ACK
  floods count as invalid, so they get dropped.
- **Rollback on every load.** `load.sh on` detaches the filter by itself after a
  timer unless I confirm it, so a bad version cannot lock me out of SSH.
- **Changes live in small files.** Runtime changes sit in `/etc/nftables.d/zz-*.nft`
  so the main rules file stays clean.

## What it covers
UDP, SYN, bare ACK and NULL-flag floods, port scans, and spoofed private-address
sources. It does not cover terabit-scale floods (that needs the provider),
application-layer attacks, or attackers inside the provider network that bypass the
edge firewall in ways the host cannot see.
