#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * fortress_xdp v7 — hardened.
 *
 * Role: a CHEAP, STATELESS pre-filter on the WAN. It drops obvious garbage
 * (bogons, bad flags, fragments), rate-limits per source, and puts a HARD
 * GLOBAL CEILING on everything that isn't an explicitly allowed service, so a
 * distributed flood (which slips every per-source limit) still hits a wall
 * before it reaches conntrack. It is NOT the policy layer — nftables, which is
 * stateful (ct state), enforces default-deny and separates real return traffic
 * from attack. XDP deliberately PASSES high-port replies so it can never
 * blackhole the host's own outbound connections or the Tailscale exit node's
 * return traffic; nft decides their fate statefully.
 *
 * v8 changes over v7 (after a ~285k pps straight-UDP flood got through):
 *   - UDP: unsolicited UDP now goes through small aggregate valves instead of
 *     being passed whenever each source stays under its own limit.
 *   - UDP 41641 (Tailscale): only WireGuard/disco/STUN-shaped packets get the
 *     fast lane; anything else on that port is treated as unsolicited UDP.
 *   - TCP: inbound bare SYNs are cut to a 500/s sample in total (this host
 *     has no public TCP service; allowlisted SSH/Minecraft are handled first).
 *   - TCP: "bare" now means zero payload, not "PSH clear", so bulk downloads
 *     are no longer clipped by the per-source ACK limit.
 *   - Global ceiling lowered to what this box can actually process.
 */

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP   1
#define IPPROTO_TCP    6
#define IPPROTO_UDP    17
#define IPPROTO_ICMPV6 58
#endif

struct lpm4 { __u32 prefixlen; __u32 addr; };

#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define WG_PORT 51820
#define TS_PORT 41641
#define MC_PORT 25565
#define SSH_PORT 22
#define RCON_PORT 25575
#define NSEC_PER_SEC 1000000000ull
/* Per-source UDP cap. Raised for exit-node use: legit real-time UDP (Discord
 * voice/video/screenshare, game traffic) from a single server easily exceeds
 * 1-2k pps, and this box now forwards the user's own traffic. Floods are
 * caught downstream anyway — nft drops unsolicited UDP statefully, the global
 * valve caps the aggregate, and a single-source flood above this still gets
 * chopped here then dropped by nft. */
#define UDP_RATE 5000
#define UDP_BURST 10000
#define ACK_RATE 8000
#define ACK_BURST 16000
#define ICMP_RATE 20
#define ICMP_BURST 40
#define RATE_MAP 65536

/* Aggregate valves (packets/second, burst). One shared token bucket each.
 * They bound what reaches conntrack no matter how many sources take part.
 * While a valve is saturated, legitimate traffic of the same class is lost
 * too; the tunnel and TCP data are in separate classes for that reason. */
#define V_GLOBAL     0	/* everything that is not an allowed service */
#define V_UDP_REPLY  1	/* UDP from sport 53/123/443/3478 (DNS, NTP, QUIC, STUN) */
#define V_UDP_OTHER  2	/* all other unsolicited UDP */
#define V_TCP_BARE   3	/* TCP segments with no payload (ACK/RST/FIN) */
#define V_TS         4	/* well-formed tunnel packets to 41641 */
#define V_DHCP       5
#define V_SYN        6	/* inbound bare SYNs let through for nftables to log */
#define V_MAX        7
#define GLOBAL_RATE  120000
#define UDP_REPLY_RATE 20000
#define UDP_OTHER_RATE 20000
#define TCP_BARE_RATE  30000
#define TS_RATE        60000
#define TS_SRC_RATE    20000
#define DHCP_RATE      100
#define SYN_SAMPLE_RATE 500

enum {
	S_PASS = 0, S_DROP_TRUNC, S_DROP_BOGON, S_DROP_FRAG, S_DROP_OTHER,
	S_DROP_BADFLAGS, S_DROP_BAIT_TCP, S_DROP_SSH, S_DROP_MC, S_DROP_SYN_RATE,
	S_DROP_BAIT_UDP, S_DROP_UDP_RATE, S_DROP_ICMP_RATE, S_DROP_IPV6_TCP,
	S_DROP_ACK_RATE, S_DROP_PRIV, S_DROP_GLOBAL, S_DROP_UDP_VALVE, S_MAX
};

struct eth_hdr { __u8 dst[6]; __u8 src[6]; __be16 proto; };
struct vlan_hdr { __be16 tci; __be16 proto; };
struct ip_hdr {
	__u8 ver_ihl; __u8 tos; __be16 tot_len; __be16 id; __be16 frag_off;
	__u8 ttl; __u8 proto; __be16 check; __be32 saddr; __be32 daddr;
};
struct ipv6_hdr {
	__u8 ver_tc; __u8 tc_fl; __be16 fl; __be16 payload_len;
	__u8 nexthdr; __u8 hop_limit; __u8 saddr[16]; __u8 daddr[16];
};
struct tcp_hdr {
	__be16 source; __be16 dest; __be32 seq; __be32 ack_seq;
	__u8 doff_res; __u8 flags; __be16 window; __be16 check; __be16 urg_ptr;
};
struct udp_hdr { __be16 source; __be16 dest; __be16 len; __be16 check; };
struct icmp_hdr { __u8 type; __u8 code; __be16 check; };
struct rate_key { __u32 addr; };
struct rate_val { __u64 last_ns; __s32 tokens; };

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, S_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, RATE_MAP);
	__type(key, struct rate_key);
	__type(value, struct rate_val);
} udp4 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, RATE_MAP);
	__type(key, struct rate_key);
	__type(value, struct rate_val);
} ack4 SEC(".maps");
/* Shared valve buckets, indexed by V_*. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, V_MAX);
	__type(key, __u32);
	__type(value, struct rate_val);
} valves SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm4);
	__type(value, __u8);
} mc_allow4 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} ssh_allow4 SEC(".maps");

static __always_inline void count(__u32 key)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &key);
	if (v) (*v)++;
}
static __always_inline int allow_mc(__u32 saddr)
{
	struct lpm4 key = { .prefixlen = 32, .addr = saddr };
	return bpf_map_lookup_elem(&mc_allow4, &key) != 0;
}
static __always_inline int allow_ssh(__u32 saddr)
{
	return bpf_map_lookup_elem(&ssh_allow4, &saddr) != 0;
}
static __always_inline int take_tokens(void *map, __u32 saddr, __u32 rate, __u32 burst)
{
	struct rate_key k = { .addr = saddr };
	struct rate_val *b, init = {};
	__u64 now = bpf_ktime_get_ns();
	__u64 add;
	b = bpf_map_lookup_elem(map, &k);
	if (!b) {
		init.last_ns = now;
		init.tokens = burst - 1;
		bpf_map_update_elem(map, &k, &init, BPF_ANY);
		return 1;
	}
	if (now > b->last_ns) {
		add = ((now - b->last_ns) * rate) / NSEC_PER_SEC;
		if (add) {
			if (add > burst) add = burst;
			b->tokens += (__s32)add;
			if (b->tokens > (__s32)burst) b->tokens = burst;
			b->last_ns = now;
		}
	}
	if (b->tokens < 1) return 0;
	b->tokens--;
	return 1;
}
/* Aggregate valve. Best-effort across CPUs: a race can let a few extra
 * packets through, never fewer than the configured rate. Burst is 2x rate.
 * Returns 1 to pass, 0 when the valve is exhausted. */
static __always_inline int valve(__u32 k, __u32 rate)
{
	struct rate_val *b = bpf_map_lookup_elem(&valves, &k);
	__u32 burst = rate * 2;
	__u64 now, add;
	if (!b) return 1;
	now = bpf_ktime_get_ns();
	if (b->last_ns == 0) {
		b->last_ns = now;
		b->tokens = burst - 1;
		return 1;
	}
	if (now > b->last_ns) {
		add = ((now - b->last_ns) * rate) / NSEC_PER_SEC;
		if (add) {
			if (add > burst) add = burst;
			b->tokens += (__s32)add;
			if (b->tokens > (__s32)burst) b->tokens = burst;
			b->last_ns = now;
		}
	}
	if (b->tokens < 1) return 0;
	b->tokens--;
	return 1;
}
/* Does a packet to the Tailscale port look like something tailscaled would
 * accept? WireGuard messages start with type 1..4 and three zero bytes;
 * Tailscale disco packets start with "TS" + U+1F4AC; STUN replies come from
 * port 3478 with the magic cookie. A random-payload flood fails all three.
 * Failing is not a drop: the packet is just treated as unsolicited UDP. */
static __always_inline int ts_shape_ok(void *end, struct udp_hdr *u, __u16 sport)
{
	__u8 *p = (void *)(u + 1);
	__u16 plen = bpf_ntohs(u->len);
	if ((void *)(p + 8) > end) return 0;
	if (plen < 16) return 0;
	plen -= 8;
	if (p[0] >= 1 && p[0] <= 4 && !p[1] && !p[2] && !p[3] && plen >= 32) return 1;
	if (p[0] == 0x54 && p[1] == 0x53 && p[2] == 0xf0 && p[3] == 0x9f &&
	    p[4] == 0x92 && p[5] == 0xac) return 1;
	if (sport == 3478 && p[4] == 0x21 && p[5] == 0x12 && p[6] == 0xa4 && p[7] == 0x42) return 1;
	return 0;
}
static __always_inline int ipv4_bogon(__u32 addr)
{
	__u32 a = bpf_ntohl(addr);
	if (a == 0xffffffff) return 0;
	if ((a & 0xff000000) == 0x00000000) return 1;
	if ((a & 0xff000000) == 0x0a000000) return 1;
	if ((a & 0xffc00000) == 0x64400000) return 1;
	if ((a & 0xff000000) == 0x7f000000) return 1;
	if ((a & 0xffff0000) == 0xa9fe0000) return 1;
	if ((a & 0xfff00000) == 0xac100000) return 1;
	if ((a & 0xffffff00) == 0xc0000000) return 1;
	if ((a & 0xffffff00) == 0xc0000200) return 1;
	if ((a & 0xffff0000) == 0xc0a80000) return 1;
	if ((a & 0xfffe0000) == 0xc6120000) return 1;
	if ((a & 0xffffff00) == 0xc6336400) return 1;
	if ((a & 0xffffff00) == 0xcb007100) return 1;
	if ((a & 0xf0000000) == 0xe0000000) return 1;
	if ((a & 0xf0000000) == 0xf0000000) return 1;
	return 0;
}
static __always_inline int bait_tcp(__u16 p)
{
	switch (p) {
	case 20: case 21: case 23: case 25: case 53:
	case 80: case 110: case 135: case 139: case 143:
	case 161: case 389: case 443: case 445: case 993:
	case 995: case 1433: case 1521: case 2049: case 3306:
	case 3389: case 5432: case 5900: case 6379: case 8000:
	case 8080: case 8443: case 9200: case 11211: case 27017:
		return 1;
	default: return 0;
	}
}
static __always_inline int bait_udp(__u16 p)
{
	switch (p) {
	case 53: case 123: case 137: case 138: case 161:
	case 389: case 1900: case 5353: case 11211:
	case 19132: case 27015:
		return 1;
	default: return 0;
	}
}
static __always_inline int bad_tcp_flags(__u8 f)
{
	if ((f & (TCP_FIN | TCP_SYN)) == (TCP_FIN | TCP_SYN)) return 1;
	if ((f & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST)) return 1;
	if ((f & (TCP_FIN | TCP_RST)) == (TCP_FIN | TCP_RST)) return 1;
	if ((f & (TCP_FIN | TCP_SYN | TCP_RST | TCP_PSH | TCP_ACK | TCP_URG)) == 0) return 1;
	if ((f & (TCP_FIN | TCP_SYN | TCP_RST | TCP_PSH | TCP_ACK | TCP_URG)) ==
	    (TCP_FIN | TCP_SYN | TCP_RST | TCP_PSH | TCP_ACK | TCP_URG)) return 1;
	if ((f & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG)) return 1;
	if ((f & TCP_SYN) && (f & (TCP_FIN | TCP_RST | TCP_PSH | TCP_URG))) return 1;
	return 0;
}

static __always_inline int parse_tcp(void *data, void *end, void *hdr, __u32 saddr, int v6, __u32 l4len)
{
	struct tcp_hdr *t = hdr;
	__u16 dport;
	__u8 flags, doff;
	if ((void *)(t + 1) > end) { count(S_DROP_TRUNC); return XDP_DROP; }
	doff = t->doff_res >> 4;
	if (doff < 5 || (void *)t + doff * 4 > end) { count(S_DROP_TRUNC); return XDP_DROP; }
	flags = t->flags;
	if (bad_tcp_flags(flags)) { count(S_DROP_BADFLAGS); return XDP_DROP; }
	dport = bpf_ntohs(t->dest);
	if (dport == 0) { count(S_DROP_OTHER); return XDP_DROP; }
	if (dport == SSH_PORT) {
		if (!v6 && allow_ssh(saddr)) { count(S_PASS); return XDP_PASS; }
		count(S_DROP_SSH); return XDP_DROP;
	}
	if (dport == MC_PORT) {
		if (!v6 && allow_mc(saddr)) { count(S_PASS); return XDP_PASS; }
		count(S_DROP_MC); return XDP_DROP;
	}
	if (dport == RCON_PORT) { count(S_DROP_MC); return XDP_DROP; }
	if (bait_tcp(dport)) { count(S_DROP_BAIT_TCP); return XDP_DROP; }
	if (dport < 1024) { count(S_DROP_PRIV); return XDP_DROP; }
	/* A bare SYN is a new inbound connection. This host offers no public
	 * TCP service (allowlisted SSH/Minecraft returned above), so none is
	 * legitimate. A small aggregate sample is still passed so nftables can
	 * log scanners and the bait ports keep working; a SYN flood is cut to
	 * that sample. SYN-ACK replies to our own outbound connections carry
	 * ACK and are not affected. */
	if ((flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
		if (v6) { count(S_DROP_IPV6_TCP); return XDP_DROP; }
		if (!valve(V_SYN, SYN_SAMPLE_RATE)) { count(S_DROP_SYN_RATE); return XDP_DROP; }
		count(S_PASS); return XDP_PASS;
	}
	/* Segments with no payload (ACK/RST/FIN floods look like this) get a
	 * per-source cap and an aggregate valve. Data segments are left to the
	 * global ceiling so downloads keep their throughput. */
	if (l4len <= (__u32)doff * 4) {
		if (!v6 && !take_tokens(&ack4, saddr, ACK_RATE, ACK_BURST)) {
			count(S_DROP_ACK_RATE); return XDP_DROP;
		}
		if (!valve(V_TCP_BARE, TCP_BARE_RATE)) { count(S_DROP_ACK_RATE); return XDP_DROP; }
	}
	if (!valve(V_GLOBAL, GLOBAL_RATE)) { count(S_DROP_GLOBAL); return XDP_DROP; }
	count(S_PASS); return XDP_PASS;
}

static __always_inline int parse_udp(void *end, void *hdr, __u32 saddr, __u32 daddr)
{
	struct udp_hdr *u = hdr;
	__u16 dport, sport;
	__u32 cls;
	if ((void *)(u + 1) > end) { count(S_DROP_TRUNC); return XDP_DROP; }
	dport = bpf_ntohs(u->dest);
	sport = bpf_ntohs(u->source);
	if (dport == 0) { count(S_DROP_OTHER); return XDP_DROP; }
	/* DHCP / DHCPv6 replies to this host: rare, so a tiny valve of their own. */
	if ((dport == 68 && sport == 67) || (dport == 546 && sport == 547)) {
		if (!valve(V_DHCP, DHCP_RATE)) { count(S_DROP_UDP_VALVE); return XDP_DROP; }
		count(S_PASS); return XDP_PASS;
	}
	/* Tunnel fast lane: only packets shaped like WireGuard/disco/STUN. */
	if (dport == TS_PORT && ts_shape_ok(end, u, sport)) {
		if (saddr && !take_tokens(&udp4, saddr ^ 0x54536864, TS_SRC_RATE, TS_SRC_RATE * 2)) {
			count(S_DROP_UDP_RATE); return XDP_DROP;
		}
		if (!valve(V_TS, TS_RATE)) { count(S_DROP_UDP_VALVE); return XDP_DROP; }
		count(S_PASS); return XDP_PASS;
	}
	if (bait_udp(dport)) { count(S_DROP_BAIT_UDP); return XDP_DROP; }
	if (saddr && !take_tokens(&udp4, saddr, UDP_RATE, UDP_BURST)) {
		count(S_DROP_UDP_RATE); return XDP_DROP;
	}
	/* Everything else is either a reply to something we sent or a flood;
	 * XDP cannot tell which, so both classes are metered in aggregate and
	 * nftables (conntrack) makes the final call on what gets through. */
	cls = (sport == 53 || sport == 123 || sport == 443 || sport == 3478) ? V_UDP_REPLY : V_UDP_OTHER;
	if (!valve(cls, cls == V_UDP_REPLY ? UDP_REPLY_RATE : UDP_OTHER_RATE)) {
		count(S_DROP_UDP_VALVE); return XDP_DROP;
	}
	if (!valve(V_GLOBAL, GLOBAL_RATE)) { count(S_DROP_GLOBAL); return XDP_DROP; }
	count(S_PASS); return XDP_PASS;
}

static __always_inline int parse_icmp4(void *end, void *hdr, __u32 saddr, __u32 daddr)
{
	struct icmp_hdr *i = hdr;
	if ((void *)(i + 1) > end) { count(S_DROP_TRUNC); return XDP_DROP; }
	if (i->type == 8) {
		if (daddr == 0xffffffff) { count(S_DROP_ICMP_RATE); return XDP_DROP; }
		if (!take_tokens(&udp4, saddr ^ 0x49634d50, ICMP_RATE, ICMP_BURST)) {
			count(S_DROP_ICMP_RATE); return XDP_DROP;
		}
	}
	count(S_PASS); return XDP_PASS;
}

static __always_inline int parse_ipv6(void *data, void *end, struct ipv6_hdr *ip6)
{
	void *l4;
	__u8 nh;
	if ((void *)(ip6 + 1) > end) { count(S_DROP_TRUNC); return XDP_DROP; }
	if ((ip6->saddr[0] & 0xfe) == 0xfc ||
	    (ip6->saddr[0] == 0 && ip6->saddr[15] == 1 &&
	     !ip6->saddr[1] && !ip6->saddr[2] && !ip6->saddr[3])) {
		count(S_DROP_BOGON); return XDP_DROP;
	}
	nh = ip6->nexthdr;
	if (nh == 44) { count(S_DROP_FRAG); return XDP_DROP; }
	if (nh != IPPROTO_TCP && nh != IPPROTO_UDP && nh != IPPROTO_ICMPV6) {
		count(S_DROP_OTHER); return XDP_DROP;
	}
	l4 = ip6 + 1;
	if (nh == IPPROTO_TCP) return parse_tcp(data, end, l4, 0, 1, bpf_ntohs(ip6->payload_len));
	if (nh == IPPROTO_UDP) return parse_udp(end, l4, 0, 0);
	count(S_PASS); return XDP_PASS;
}

static __always_inline int parse_ipv4(void *data, void *end, struct ip_hdr *ip)
{
	void *l4;
	__u32 ihl, saddr, daddr;
	__u16 frag;
	if ((void *)(ip + 1) > end) { count(S_DROP_TRUNC); return XDP_DROP; }
	if ((ip->ver_ihl >> 4) != 4) { count(S_DROP_TRUNC); return XDP_DROP; }
	ihl = (ip->ver_ihl & 0x0f) * 4;
	if (ihl < sizeof(*ip) || (void *)ip + ihl > end) { count(S_DROP_TRUNC); return XDP_DROP; }
	if (ihl > sizeof(*ip)) { count(S_DROP_OTHER); return XDP_DROP; }
	saddr = ip->saddr;
	daddr = ip->daddr;
	if (saddr == daddr && daddr != 0xffffffff) { count(S_DROP_BOGON); return XDP_DROP; }
	frag = bpf_ntohs(ip->frag_off);
	if (frag & (IP_OFFMASK | IP_MF)) { count(S_DROP_FRAG); return XDP_DROP; }
	l4 = (void *)ip + ihl;
	/* DHCP (server->client, sport 67 dport 68) is legitimately sourced from
	 * private or link-local addresses, so it must survive the bogon filter —
	 * otherwise a private-IP DHCP server breaks the box's own lease renewal. */
	if (ip->proto == IPPROTO_UDP) {
		struct udp_hdr *u = l4;
		if ((void *)(u + 1) <= end &&
		    bpf_ntohs(u->source) == 67 && bpf_ntohs(u->dest) == 68)
			goto l4dispatch;
	}
	/* Broadcast DHCP (client discover/request) is also source-exempt. */
	if (!(daddr == 0xffffffff && ip->proto == IPPROTO_UDP) && ipv4_bogon(saddr)) {
		count(S_DROP_BOGON); return XDP_DROP;
	}
l4dispatch:
	switch (ip->proto) {
	case IPPROTO_TCP: {
		__u32 tot = bpf_ntohs(ip->tot_len);
		return parse_tcp(data, end, l4, saddr, 0, tot > ihl ? tot - ihl : 0);
	}
	case IPPROTO_UDP: return parse_udp(end, l4, saddr, daddr);
	case IPPROTO_ICMP: return parse_icmp4(end, l4, saddr, daddr);
	default: count(S_DROP_OTHER); return XDP_DROP;
	}
}

SEC("xdp")
int fortress_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth = data;
	__be16 proto;
	void *nh;
	if ((void *)(eth + 1) > end) { count(S_DROP_TRUNC); return XDP_DROP; }
	proto = eth->proto;
	nh = eth + 1;
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *v = nh;
		if ((void *)(v + 1) > end) { count(S_DROP_TRUNC); return XDP_DROP; }
		proto = v->proto;
		nh = v + 1;
	}
	if (proto == bpf_htons(ETH_P_IP)) return parse_ipv4(data, end, nh);
	if (proto == bpf_htons(ETH_P_IPV6)) return parse_ipv6(data, end, nh);
	if (proto == bpf_htons(ETH_P_ARP)) { count(S_PASS); return XDP_PASS; }
	count(S_DROP_OTHER); return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
