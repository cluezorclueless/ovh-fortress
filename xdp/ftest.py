#!/usr/bin/env python3
"""Load a fortress_xdp object through the real kernel verifier and fire floods
at it with BPF_PROG_TEST_RUN at more than 500k packets/second.

  ftest.py v8  path/to/fortress_xdp.o
  ftest.py v10 path/to/fortress_xdp.o

Hand loader: handles static sub-programs (.text) and spin-lock map values
(needs a small BTF), which the older harness could not.
"""
import ctypes, os, random, socket, struct, sys, time

libc = ctypes.CDLL(None, use_errno=True)
NR_BPF = 321
MAP_CREATE, MAP_LOOKUP, MAP_UPDATE, PROG_LOAD, TEST_RUN, BTF_LOAD = 0, 1, 2, 5, 10, 18
HASH, ARRAY, PERCPU_ARRAY, LRU_HASH, LPM_TRIE = 1, 2, 6, 9, 11
DROP, PASS = 1, 2
NCPU = int(open("/sys/devices/system/cpu/possible").read().strip().split("-")[-1]) + 1

PROFILES = {
    "v8": {
        "stats": ["pass", "trunc", "bogon", "frag", "other-proto", "badflags", "bait-tcp",
                  "ssh", "mc", "syn-rate", "bait-udp", "udp-rate", "icmp-rate", "ipv6-tcp",
                  "ack-rate", "priv", "global", "udp-valve"],
        "maps": {
            "udp4": (LRU_HASH, 4, 16, 65536, 0, False),
            "ack4": (LRU_HASH, 4, 16, 65536, 0, False),
            "valves": (ARRAY, 4, 16, 7, 0, False),
            "mc_allow4": (LPM_TRIE, 8, 1, 4096, 1, False),
            "ssh_allow4": (HASH, 4, 1, 64, 0, False),
        },
    },
    "v10": {
        "stats": ["pass", "trunc", "bogon", "frag", "other-proto", "badflags", "bait-tcp",
                  "ssh", "mc", "syn-rate", "bait-udp", "udp-rate", "icmp-rate", "ipv6-tcp",
                  "ack-rate", "priv", "global", "options", "ttl", "icmp-type", "mss", "ts",
                  "synproxy", "flow", "cookie", "amplify", "len", "win", "mcast",
                  "data-rate", "csum"],
        "maps": dict(
            [(n, (ARRAY, 4, 16, 65536, 0, True)) for n in
             ("syn4", "udp4", "ack4", "data4", "icmp4", "wg4", "amp4")] +
            [("global_pcpu", (ARRAY, 4, 16, 8, 0, True)),
             ("verified4", (LRU_HASH, 4, 8, 65536, 0, False)),
             ("mc_allow4", (LPM_TRIE, 8, 1, 4096, 1, False)),
             ("ssh_allow4", (HASH, 4, 1, 64, 0, False))]),
    },
}


def bpf(cmd, attr):
    buf = ctypes.create_string_buffer(attr, len(attr))
    r = libc.syscall(NR_BPF, cmd, buf, len(attr))
    if r < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return r, buf.raw


def lock_btf():
    """BTF describing {u32 key} and struct locked_bucket {bpf_spin_lock; s32; u64}."""
    strs = b"\0"
    def s(name):
        nonlocal strs
        off = len(strs); strs += name.encode() + b"\0"; return off
    t = b""
    t += struct.pack("<III", s("unsigned int"), 1 << 24, 4) + struct.pack("<I", 32)            # 1
    t += struct.pack("<III", s("bpf_spin_lock"), (4 << 24) | 1, 4) + struct.pack("<III", s("val"), 1, 0)  # 2
    t += struct.pack("<III", s("int"), 1 << 24, 4) + struct.pack("<I", (1 << 24) | 32)         # 3
    t += struct.pack("<III", s("unsigned long long"), 1 << 24, 8) + struct.pack("<I", 64)     # 4
    t += struct.pack("<III", s("locked_bucket"), (4 << 24) | 3, 16)                            # 5
    t += struct.pack("<III", s("lock"), 2, 0) + struct.pack("<III", s("tokens"), 3, 32)
    t += struct.pack("<III", s("last_ns"), 4, 64)
    blob = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(t), len(t), len(strs)) + t + strs
    buf = ctypes.create_string_buffer(blob, len(blob))
    log = ctypes.create_string_buffer(65536)
    attr = struct.pack("QQIII", ctypes.addressof(buf), ctypes.addressof(log), len(blob), len(log), 1)
    try:
        return bpf(BTF_LOAD, attr.ljust(64, b"\0"))[0]
    except OSError as exc:
        sys.exit(f"BTF load failed: {exc}\n{log.value.decode()[-800:]}")


def map_create(name, mtype, ksz, vsz, entries, flags, btf_fd=0):
    attr = struct.pack("IIIIIII16sIIII", mtype, ksz, vsz, entries, flags, 0, 0, name.encode(),
                       0, btf_fd, 1 if btf_fd else 0, 5 if btf_fd else 0)
    return bpf(MAP_CREATE, attr.ljust(128, b"\0"))[0]


def load(path, profile):
    elf = open(path, "rb").read()
    shoff, = struct.unpack_from("<Q", elf, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 0x3A)
    secs = []
    for i in range(shnum):
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
            "<IIQQQQIIQQ", elf, shoff + i * shentsize)
        secs.append(dict(name=name, off=off, size=size, link=link, type=typ, idx=i))
    strtab = secs[shstrndx]
    for s in secs:
        end = elf.index(b"\0", strtab["off"] + s["name"])
        s["sname"] = elf[strtab["off"] + s["name"]:end].decode()
    by = {s["sname"]: s for s in secs}
    xdp = elf[by["xdp"]["off"]:by["xdp"]["off"] + by["xdp"]["size"]]
    text = b""
    if ".text" in by:
        text = elf[by[".text"]["off"]:by[".text"]["off"] + by[".text"]["size"]]
    code = bytearray(xdp + text)
    text_base = len(xdp) // 8
    symtab, symstr = by[".symtab"], secs[by[".symtab"]["link"]]
    need_btf = any(spec[5] for spec in profile["maps"].values())
    btf_fd = lock_btf() if need_btf else 0
    fds = {"stats": map_create("stats", PERCPU_ARRAY, 4, 8, len(profile["stats"]), 0)}
    for n, spec in profile["maps"].items():
        fds[n] = map_create(n, *spec[:5], btf_fd=btf_fd if spec[5] else 0)

    def sym(index):
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", elf, symtab["off"] + index * 24)
        end = elf.index(b"\0", symstr["off"] + st_name)
        return elf[symstr["off"] + st_name:end].decode(), st_shndx, st_value

    for relname, base in ((".relxdp", 0), (".rel.text", text_base)):
        if relname not in by:
            continue
        rel = by[relname]
        for i in range(rel["size"] // 16):
            r_off, r_info = struct.unpack_from("<QQ", elf, rel["off"] + i * 16)
            name, shndx, value = sym(r_info >> 32)
            at = base * 8 + r_off
            opcode = code[at]
            if opcode == 0x18:                       # ld_imm64 -> map fd
                if name not in fds:
                    sys.exit(f"relocation against unknown map {name!r}")
                code[at + 1] = (code[at + 1] & 0x0F) | (1 << 4)
                struct.pack_into("<i", code, at + 4, fds[name])
            elif opcode == 0x85:                     # call -> sub-program in .text
                if ".text" not in by or shndx != by[".text"]["idx"]:
                    sys.exit(f"call relocation to {name!r} outside .text")
                imm, = struct.unpack_from("<i", code, at + 4)
                target = text_base + value // 8 + imm + 1
                struct.pack_into("<i", code, at + 4, target - (at // 8 + 1))
                code[at + 1] = (code[at + 1] & 0x0F) | (1 << 4)
            else:
                sys.exit(f"unhandled relocation on opcode {opcode:#x} ({name})")
    insns = ctypes.create_string_buffer(bytes(code), len(code))
    lic = ctypes.create_string_buffer(b"GPL")

    def attempt(level):
        log = ctypes.create_string_buffer(1 << 24) if level else ctypes.create_string_buffer(1)
        attr = struct.pack("IIQQIIQII16s", 6, len(code) // 8, ctypes.addressof(insns),
                           ctypes.addressof(lic), level, len(log) if level else 0,
                           ctypes.addressof(log) if level else 0, 0, 0,
                           b"fortress_xdp").ljust(148, b"\0")
        try:
            return bpf(PROG_LOAD, attr)[0], log
        except OSError as exc:
            return exc, log

    fd, _ = attempt(0)
    if isinstance(fd, OSError):
        err, log = attempt(1)
        print(log.value.decode(errors="replace")[-2500:])
        sys.exit(f"VERIFIER REJECTED: {fd}")
    return fd, fds, len(code) // 8


class Runner:
    def __init__(self, fd):
        self.attr = ctypes.create_string_buffer(80)
        self.pkt = ctypes.create_string_buffer(2048)
        struct.pack_into("I", self.attr, 0, fd)
        struct.pack_into("Q", self.attr, 16, ctypes.addressof(self.pkt))

    def run(self, data, repeat=1):
        n = len(data)
        ctypes.memmove(self.pkt, data, n)
        struct.pack_into("II", self.attr, 8, n, 0)
        struct.pack_into("II", self.attr, 32, repeat, 0)
        if libc.syscall(NR_BPF, TEST_RUN, self.attr, 80) < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return struct.unpack_from("I", self.attr, 4)[0]


def read_stats(fd, names):
    out = {}
    for i, name in enumerate(names):
        key = ctypes.create_string_buffer(struct.pack("I", i))
        val = ctypes.create_string_buffer(8 * NCPU)
        attr = struct.pack("IIQQQ", fd, 0, ctypes.addressof(key), ctypes.addressof(val), 0)
        bpf(MAP_LOOKUP, attr.ljust(64, b"\0"))
        out[name] = sum(struct.unpack(f"{NCPU}Q", val.raw))
    return out


ETH4 = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00"
ME = socket.inet_aton("203.0.113.10")
FIN, SYN, RST, PSH, ACK, URG = 1, 2, 4, 8, 16, 32


def csum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip4(src, proto, payload):
    if isinstance(src, str):
        src = socket.inet_aton(src)
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, 0x4000, 58, proto, 0, src, ME)
    head = head[:10] + struct.pack("!H", csum(head)) + head[12:]
    return ETH4 + head + payload


def tcp(src, sport, dport, flags, extra=b""):
    return ip4(src, 6, struct.pack("!HHIIBBHHH", sport, dport, 0x1000, 0x2000, 5 << 4, flags, 4096, 0xBEEF, 0) + extra)


def udp(src, sport, dport, payload):
    return ip4(src, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0xBEEF) + payload)


def rnd_src(rng):
    while True:
        a = rng.randrange(1, 224)
        if a not in (10, 100, 127, 169, 172, 192, 198, 203):
            return struct.pack("!BBBB", a, rng.randrange(256), rng.randrange(256), rng.randrange(1, 255))


WG_DATA = b"\x04\x00\x00\x00" + os.urandom(12) + os.urandom(120)   # WireGuard transport-data shape


def legit_flows(rng):
    """name -> (packets per second, generator). Roughly what the exit node carries."""
    n = {"i": 0}

    def download():
        n["i"] += 1
        flags = ACK | PSH if n["i"] % 10 == 0 else ACK          # most data segments carry no PSH
        return tcp("151.101.1.140", 443, 45000, flags, b"d" * 1200)

    return {
        "tunnel (WireGuard-shaped, UDP 41641)": (1000, lambda: udp("172.58.10.20", 41641, 41641, WG_DATA)),
        "TCP download, one server": (3000, download),
        "TCP ACKs for an upload": (800, lambda: tcp("151.101.1.140", 443, 45001, ACK)),
        "voice/video UDP, one server": (1500, lambda: udp("162.159.130.234", 50004, 51234, os.urandom(200))),
        "DNS replies": (20, lambda: udp("213.186.33.99", 53, 40000 + rng.randrange(999), b"\x12\x34" + b"\0" * 80)),
    }


def worker(fd, pool, seconds, wfd, offset):
    r = Runner(fd)
    run = r.run
    n = len(pool)
    i = offset
    sent = 0
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        for _ in range(256):
            run(pool[i % n])
            i += 1
        sent += 256
    os.write(wfd, struct.pack("Q", sent))
    os._exit(0)


def flood(r, prog_fd, stats_fd, names, title, pool, seconds, workers, rng):
    """Attack runs in forked workers (one syscall per packet, so every packet
    can have its own source); your own traffic is paced from this process."""
    flows = legit_flows(rng)
    due = {k: 0.0 for k in flows}
    sent = {k: 0 for k in flows}
    ok = {k: 0 for k in flows}
    before = read_stats(stats_fd, names)
    pipes = []
    if pool:
        for w in range(workers):
            rfd, wfd = os.pipe()
            if os.fork() == 0:
                os.close(rfd)
                worker(prog_fd, pool, seconds, wfd, w * (len(pool) // workers))
            os.close(wfd)
            pipes.append(rfd)
    start = time.perf_counter()
    run = r.run
    while True:
        now = time.perf_counter() - start
        if now >= seconds:
            break
        for name, (pps, gen) in flows.items():
            while due[name] <= now:
                due[name] += 1.0 / pps
                sent[name] += 1
                if run(gen()) == PASS:
                    ok[name] += 1
        time.sleep(0.0002)
    attack = 0
    for rfd in pipes:
        attack += struct.unpack("Q", os.read(rfd, 8))[0]
        os.close(rfd)
        os.wait()
    took = seconds
    after = read_stats(stats_fd, names)
    delta = {k: after[k] - before[k] for k in names}
    legit_pass = sum(ok.values())
    attack_pass = max(0, delta["pass"] - legit_pass)
    print(f"\n=== {title} ===")
    if pool:
        print(f"  attack rate       : {attack / took:>10,.0f} pkt/s for {took:.0f}s ({attack:,} packets)")
        print(f"  dropped in XDP    : {100 * (attack - attack_pass) / attack:>9.2f}%")
        print(f"  passed to nftables: {attack_pass / took:>10,.0f} pkt/s")
        drops = {k: v for k, v in delta.items() if k != "pass" and v}
        print("  drop reasons      : " + ", ".join(f"{k} {v:,}" for k, v in sorted(drops.items(), key=lambda x: -x[1])[:5]))
    print("  your own traffic at the same time:")
    for name in flows:
        pct = 100 * ok[name] / max(1, sent[name])
        mark = "ok" if pct >= 99 else ("degraded" if pct >= 50 else "BROKEN")
        print(f"    {name:38} {flows[name][0]:>5} pps  {pct:6.1f}% delivered  {mark}")


def main():
    which, obj = sys.argv[1], sys.argv[2]
    seconds = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0
    prof = PROFILES[which]
    fd, fds, insns = load(obj, prof)
    print(f"VERIFIER: accepted, {insns} instructions ({which})")
    r = Runner(fd)
    names = prof["stats"]
    rng = random.Random(11)
    POOL = 60000
    hi = lambda: rng.randrange(1024, 65536)
    null_pool = [tcp(rnd_src(rng), hi(), rng.randrange(1, 65536), 0, b"") for _ in range(POOL)]
    udp_pool = [udp(rnd_src(rng), hi(), hi(), os.urandom(rng.choice((32, 512, 1200)))) for _ in range(POOL)]
    one = rnd_src(rng)
    udp_one = [udp(one, hi(), 45000, os.urandom(512)) for _ in range(2000)]
    ts_pool = [udp(rnd_src(rng), hi(), 41641, os.urandom(rng.choice((32, 512, 1200)))) for _ in range(POOL)]
    syn_pool = [tcp(rnd_src(rng), hi(), hi(), 2) for _ in range(POOL)]
    ack_pool = [tcp(rnd_src(rng), hi(), hi(), 16) for _ in range(POOL)]

    workers = int(os.environ.get("WORKERS", "2"))
    print(f"harness: {workers} attack workers")
    S = fds["stats"]
    flood(r, fd, S, names, "BASELINE: no attack, just your traffic", [], 3.0, workers, rng)
    time.sleep(2.5)
    flood(r, fd, S, names, "TCP NULL flood (no flags), forged sources", null_pool, seconds, workers, rng)
    time.sleep(2.5)
    flood(r, fd, S, names, "UDP flood, random high ports, forged sources", udp_pool, seconds, workers, rng)
    time.sleep(2.5)
    flood(r, fd, S, names, "UDP flood from ONE source", udp_one, seconds, workers, rng)
    time.sleep(2.5)
    flood(r, fd, S, names, "UDP flood aimed at the Tailscale port 41641", ts_pool, seconds, workers, rng)
    time.sleep(2.5)
    flood(r, fd, S, names, "SYN flood, forged sources", syn_pool, seconds, workers, rng)
    time.sleep(2.5)
    flood(r, fd, S, names, "bare ACK flood, forged sources", ack_pool, seconds, workers, rng)


if __name__ == "__main__":
    main()
