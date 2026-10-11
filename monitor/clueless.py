#!/usr/bin/env python3
"""CLUELESS lab recon dashboard (v6).

Runs on a machine inside the lab (LAN + tailnet), not on the VPS.
Needs: python3 >= 3.8, ssh, ping, curl. No pip packages.
The firewall panels need /usr/local/bin/fortress-report on the VPS.
Try it with no network at all: --self-test
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import re
import select
import shlex
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import termios
import threading
import time
import tty
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

ASSETS_RAW = [
    "Home gateway|192.168.1.1|SENSITIVE|80,443",
    "Hypervisor|192.168.1.200|SENSITIVE|22,8006",
    "Lab box (LAN)|192.168.1.201|SENSITIVE|22",
    "Lab box (Tailnet)|100.64.0.20|SENSITIVE|22",
    # Ping only: TCP probes to the VPS's closed public ports would land this
    # machine's own address in the firewall's scanners4 set.
    "VPS|203.0.113.10|PUBLIC|",
    "VPS (Tailnet)|100.64.0.10|SENSITIVE|22",
]

VPS_HOST = os.environ.get("VPS_HOST", "100.64.0.10")
VPS_USER = os.environ.get("VPS_USER", "ubuntu")
VPS_REPORT_CMD = os.environ.get("VPS_REPORT_CMD", "sudo -n /usr/local/bin/fortress-report")
MONITOR_SSH_KEY = os.environ.get("MONITOR_SSH_KEY", "")
DEMO_MODE = os.environ.get("DEMO_MODE", "1") == "1"
WATERMARK = os.environ.get("WATERMARK", "1") == "1"
INTEL = os.environ.get("INTEL", "1") == "1"
REFRESH = float(os.environ.get("INTERVAL", "1.0"))
POLL_FIREWALL = 2.0
POLL_ASSETS = 3.0
PING_TIMEOUT = 1
TCP_TIMEOUT = 1.0
SSH_TIMEOUT = 6
HIST_MAX = 20
ANOM_MIN = 5
ANOM_SIGMA = 3.0
ANOM_FLOOR = 5.0
SPARK_N = 12
INTEL_TTL = 900
LOG_DIR = Path(os.environ.get("LOG_DIR", Path.home() / ".cluelabs"))
ATTACK_LOG = LOG_DIR / "attackers.jsonl"
# Total drops per second, both layers, that count as "probing" and "attack".
PROBE_RATE = 20.0
ATTACK_RATE = 1000.0
REPEAT_PACKETS = 4     # a source seen this often is a real sender, not a forged one
WHO_ROWS = int(os.environ.get("WHO_ROWS", "30"))  # real attacker sources listed in WHO before collapsing the rest

BOLD = "\x1b[1m"
RST = "\x1b[0m"
GRN = "\x1b[32m"
RED = "\x1b[31m"
YEL = "\x1b[33m"
MAG = "\x1b[35m"
GRY = "\x1b[90m"
CYN = "\x1b[36m"
WHT = "\x1b[97m"
WMC = "\x1b[2;35m"
SPARKS = "▁▂▃▄▅▆▇█"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
BANNER = [
    "   ____ _    _   _ _____ _     _____ ____ ____  ",
    "  / ___| |  | | | | ____| |   | ____/ ___/ ___| ",
    " | |   | |  | | | |  _| | |   |  _| \\___ \\___ \\ ",
    " | |___| |__| |_| | |___| |___| |___ ___) |__) |",
    "  \\____|_____\\___/|_____|_____|_____|____/____/ ",
]
WM = [
    "    ▒▒▒▒▒▒▒    ",
    "  ▒▒▒▒▒▒▒▒▒▒▒  ",
    " ▒▒▒     ▒▒▒▒  ",
    "          ▒▒▒  ",
    "         ▒▒▒   ",
    "        ▒▒▒    ",
    "      ▒▒▒▒     ",
    "      ▒▒▒      ",
    "      ▒▒▒      ",
    "               ",
    "      ▒▒▒      ",
    "      ▒▒▒      ",
]
WM_W = 15
WM_ROW = 2


XDP_FRIENDLY = {
    "trunc": "truncated headers",
    "bogon": "forged private source",
    "frag": "fragments",
    "other-proto": "other protocols (GRE...)",
    "badflags": "malformed TCP flags",
    "bait-tcp": "TCP to bait ports",
    "ssh": "SSH probes",
    "mc": "Minecraft probes",
    "syn-rate": "inbound SYN flood",
    "bait-udp": "UDP to bait ports",
    "udp-rate": "UDP over per-source limit",
    "icmp-rate": "ping flood",
    "ipv6-tcp": "IPv6 TCP attempts",
    "ack-rate": "empty-ACK flood",
    "priv": "TCP to privileged ports",
    "global": "over the total ceiling",
    "udp-valve": "unsolicited UDP flood",
}
XDP_PASS = ("pass",)

FRIENDLY = {
    "wan-ack-flood": "bare ACK, no connection",
    "wan-rst-flood": "RST, no connection",
    "wan-fin-flood": "FIN, no connection",
    "wan-invalid": "invalid state",
    "wan-nonsyn-new": "non-SYN opening packet",
    "wan-udp-unsolicited": "unsolicited UDP",
    "wan-udp-flood": "UDP over per-source limit",
    "wan-ssh-closed": "SSH probes",
    "wan-bait-tcp": "TCP to bait ports",
    "wan-bait-udp": "UDP to bait ports",
    "wan-other-proto": "other protocols",
    "wan-bad-mss": "SYN with tiny MSS",
    "wan-closed-port": "TCP to closed ports",
    "wan-closed-port6": "IPv6 TCP attempts",
    "wan-syn-flood": "SYN flood over limit",
    "wan-bogon4": "spoofed / bogon source",
    "wan-bogon6": "spoofed IPv6 source",
    "wan-badflags": "malformed TCP flags",
    "wan-blocklist": "manually blocked",
    "input-fallthrough": "unsolicited, no rule",
    "input-drop": "invalid / rate-limited",
    "forward-drop": "forwarding refused",
    "mc-ingress-drop": "MC SYN not allowlisted",
    "mc-unauthorized": "MC unauthorized (input)",
    "mc-syn-flood": "MC SYN over limit",
    "mc-connlimit": "MC connection cap",
    "mc-query-blocked": "MC query (UDP) blocked",
    "mc-rcon-blocked": "MC RCON blocked",
    "wan-icmp-echo": "ICMP echo allowed",
    "wan-wireguard": "WireGuard accepted",
    "wan-tailscale": "Tailscale accepted",
    "service-accept": "public service accepted",
    "wg-ssh": "SSH over WireGuard",
    "mc-accept": "Minecraft accepted",
    "mc-proxy-accept": "MC proxy accepted",
    "mc-admin-tunnel": "MC admin over WireGuard",
}
BLOCKED = {
    "wan-closed-port", "wan-closed-port6", "wan-syn-flood", "wan-bogon4",
    "wan-bogon6", "wan-badflags", "wan-blocklist", "input-fallthrough",
    "mc-ingress-drop", "mc-unauthorized", "mc-syn-flood", "mc-connlimit",
    "mc-query-blocked", "mc-rcon-blocked",
}


def clean(value, limit=64):
    """Remote text (rDNS, WHOIS, log fields) must never reach the terminal raw."""
    return "".join(ch for ch in str(value) if ch.isprintable())[:limit]


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def pad(text: str, width: int) -> str:
    gap = width - visible_len(text)
    return text + " " * gap if gap > 0 else text


def clip(text: str, width: int) -> str:
    if visible_len(text) <= width:
        return text
    out, shown, index = [], 0, 0
    while index < len(text) and shown < width:
        if text[index] == "\x1b":
            end = text.find("m", index)
            if end == -1:
                break
            out.append(text[index:end + 1])
            index = end + 1
            continue
        out.append(text[index])
        shown += 1
        index += 1
    return "".join(out) + RST


def human(value: float) -> str:
    for unit in ("", "K", "M", "G", "T"):
        if abs(value) < 1000:
            return f"{value:.0f}{unit}" if unit == "" else f"{value:.1f}{unit}"
        value /= 1000
    return f"{value:.1f}P"


def bits(per_second: float) -> str:
    if per_second >= 1e9:
        return f"{per_second / 1e9:.2f} Gbit/s"
    if per_second >= 1e6:
        return f"{per_second / 1e6:.1f} Mbit/s"
    return f"{per_second / 1e3:.0f} kbit/s"


def ago(seconds) -> str:
    if seconds is None:
        return "-"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


@dataclass
class AssetState:
    label: str
    target: str
    visibility: str
    ports: list
    reachable: str = "WAIT"
    latency: float | None = None
    port_results: list = field(default_factory=list)
    history: deque = field(default_factory=lambda: deque(maxlen=HIST_MAX))
    anomaly: bool = False


@dataclass
class RuleRate:
    packets: int = 0
    rate: float = 0.0
    peak: float = 0.0
    nbytes: int = 0
    avg: int = 0          # average packet size in bytes (bytes / packets)


class Dashboard:
    def __init__(self, self_test: bool = False):
        self.self_test = self_test
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.paused = False
        self.demo = DEMO_MODE
        self.tick = 0
        self.assets = []
        for row in ASSETS_RAW:
            label, target, visibility, ports = [part.strip() for part in row.split("|")]
            self.assets.append(AssetState(
                label=label, target=target, visibility=visibility,
                ports=[int(p) for p in ports.split(",") if p],
            ))
        self.report = None
        self.report_error = None
        self.report_age = None
        self.rates = {}
        self.verdicts = {}
        self._prev_counters = {}
        self._prev_counter_time = None
        self.xrates = {}
        self._prev_extra = None
        self.net = {}
        self.cpu_net = None
        self.peak_drop = 0.0
        self.intel = {}
        self._intel_lock = threading.Lock()
        self.notice = ""
        self.notice_until = 0.0
        LOG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        ATTACK_LOG.touch(mode=0o600, exist_ok=True)
        self._logged_totals = {}
        self.all_time_packets = 0
        self.all_time_sources = set()
        self._load_history()

    def _load_history(self):
        """Read the log once; the footer and the de-dup both work from memory after that."""
        try:
            with ATTACK_LOG.open() as handle:
                for line in handle:
                    try:
                        row = json.loads(line)
                        ip = row.get("src_ip")
                    except (AttributeError, ValueError):
                        continue
                    if not ip:
                        continue
                    self.all_time_packets += int(row.get("new_packets") or 0)
                    self.all_time_sources.add(ip)
                    self._logged_totals[f"{row.get('category')}|{ip}"] = int(row.get("packets") or 0)
        except (OSError, TypeError, ValueError):
            pass

    def ssh_base(self, user, host, control):
        args = ["ssh"]
        if MONITOR_SSH_KEY:
            args += ["-i", MONITOR_SSH_KEY, "-o", "IdentitiesOnly=yes"]
        args += [
            "-o", f"ConnectTimeout={SSH_TIMEOUT}", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "ControlMaster=auto",
            "-o", f"ControlPath={control}", "-o", "ControlPersist=60",
            f"{user}@{host}",
        ]
        return args

    def poll_firewall(self):
        control = str(LOG_DIR / "vps.sock")
        while not self.stop.is_set():
            if self.paused:
                self.stop.wait(POLL_FIREWALL)
                continue
            if self.self_test:
                report, error = synthetic_report(), None
            else:
                report, error = self._fetch_report(control)
            with self.lock:
                if report is not None:
                    try:
                        self._update_rates(report)
                        self._update_extra(report)
                        if not self.self_test:
                            self._persist(report)
                        self.report = report
                        self.report_error = None
                        self.report_age = time.time()
                    except (AttributeError, KeyError, TypeError, ValueError) as exc:
                        self.report_error = f"vps: malformed report ({type(exc).__name__})"
                else:
                    self.report_error = error
            self.stop.wait(POLL_FIREWALL)

    def _fetch_report(self, control):
        if VPS_HOST == "local":
            cmd = shlex.split(VPS_REPORT_CMD)
        else:
            cmd = self.ssh_base(VPS_USER, VPS_HOST, control) + [VPS_REPORT_CMD]
        try:
            done = subprocess.run(cmd, capture_output=True, text=True, timeout=SSH_TIMEOUT + 6)
        except subprocess.TimeoutExpired:
            return None, "vps: report timed out"
        except OSError as exc:
            return None, f"vps: {exc}"
        if done.returncode != 0:
            detail = done.stderr.strip().splitlines()
            return None, f"vps: {clean(detail[-1], 60) if detail else 'ssh failed'}"
        try:
            report = json.loads(done.stdout)
        except json.JSONDecodeError:
            return None, "vps: report was not valid JSON"
        if not isinstance(report, dict):
            return None, "vps: report was not a JSON object"
        return report, None

    def _update_rates(self, report):
        now = time.time()
        counters = {}
        cbytes = {}
        for row in report.get("counters") or []:
            # Several rules can share one name (wan-badflags has four); add them up.
            rule = clean(row.get("rule") or "unnamed", 32)
            counters[rule] = counters.get(rule, 0) + int(row.get("packets") or 0)
            cbytes[rule] = cbytes.get(rule, 0) + int(row.get("bytes") or 0)
            if row.get("verdict") in ("drop", "accept"):
                self.verdicts[rule] = row["verdict"]
        elapsed = (now - self._prev_counter_time) if self._prev_counter_time else None
        for rule, packets in counters.items():
            entry = self.rates.setdefault(rule, RuleRate())
            previous = self._prev_counters.get(rule)
            entry.packets = packets
            entry.nbytes = cbytes.get(rule, 0)
            entry.avg = entry.nbytes // packets if packets else 0
            if previous is not None and elapsed and elapsed > 0:
                delta = packets - previous
                entry.rate = max(0.0, delta / elapsed) if delta >= 0 else 0.0
                entry.peak = max(entry.peak, entry.rate)
        self._prev_counters = counters
        self._prev_counter_time = now

    def _update_extra(self, report):
        """Rates for the XDP counters, the WAN interface and network CPU time."""
        now = time.time()
        counters = {clean(k, 24): int(v or 0) for k, v in ((report.get("xdp") or {}).get("counters") or {}).items()}
        net = report.get("net") or {}
        cpu = report.get("cpu") or {}
        previous = self._prev_extra
        self._prev_extra = {"time": now, "xdp": counters, "net": net, "cpu": cpu}
        for name, packets in counters.items():
            self.xrates.setdefault(name, RuleRate()).packets = packets
        if not previous:
            return
        elapsed = now - previous["time"]
        if elapsed <= 0:
            return
        for name, packets in counters.items():
            entry = self.xrates[name]
            # Counters restart from zero when the program is re-attached.
            delta = packets - previous["xdp"].get(name, packets)
            entry.rate = max(0.0, delta / elapsed)
            entry.peak = max(entry.peak, entry.rate)

        def per_second(key):
            delta = int(net.get(key) or 0) - int(previous["net"].get(key) or 0)
            return max(0.0, delta / elapsed)

        # An older fortress-report sends no interface counters; show nothing, not zero.
        self.net = {
            "in_bps": per_second("rx_bytes") * 8, "out_bps": per_second("tx_bytes") * 8,
            "in_pps": per_second("rx_packets"), "out_pps": per_second("tx_packets"),
        } if net else {}
        total = int(cpu.get("total") or 0) - int(previous["cpu"].get("total") or 0)
        soft = int(cpu.get("softirq") or 0) - int(previous["cpu"].get("softirq") or 0)
        self.cpu_net = max(0.0, soft / total * 100) if total > 0 else None

    def drop_rows(self):
        """Every rule that is dropping, both layers: (layer, name, label, RuleRate)."""
        rows = []
        for name, entry in self.xrates.items():
            if name not in XDP_PASS and entry.packets:
                rows.append(("XDP", name, XDP_FRIENDLY.get(name, name), entry))
        for name, entry in self.rates.items():
            is_drop = self.verdicts[name] == "drop" if name in self.verdicts else name in BLOCKED
            if is_drop and entry.packets:
                rows.append(("nft", name, FRIENDLY.get(name, name), entry))
        rows.sort(key=lambda row: (row[3].rate, row[3].packets), reverse=True)
        return rows

    def _persist(self, report):
        rows = []
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for set_name, entries in report.get("observations", {}).items():
            for entry in entries:
                ip = valid_ip(entry.get("value"))
                packets = int(entry.get("packets") or 0)
                if not ip:
                    continue
                key = f"{set_name}|{ip}"
                previous = self._logged_totals.get(key, 0)
                if packets == previous:
                    continue
                # A lower count means the set entry expired and came back.
                gained = packets - previous if packets > previous else packets
                self._logged_totals[key] = packets
                self.all_time_packets += gained
                self.all_time_sources.add(ip)
                rows.append({
                    "ts": stamp, "source": "VPS", "category": clean(set_name, 24),
                    "src_ip": ip, "packets": packets, "new_packets": gained,
                })
        if not rows:
            return
        try:
            with ATTACK_LOG.open("a") as handle:
                for row in rows:
                    handle.write(json.dumps(row) + "\n")
        except OSError:
            pass

    def poll_assets(self):
        pool = ThreadPoolExecutor(max_workers=8)
        while not self.stop.is_set():
            if self.paused:
                self.stop.wait(POLL_ASSETS)
                continue
            if self.self_test:
                for asset in self.assets:
                    synthetic_asset(asset)
                self.stop.wait(POLL_ASSETS)
                continue
            list(pool.map(self._probe_asset, self.assets))
            self.stop.wait(POLL_ASSETS)

    def _probe_asset(self, asset):
        latency = ping_once(asset.target)
        results = [(port, tcp_open(asset.target, port)) for port in asset.ports]
        with self.lock:
            asset.port_results = results
            if latency is None:
                asset.reachable = "DOWN"
                asset.latency = None
                asset.anomaly = False
                return
            asset.reachable = "UP"
            asset.latency = latency
            asset.anomaly = self._judge(asset, latency)
            if not asset.anomaly:
                asset.history.append(latency)

    @staticmethod
    def _judge(asset, latency):
        if len(asset.history) < ANOM_MIN:
            return False
        mean = statistics.fmean(asset.history)
        spread = statistics.pstdev(asset.history)
        return latency > mean + ANOM_SIGMA * spread and latency > mean + ANOM_FLOOR

    def enrich(self, ip):
        try:
            if not ipaddress.ip_address(ip).is_global:
                return
        except ValueError:
            return
        with self._intel_lock:
            entry = self.intel.get(ip)
            if entry and time.time() - entry.get("ts", 0) < INTEL_TTL:
                return
            if entry and entry.get("running"):
                return
            self.intel[ip] = {"running": True, "ts": time.time()}

        def worker():
            data = {"running": False, "ts": time.time()}
            try:
                data["rdns"] = clean(socket.gethostbyaddr(ip)[0])
            except (OSError, socket.herror):
                data["rdns"] = None
            try:
                done = subprocess.run(
                    ["curl", "-s", "--max-time", "4", f"https://ipinfo.io/{ip}/json"],
                    capture_output=True, text=True, timeout=6,
                )
                info = json.loads(done.stdout)
                for key in ("country", "org", "city"):
                    if info.get(key):
                        data[key] = clean(info[key])
            except (AttributeError, OSError, ValueError, subprocess.SubprocessError):
                pass
            with self._intel_lock:
                self.intel[ip] = data

        threading.Thread(target=worker, daemon=True).start()

    def attackers(self):
        if not self.report:
            return []
        merged = {}
        labels = {"scanners4": "scan", "flooders4": "flood", "spoofed4": "spoof", "udpflood4": "udp"}
        for set_name, entries in self.report.get("observations", {}).items():
            for entry in entries:
                ip = valid_ip(entry.get("value"))
                if not ip:
                    continue
                row = merged.setdefault(ip, {"ip": ip, "packets": 0, "bytes": 0, "kinds": set(), "age": None})
                row["packets"] += int(entry.get("packets") or 0)
                row["bytes"] += int(entry.get("bytes") or 0)
                row["kinds"].add(labels.get(set_name, clean(set_name, 12)))
                age = entry.get("last_seen_seconds_ago")
                if isinstance(age, (int, float)):
                    row["age"] = age if row["age"] is None else min(row["age"], age)
        return sorted(merged.values(), key=lambda row: row["packets"], reverse=True)

    @staticmethod
    def own_addresses(report):
        """Public addresses of our own WireGuard peers: never suggest blocking these."""
        own = set()
        for peer in report.get("wireguard") or []:
            if isinstance(peer, dict):
                host = valid_ip(str(peer.get("endpoint") or "").rsplit(":", 1)[0].strip("[]"))
                if host:
                    own.add(host)
        return own

    def build(self, width):
        """One screen, read top to bottom: up, under attack, what kind, who, can I get in."""
        inner = max(72, min(width - 2, 108))
        lines = [f"{MAG}{BOLD}{row}{RST}" for row in BANNER]
        lines.extend(self.panel_assets(inner))
        for panel in (self.panel_verdict, self.panel_kind, self.panel_who,
                      self.panel_access, self.panel_feed, self.panel_footer):
            block = panel(inner)
            if block:
                lines.append("")
                lines.extend(block)
        return lines

    def _box_top(self, inner, title):
        return [
            f"{MAG}╔{'═' * inner}╗{RST}",
            f"{MAG}║{RST}{BOLD}{pad(title, inner)}{RST}{MAG}║{RST}",
        ]

    def panel_assets(self, inner):
        mode = "[addresses hidden] " if self.demo else ""
        title = f"  AM I UP   {mode}{time.strftime('%H:%M:%S')}   refresh #{self.tick}"
        lines = self._box_top(inner, title)
        host_w, addr_w, ping_w, trend_w = 20, 16, 10, SPARK_N
        fixed = 1 + host_w + 3 + addr_w + 3 + ping_w + 3 + 3 + trend_w + 1
        ports_w = max(12, inner - fixed)

        def row(cells):
            return " " + " │ ".join(cells) + " "

        header = row([
            f"{'HOST':<{host_w}}", f"{'ADDRESS':<{addr_w}}", f"{'PING':<{ping_w}}",
            f"{'PORTS':<{ports_w}}", f"{'TREND':<{trend_w}}",
        ])
        lines.append(f"{MAG}╠{'═' * inner}╣{RST}")
        lines.append(f"{MAG}║{RST}{GRY}{pad(clip(header, inner), inner)}{RST}{MAG}║{RST}")
        lines.append(f"{MAG}╟{'─' * inner}╢{RST}")
        up = anomalies = hidden = 0
        with self.lock:
            for asset in self.assets:
                # Home hosts are out of reach away from home; a wall of red says nothing.
                if asset.reachable == "DOWN" and not asset.label.startswith("OVH"):
                    hidden += 1
                    continue
                address = "xxx.xxx.xxx.xxx" if (self.demo and asset.visibility == "SENSITIVE") else asset.target
                if asset.reachable == "UP":
                    up += 1
                    if asset.anomaly:
                        anomalies += 1
                        ping_cell = f"{YEL}! {asset.latency:.1f}ms{RST}"
                        ping_raw = f"! {asset.latency:.1f}ms"
                    else:
                        ping_cell = f"{GRN}+ {asset.latency:.1f}ms{RST}"
                        ping_raw = f"+ {asset.latency:.1f}ms"
                elif asset.reachable == "WAIT":
                    ping_cell, ping_raw = f"{GRY}probing{RST}", "probing"
                else:
                    ping_cell, ping_raw = f"{RED}- down{RST}", "- down"
                if asset.port_results:
                    bits = []
                    closed = False
                    for port, is_open in asset.port_results:
                        bits.append(f"{port}{'+' if is_open else '-'}")
                        closed = closed or not is_open
                    ports_raw = " ".join(bits)
                    ports_cell = f"{YEL if closed else GRN}{ports_raw}{RST}"
                else:
                    ports_raw, ports_cell = "n/a", f"{GRY}n/a{RST}"
                spark = sparkline(asset.history)
                line = row([
                    f"{asset.label[:host_w]:<{host_w}}",
                    f"{address[:addr_w]:<{addr_w}}",
                    ping_cell + " " * max(0, ping_w - len(ping_raw)),
                    ports_cell + " " * max(0, ports_w - len(ports_raw)),
                    f"{GRY}{spark}{RST}" + " " * max(0, trend_w - len(spark)),
                ])
                lines.append(f"{MAG}║{RST}{pad(clip(line, inner), inner)}{MAG}║{RST}")
        total = len(self.assets)
        colour = YEL if anomalies else GRY
        status = f"  {up}/{total} up   " + (
            f"! {anomalies} latency anomaly(s)" if anomalies else "baseline normal"
        )
        if hidden:
            status += f"   · {hidden} home host(s) out of reach, not shown"
        lines.append(f"{MAG}╠{'═' * inner}╣{RST}")
        lines.append(f"{MAG}║{RST}{colour}{pad(clip(status, inner), inner)}{RST}{MAG}║{RST}")
        lines.append(f"{MAG}╚{'═' * inner}╝{RST}")
        return lines

    def panel_verdict(self, inner):
        with self.lock:
            report = self.report
            error = self.report_error
            age = self.report_age
            rows = self.drop_rows()
            net = dict(self.net)
            cpu_net = self.cpu_net
        title = f"{MAG}▌{RST} {BOLD}UNDER ATTACK?{RST}  "
        if report is None:
            where = "the VPS" if self.demo else f"{VPS_USER}@{VPS_HOST}"
            shown = "vps unreachable" if (self.demo and error) else error
            return [
                f"{title}{YEL}unknown: {shown or 'connecting...'}{RST}",
                f"  {GRY}expects fortress-report on {where}{RST}",
            ]
        if not report.get("firewall", {}).get("loaded"):
            return [
                f"{title}{RED}FIREWALL NOT LOADED{RST}",
                f"  {RED}{clean(report.get('error', 'the ovh_fortress table is absent'), 80)}{RST}",
            ]
        by_xdp = sum(entry.rate for layer, _, _, entry in rows if layer == "XDP")
        by_nft = sum(entry.rate for layer, _, _, entry in rows if layer == "nft")
        total = by_xdp + by_nft
        with self.lock:
            self.peak_drop = max(self.peak_drop, total)
            peak = self.peak_drop
        if total >= ATTACK_RATE:
            word, colour = "YES", RED
        elif total >= PROBE_RATE:
            word, colour = "PROBING", YEL
        else:
            word, colour = "NO", GRN
        lag = time.time() - age if age else 0.0
        stale = ""
        if lag > POLL_FIREWALL * 5:
            detail = "" if self.demo or not error else f" ({error})"
            stale = f"  {RED}STALE: last report {int(lag)}s ago{detail}{RST}"
        lines = [
            f"{title}{colour}{BOLD}{word}{RST}{colour} · {total:,.0f} pkt/s dropped{RST}  "
            f"{GRY}(XDP {by_xdp:,.0f} | nftables {by_nft:,.0f} | peak {peak:,.0f}){RST}{stale}"
        ]
        conntrack = report.get("conntrack") or {}
        used, cap = int(conntrack.get("count") or 0), int(conntrack.get("max") or 1)
        pressure = used / cap * 100
        ct_colour = RED if pressure > 80 else (YEL if pressure > 50 else GRN)
        load = " ".join(clean(value, 6) for value in (report.get("loadavg") or [])[:3]) or "-"
        if net:
            traffic = (f"in {bits(net['in_bps'])} ({net['in_pps']:,.0f} pkt/s)   "
                       f"out {bits(net['out_bps'])}")
        else:
            traffic = f"{GRY}traffic: no data yet{RST}"
        if cpu_net is None:
            cpu_text = f"{GRY}CPU on packets -{RST}"
        else:
            cpu_colour = RED if cpu_net > 60 else (YEL if cpu_net > 25 else GRN)
            cpu_text = f"{GRY}CPU on packets{RST} {cpu_colour}{cpu_net:.0f}%{RST}"
        lines.append(
            f"  {traffic}   {cpu_text}   {GRY}conntrack{RST} {ct_colour}{pressure:.1f}%{RST}"
            f"   {GRY}load {load}{RST}"
        )
        return [clip(line, inner) for line in lines]

    def panel_kind(self, inner):
        with self.lock:
            report = self.report
            rows = self.drop_rows()
            xrates = dict(self.xrates)
        if not report or not report.get("firewall", {}).get("loaded"):
            return []
        lines = [f"{MAG}▌{RST} {BOLD}WHAT KIND{RST}  {GRY}each attack · avg size · dropped vs handed to nftables{RST}"]
        if not rows:
            lines.append(f"  {GRY}nothing dropped since the filters were loaded{RST}")
        else:
            top_rate = max(entry.rate for _, _, _, entry in rows) or 1.0
            for layer, _, label, entry in rows[:9]:
                layer_colour = CYN if layer == "XDP" else MAG
                filled = int(min(1.0, entry.rate / top_rate) * 14) if entry.rate else 0
                bar = "█" * filled + "·" * (14 - filled)
                rate_text = f"{RED}{entry.rate:7,.0f}/s{RST}" if entry.rate >= 0.5 else f"{GRY}     idle{RST}"
                size = f"{entry.avg:>4}B" if entry.avg else "   ·"
                lines.append(
                    f"  {GRN}✓{RST} {layer_colour}{layer:<3}{RST} {label:<23} {GRY}{bar}{RST} {rate_text}"
                    f"  {GRY}sz{RST} {size}  {GRY}tot{RST} {human(entry.packets):>6}"
                )
            if len(rows) > 9:
                lines.append(f"  {GRY}+ {len(rows) - 9} quieter rule(s){RST}")
        # mitigated (everything above is a drop) vs what the filters let reach the host
        mit_rate = sum(entry.rate for _, _, _, entry in rows)
        passed = xrates.get("pass")
        pass_rate = passed.rate if passed else 0.0
        through_colour = RED if pass_rate >= ATTACK_RATE else GRN
        lines.append(
            f"  {GRY}──{RST} {GRN}MITIGATED {mit_rate:>8,.0f}/s{RST}   "
            f"{through_colour}PASSED XDP {pass_rate:>7,.0f}/s{RST} {GRY}(nftables filters these next){RST}"
        )
        return [clip(line, inner) for line in lines]

    def panel_who(self, inner):
        with self.lock:
            report = self.report
        if not report:
            return []
        assessment = report.get("assessment", {})
        ranked = self.attackers()
        own = self.own_addresses(report)
        verdict = clean(assessment.get("verdict", "unknown"), 24)
        verdict_colour = {
            "quiet": GRN, "background noise": GRY,
            "persistent scanning": YEL, "likely spoofed flood": RED,
        }.get(verdict, GRY)
        lines = [f"{MAG}▌{RST} {BOLD}WHO{RST}  {verdict_colour}{verdict}{RST}"]
        seen = report.get("ports") or {}
        hits = [(clean(row.get("port"), 12), int(row.get("hits") or 0))
                for row in seen.get("ports") or [] if isinstance(row, dict)]
        total_hits = sum(count for _, count in hits)
        if total_hits:
            cells = "  ".join(f"{WHT}{port}{RST} {count * 100 // total_hits}%" for port, count in hits[:7])
            lines.append(f"  {GRY}ports hit (sampled, last {int(seen.get('window') or 0)}s){RST}  {cells}")
        else:
            lines.append(f"  {GRY}ports hit: no sampled drops in the last {int(seen.get('window') or 120)}s{RST}")
        spread = {}
        for row in seen.get("pairs") or []:
            if isinstance(row, dict) and valid_ip(row.get("src")):
                spread.setdefault(row["src"], set()).add(clean(row.get("port"), 12))
        # A source seen repeatedly really is sending. One packet each is what forged
        # addresses look like, and looking those up or blocking them is pointless.
        real = [row for row in ranked if row["packets"] >= REPEAT_PACKETS and "spoof" not in row["kinds"]]
        one_shot = len(ranked) - len(real)
        if real:
            lines.append(
                f"  {GRY}{'REAL SOURCE':<16} {'PKTS':>8} {'SIZE':>6} {'SEEN':>6} {'TYPE':<9} {'PORTS':<14} "
                f"{'ORIGIN':<18} RDNS{RST}  {GRN}· all dropped{RST}"
            )
        for row in real[:WHO_ROWS]:
            ip = row["ip"]
            if INTEL:
                self.enrich(ip)
            with self._intel_lock:
                info = dict(self.intel.get(ip, {}))
            kinds = ",".join(sorted(row["kinds"]))
            kind_colour = RED if "flood" in row["kinds"] else (YEL if "scan" in row["kinds"] else GRY)
            if ip in own:
                kinds, kind_colour = "you", CYN
            origin = "looking up" if info.get("running") else "-"
            if info.get("country") or info.get("org"):
                org = (info.get("org") or "").split(" ", 1)
                name = org[1][:12] if len(org) > 1 else ""
                origin = f"{info.get('country') or '??'} {org[0] if org else ''} {name}".strip()
            rdns = info.get("rdns") or "-"
            if self.demo:
                rdns = "(hidden)"
            targets = sorted(spread.get(ip, ()))
            ports = ",".join(targets[:2]) + (f" +{len(targets) - 2}" if len(targets) > 2 else "") if targets else "-"
            weight = WHT if row["packets"] >= 100 else ""
            avg = row["bytes"] // row["packets"] if row["packets"] else 0
            size = f"{avg}B" if avg else "·"
            lines.append(
                f"  {weight}{ip:<16}{RST} {row['packets']:>8} {size:>6} {ago(row['age']):>6} "
                f"{kind_colour}{kinds[:9]:<9}{RST} {ports[:14]:<14} "
                f"{GRY}{origin[:18]:<18}{RST} {GRY}{rdns[:20]}{RST}"
            )
        if len(real) > WHO_ROWS:
            lines.append(f"  {GRY}+ {len(real) - WHO_ROWS} more repeat source(s){RST}")
        if one_shot:
            colour = YEL if verdict == "likely spoofed flood" else GRY
            lines.append(
                f"  {colour}{one_shot:,} other address(es) seen only a few times: probably forged, "
                f"not listed, not worth blocking{RST}"
            )
        if not ranked:
            lines.append(f"  {GRY}no sources recorded right now{RST}")
        if real and real[0]["packets"] >= 50 and real[0]["ip"] not in own:
            lines.append(
                f"  {GRY}to block the top source:{RST} "
                f"{CYN}sudo nft add element inet ovh_fortress blocklist4 {{ {real[0]['ip']} }}{RST}"
            )
        return [clip(line, inner) for line in lines]

    def panel_access(self, inner):
        with self.lock:
            report = self.report
            error = self.report_error
            age = self.report_age
            rates = dict(self.rates)
        lines = [f"{MAG}▌{RST} {BOLD}CAN I GET IN{RST}"]
        where = "the tailnet" if self.demo else VPS_HOST
        if age is None:
            lines.append(f"  {RED}Tailscale path: no report yet{RST}  {GRY}{clean(error or '', 60)}{RST}")
            return [clip(line, inner) for line in lines]
        lag = time.time() - age
        if lag <= POLL_FIREWALL * 5:
            lines.append(f"  {GRN}Tailscale path works{RST}  {GRY}last report {int(lag)}s ago over {where}{RST}")
        else:
            lines.append(f"  {RED}Tailscale path FAILING{RST}  {GRY}last report {int(lag)}s ago{RST}")
        peers = [peer for peer in (report.get("wireguard") or []) if isinstance(peer, dict)]
        for peer in peers[:3]:
            handshake = peer.get("handshake_age")
            name = "peer" if self.demo else clean(peer.get("allowed_ips") or "peer", 20)
            if handshake is None:
                lines.append(f"  {YEL}WireGuard {name}: never connected{RST}  {GRY}this fallback is unproven{RST}")
            elif handshake < 300:
                lines.append(f"  {GRN}WireGuard {name}: handshake {ago(handshake)} ago{RST}")
            else:
                lines.append(f"  {YEL}WireGuard {name}: last handshake {ago(handshake)} ago{RST}")
        if not peers:
            lines.append(f"  {GRY}WireGuard: no peers configured{RST}")
        xdp = report.get("xdp")
        if isinstance(xdp, dict):
            if not xdp.get("loaded"):
                lines.append(f"  {RED}XDP filter NOT attached{RST}  {GRY}nftables alone is filtering{RST}")
            elif xdp.get("rollback_armed"):
                lines.append(
                    f"  {YEL}XDP attached ({clean(xdp.get('mode'), 8)}), rollback timer ARMED{RST}  "
                    f"{GRY}run load.sh confirm to keep it{RST}"
                )
            else:
                lines.append(f"  {GRN}XDP attached ({clean(xdp.get('mode'), 8)}){RST}")
        else:
            lines.append(f"  {GRY}XDP: the VPS runs an old fortress-report that does not say{RST}")
        tunnels = []
        for rule, label in (("wan-tailscale", "Tailscale"), ("wan-wireguard", "WireGuard")):
            entry = rates.get(rule)
            if entry:
                tunnels.append(f"{label} {entry.rate:.0f} new/s")
        if tunnels:
            lines.append(f"  {GRY}tunnel connections accepted: {' · '.join(tunnels)}{RST}")
        return [clip(line, inner) for line in lines]

    def panel_feed(self, inner):
        with self.lock:
            report = self.report
        events = [item for item in ((report or {}).get("recent") or []) if isinstance(item, dict)]
        lines = [f"{MAG}▌{RST} {BOLD}FIREWALL LOG{RST} {GRY}(a few sampled packets per second){RST}"]
        if not events:
            lines.append(f"  {GRY}no sampled packets yet; the counters above still count every packet{RST}")
            return [clip(line, inner) for line in lines]
        for item in events[-8:]:
            kind = clean(item.get("kind") or "drop", 6).lower()
            colour = RED if kind in {"scan", "drop", "flood"} else YEL
            src = clean(item.get("src") or "?", 40)
            port = clean(item.get("dst_port") or "-", 5)
            proto = clean(item.get("proto") or "-", 8)
            stamp = clean(str(item.get("ts") or "")[-8:], 8)
            lines.append(
                f"  {stamp} {colour}{kind:<6}{RST} {src:<16} {GRY}→{RST} {proto}/{port}"
            )
        return [clip(line, inner) for line in lines]

    def panel_footer(self, inner):
        with self.lock:
            total_events = self.all_time_packets
            unique = len(self.all_time_sources)
        log_shown = str(ATTACK_LOG).replace(str(Path.home()), "~", 1)
        lines = [
            f"{CYN}▌{RST} {BOLD}ALL-TIME{RST}  {GRY}{unique} unique source(s) · "
            f"{human(total_events)} blocked packet(s) · {log_shown}{RST}"
        ]
        state = f"{YEL}PAUSED{RST}" if self.paused else f"{GRY}live{RST}"
        if self.notice and time.time() < self.notice_until:
            state = f"{CYN}{self.notice}{RST}"
        lines.append(
            f"{GRY}  q quit · p pause · d hide addresses · r reset peaks · e look up sources{RST}   {state}"
        )
        return [clip(line, inner) for line in lines]

    def handle_key(self, key):
        if key in ("q", "\x03"):
            self.stop.set()
        elif key == "p":
            self.paused = not self.paused
            self.flash("paused" if self.paused else "resumed")
        elif key == "d":
            self.demo = not self.demo
            self.flash("addresses hidden" if self.demo else "addresses shown")
        elif key == "r":
            with self.lock:
                for entry in list(self.rates.values()) + list(self.xrates.values()):
                    entry.peak = 0.0
                self.peak_drop = 0.0
            self.flash("peak rates reset")
        elif key == "e":
            for row in self.attackers()[:12]:
                self.enrich(row["ip"])
            self.flash("looking up visible sources")

    def flash(self, text):
        self.notice = text
        self.notice_until = time.time() + 2.5

    def run(self):
        threading.Thread(target=self.poll_firewall, daemon=True).start()
        threading.Thread(target=self.poll_assets, daemon=True).start()
        previous = []
        last_size = None
        sys.stdout.write("\x1b[?1049h\x1b[?25l")
        try:
            while not self.stop.is_set():
                self.tick += 1
                size = shutil.get_terminal_size((100, 40))
                if size != last_size:
                    # A resize invalidates the line-diff; start from a clean screen.
                    sys.stdout.write("\x1b[2J")
                    previous, last_size = [], size
                frame = self.build(size.columns)
                self.paint(frame, previous, size)
                previous = frame
                self.wait_for_key(REFRESH)
        finally:
            sys.stdout.write("\x1b[?25h\x1b[?1049l")
            sys.stdout.flush()

    def paint(self, frame, previous, size):
        out = []
        for index in range(max(len(frame), len(previous))):
            new = frame[index] if index < len(frame) else ""
            old = previous[index] if index < len(previous) else None
            if new == old or index >= size.lines:
                continue
            out.append(f"\x1b[{index + 1};1H{clip(new, size.columns)}\x1b[K")
        if WATERMARK and size.columns >= 118:
            column = min(size.columns - WM_W, 112)
            for offset, row in enumerate(WM):
                line = WM_ROW + offset
                if line < size.lines:
                    out.append(f"\x1b[{line + 1};{column}H{WMC}{row}{RST}")
        if out:
            sys.stdout.write("".join(out))
            sys.stdout.flush()

    def wait_for_key(self, timeout):
        if not sys.stdin.isatty():
            self.stop.wait(timeout)
            return
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if ready:
            data = os.read(sys.stdin.fileno(), 64)
            if not data:
                self.stop.set()
                return
            self.handle_key(chr(data[0]))


def ping_once(target):
    try:
        done = subprocess.run(
            ["ping", "-c", "1", "-W", str(PING_TIMEOUT), target],
            capture_output=True, text=True, timeout=PING_TIMEOUT + 2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    match = re.search(r"time=([\d.]+)", done.stdout)
    return float(match.group(1)) if match else None


def tcp_open(target, port):
    try:
        with socket.create_connection((target, port), timeout=TCP_TIMEOUT):
            return True
    except OSError:
        return False


def sparkline(history):
    values = list(history)[-SPARK_N:]
    if not values:
        return "--"
    low, high = min(values), max(values)
    span = (high - low) or 1.0
    return "".join(
        SPARKS[min(len(SPARKS) - 1, int((value - low) / span * (len(SPARKS) - 1)))]
        for value in values
    )


_SYNTHETIC = {"packets": {}, "sources": {}, "xdp": {}, "net": [0, 0, 0, 0], "cpu": [0, 0]}


def synthetic_report():
    counters = {
        "wan-closed-port": random.randint(20, 90),
        "wan-syn-flood": random.randint(0, 400),
        "wan-bogon4": random.randint(0, 12),
        "wan-badflags": random.randint(0, 4),
        "input-fallthrough": random.randint(0, 20),
        "wan-wireguard": random.randint(1, 6),
        "wan-tailscale": random.randint(1, 8),
        "wan-icmp-echo": random.randint(0, 3),
    }
    for rule, delta in counters.items():
        _SYNTHETIC["packets"][rule] = _SYNTHETIC["packets"].get(rule, 0) + delta
    pool = [
        "185.220.101.44", "45.9.148.117", "193.32.162.9", "92.63.197.153",
        "141.98.10.72", "89.248.165.33", "167.94.138.21", "205.210.31.8",
    ]
    flood = int(time.time()) % 40 < 20  # alternate quiet and flood, to exercise both views
    xdp = {
        "pass": random.randint(40, 90),
        "bogon": random.randint(0, 3),
        "bait-tcp": random.randint(8000, 30000) if flood else 0,
        "priv": random.randint(3000, 9000) if flood else 0,
        "ack-rate": random.randint(2000, 7000) if flood else 0,
        "ssh": random.randint(0, 6),
    }
    for name, delta in xdp.items():
        _SYNTHETIC["xdp"][name] = _SYNTHETIC["xdp"].get(name, 0) + delta
    inbound = sum(xdp.values())
    for index, delta in enumerate((inbound * 300, 20000, inbound, 30)):
        _SYNTHETIC["net"][index] += delta
    _SYNTHETIC["cpu"][0] += 400
    _SYNTHETIC["cpu"][1] += random.randint(60, 140) if flood else random.randint(0, 4)
    for _ in range(random.randint(1, 3)):
        ip = random.choice(pool)
        _SYNTHETIC["sources"][ip] = _SYNTHETIC["sources"].get(ip, 0) + random.randint(1, 40)
    scanners = [
        {"value": ip, "packets": count, "bytes": count * random.choice((44, 60, 120, 576, 1400)),
         "last_seen_seconds_ago": random.randint(0, 400)}
        for ip, count in _SYNTHETIC["sources"].items()
    ]
    scanners.sort(key=lambda row: row["packets"], reverse=True)
    flooders = [row for row in scanners if row["packets"] > 120][:3]
    total_packets = sum(row["packets"] for row in scanners)
    repeat = len([row for row in scanners if row["packets"] >= 4])
    return {
        "schema": 2,
        "host": "vps-099e4897",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "firewall": {"loaded": True, "table": "inet ovh_fortress"},
        "counters": [
            {"rule": rule, "chain": "wan_ingress", "packets": packets, "bytes": packets * 60,
             "verdict": "accept" if rule in ("wan-wireguard", "wan-tailscale", "wan-icmp-echo") else "drop"}
            for rule, packets in _SYNTHETIC["packets"].items()
        ],
        "observations": {
            "scanners4": scanners,
            "flooders4": flooders,
            "spoofed4": [{"value": "10.9.9.9", "packets": random.randint(1, 9), "bytes": random.randint(44, 600), "last_seen_seconds_ago": 12}],
        },
        "assessment": {
            "sources": len(scanners),
            "packets": total_packets,
            "repeat_sources": repeat,
            "single_packet_sources": len(scanners) - repeat,
            "packets_per_source": round(total_packets / max(len(scanners), 1), 2),
            "verdict": "persistent scanning" if repeat >= 3 else "background noise",
        },
        "policy": {"public_tcp_services": [], "emergency_ssh4": [], "blocklist4": []},
        "recent": [
            {
                "ts": time.strftime("%H:%M:%S"), "kind": "scan",
                "src": random.choice(pool),
                "dst_port": str(random.choice([22, 3389, 445, 23])),
                "proto": "tcp",
            }
            for _ in range(6)
        ],
        "listeners": [],
        "wireguard": [{
            "interface": "wg0", "endpoint": "203.0.113.9:51820",
            "allowed_ips": "10.66.66.2/32", "last_handshake": int(time.time()) - 40,
            "handshake_age": 40, "rx_bytes": 918273, "tx_bytes": 229311,
        }],
        "conntrack": {"count": random.randint(40, 300), "max": 262144},
        "ports": {
            "window": 120,
            "ports": [{"port": "tcp/22", "hits": 41}, {"port": "tcp/443", "hits": 22},
                      {"port": "tcp/3389", "hits": 12}, {"port": "udp/53", "hits": 9}],
            "pairs": [{"src": ip, "port": port, "hits": 3}
                      for ip in pool[:4] for port in ("tcp/22", "tcp/443", "tcp/3389")[:1 + pool.index(ip)]],
        },
        "xdp": {"loaded": True, "mode": "generic", "rollback_armed": False, "counters": dict(_SYNTHETIC["xdp"])},
        "net": dict(zip(("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"), _SYNTHETIC["net"]), name="ens3"),
        "cpu": {"total": _SYNTHETIC["cpu"][0], "softirq": _SYNTHETIC["cpu"][1]},
        "uptime_seconds": 86400,
        "loadavg": ["0.08", "0.11", "0.09"],
    }


def synthetic_asset(asset):
    base = {
        "Home gateway": 3.2, "Hypervisor": 1.1, "Lab box (LAN)": 1.4,
        "Lab box (Tailnet)": 24.0, "VPS": 31.0,
    }.get(asset.label, 10.0)
    latency = max(0.3, random.gauss(base, base * 0.12))
    if random.random() < 0.04:
        latency *= random.uniform(3, 6)
    asset.reachable = "UP"
    asset.latency = latency
    asset.anomaly = Dashboard._judge(asset, latency)
    if not asset.anomaly:
        asset.history.append(latency)
    asset.port_results = [(port, random.random() > 0.15) for port in asset.ports]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--frames", type=int, default=0)
    args = parser.parse_args()
    dashboard = Dashboard(self_test=args.self_test)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: dashboard.stop.set())
    if args.frames:
        threading.Thread(target=dashboard.poll_firewall, daemon=True).start()
        threading.Thread(target=dashboard.poll_assets, daemon=True).start()
        time.sleep(0.4)
        for _ in range(args.frames):
            dashboard.tick += 1
            for line in dashboard.build(shutil.get_terminal_size((110, 50)).columns):
                print(line)
            time.sleep(0.3)
        dashboard.stop.set()
        return 0
    if sys.stdin.isatty():
        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            dashboard.run()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    else:
        dashboard.run()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stdout.write("\x1b[?25h\x1b[?1049l")
        sys.exit(0)