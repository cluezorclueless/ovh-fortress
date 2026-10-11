#!/usr/bin/env bash
# Attach or detach fortress_xdp on the WAN interface.
#
#   sudo ./load.sh on [native]   attach (generic mode unless "native" is given)
#   sudo ./load.sh confirm       keep it: cancel the automatic rollback
#   sudo ./load.sh off           detach
#   sudo ./load.sh status        attachment, rollback timer, counters
#
# "on" arms a timer that detaches the program again after ROLLBACK seconds.
# If the new filter cuts you off, wait it out. If you can still log in from a
# NEW session, run "confirm". Nothing here survives a reboot.
set -Eeuo pipefail

IFACE="${IFACE:-ens3}"
ROLLBACK="${ROLLBACK:-180}"
UNIT="fortress-xdp-rollback"
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OBJ="$DIR/fortress_xdp.o"
IP="$(command -v ip)"

die() { echo "load.sh: $*" >&2; exit 1; }

detach() {
    # "xdp off" alone only clears the driver's default mode, so name both.
    "$IP" link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
    "$IP" link set dev "$IFACE" xdpdrv off 2>/dev/null || true
}

disarm() {
    systemctl stop "$UNIT.timer" "$UNIT.service" 2>/dev/null || true
    systemctl reset-failed "$UNIT.timer" "$UNIT.service" 2>/dev/null || true
}

(( EUID == 0 )) || die "run as root: sudo $0 ${*:-on}"
[[ -e /sys/class/net/$IFACE ]] || die "interface $IFACE not found"

case "${1:-}" in
on)
    mode="xdpgeneric"
    [[ "${2:-}" == "native" ]] && mode="xdpdrv"
    if [[ ! -f $OBJ || $DIR/fortress_xdp.c -nt $OBJ ]]; then
        command -v clang >/dev/null || die "clang missing: sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev make"
        make -C "$DIR"
    fi
    disarm
    systemd-run --quiet --unit="$UNIT" --on-active="${ROLLBACK}s" \
        /bin/sh -c "$IP link set dev $IFACE xdpgeneric off; $IP link set dev $IFACE xdpdrv off"
    detach
    if ! "$IP" -force link set dev "$IFACE" "$mode" obj "$OBJ" sec xdp; then
        disarm
        die "attach failed in $mode mode; nothing is attached"
    fi
    echo "attached to $IFACE in $mode mode"
    echo "It detaches itself in ${ROLLBACK}s unless you run: sudo $0 confirm"
    echo "Before confirming, open a NEW ssh session to prove you can still get in."
    ;;
confirm)
    "$IP" -d link show dev "$IFACE" | grep -q "prog/xdp" || die "nothing is attached to $IFACE"
    disarm
    echo "rollback cancelled; fortress_xdp stays attached until reboot or '$0 off'"
    ;;
off)
    disarm
    detach
    echo "detached from $IFACE"
    ;;
status)
    "$IP" -d link show dev "$IFACE" | grep -E "prog/xdp|xdp" || echo "no XDP program on $IFACE"
    if systemctl is-active --quiet "$UNIT.timer"; then
        echo "rollback timer is ARMED (run 'confirm' to keep the program)"
    else
        echo "rollback timer is not armed"
    fi
    "$DIR/xdp-stats" || true
    ;;
*)
    die "usage: sudo $0 on [native] | confirm | off | status"
    ;;
esac
