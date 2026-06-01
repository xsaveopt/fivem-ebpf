#!/bin/sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
SYSD_DIR="${SYSD_DIR:-/etc/systemd/system}"
ETC_DIR="${ETC_DIR:-/etc/gameshield}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/gameshield}"
LEGACY_PIN_DIR="${LEGACY_PIN_DIR:-/sys/fs/bpf/fivem}"
GRAFANA_DIR="${GRAFANA_DIR:-$ETC_DIR/grafana}"

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO=sudo

HERE=$(cd "$(dirname "$0")" && pwd)

for f in gameshield gameshield-ebpf.service config.example.yaml \
         gameshield-dashboard.json gameshield-ips-dashboard.json; do
  [ -f "$HERE/$f" ] || {
    echo "missing $f next to install.sh — run install.sh from the unzipped release directory" >&2
    exit 1
  }
done

case "$(uname -s)" in
  Linux) ;;
  *) echo "gameshield-ebpf only runs on Linux (current: $(uname -s))" >&2; exit 1 ;;
esac

[ -e /sys/kernel/btf/vmlinux ] || {
  echo "kernel BTF missing at /sys/kernel/btf/vmlinux — need CONFIG_DEBUG_INFO_BTF=y" >&2
  exit 1
}

kmajor=$(uname -r | cut -d. -f1)
kminor=$(uname -r | cut -d. -f2)
if [ "$kmajor" -lt 5 ] || { [ "$kmajor" -eq 5 ] && [ "$kminor" -lt 17 ]; }; then
  echo "kernel $(uname -r) too old — need >= 5.17" >&2
  exit 1
fi

if ! [ -e /sys/fs/cgroup/cgroup.controllers ]; then
  echo "cgroup v2 not mounted at /sys/fs/cgroup" >&2
  exit 1
fi

WAS_RUNNING=0
if $SUDO systemctl is-active --quiet gameshield-ebpf 2>/dev/null; then
  WAS_RUNNING=1
  echo "stopping running gameshield-ebpf"
  $SUDO systemctl stop gameshield-ebpf
fi

if $SUDO systemctl is-enabled --quiet fivem-ebpf 2>/dev/null; then
  echo "disabling legacy fivem-ebpf unit (replaced by gameshield-ebpf)"
  $SUDO systemctl disable --now fivem-ebpf || true
fi
if [ -d "$LEGACY_PIN_DIR" ]; then
  echo "removing legacy pinned BPF maps in $LEGACY_PIN_DIR"
  $SUDO rm -rf "$LEGACY_PIN_DIR"
fi

if [ -d "$PIN_DIR" ]; then
  echo "clearing pinned BPF maps in $PIN_DIR (shapes can change between releases)"
  $SUDO rm -rf "$PIN_DIR"
fi

$SUDO install -m 0755 "$HERE/gameshield" "$PREFIX/bin/gameshield"
$SUDO install -m 0644 "$HERE/gameshield-ebpf.service" "$SYSD_DIR/gameshield-ebpf.service"
$SUDO mkdir -p "$ETC_DIR" "$GRAFANA_DIR"
$SUDO install -m 0644 "$HERE/gameshield-dashboard.json"     "$GRAFANA_DIR/gameshield-dashboard.json"
$SUDO install -m 0644 "$HERE/gameshield-ips-dashboard.json" "$GRAFANA_DIR/gameshield-ips-dashboard.json"

NEW_CONFIG=0
if [ ! -e "$ETC_DIR/config.yaml" ]; then
  $SUDO install -m 0644 "$HERE/config.example.yaml" "$ETC_DIR/config.yaml"
  NEW_CONFIG=1
fi

$SUDO systemctl daemon-reload

if [ "$WAS_RUNNING" = 1 ]; then
  echo "starting gameshield-ebpf"
  $SUDO systemctl start gameshield-ebpf
fi

echo
echo "installed $PREFIX/bin/gameshield"
echo "  config:     $ETC_DIR/config.yaml"
echo "  unit:       $SYSD_DIR/gameshield-ebpf.service"
echo "  dashboards: $GRAFANA_DIR/ (import the .json files into Grafana)"
if [ "$NEW_CONFIG" = 1 ]; then
  echo
  echo "EDIT $ETC_DIR/config.yaml — iface is eth0 by default, probably wrong"
  echo "  $SUDO systemctl enable --now gameshield-ebpf"
fi
echo "  $SUDO systemctl status gameshield-ebpf"
echo "  sudo journalctl -u gameshield-ebpf -f"
