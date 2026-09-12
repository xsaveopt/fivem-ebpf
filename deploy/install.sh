#!/bin/sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
SYSD_DIR="${SYSD_DIR:-/etc/systemd/system}"
ETC_DIR="${ETC_DIR:-/etc/fivem-ebpf}"
GRAFANA_DIR="${GRAFANA_DIR:-$ETC_DIR/grafana}"
DEFAULT_PIN_DIR=/sys/fs/bpf/fivem

usage() {
  cat >&2 <<EOF
usage: install.sh [--uninstall] [--keep-config]

  (no flags)      install or upgrade fivem-ebpf from this directory
  --uninstall     stop the service and remove everything it installed
  --keep-config   with --uninstall, leave $ETC_DIR in place
EOF
}

MODE=install
KEEP_CONFIG=0
for arg in "$@"; do
  case "$arg" in
    --uninstall) MODE=uninstall ;;
    --keep-config) KEEP_CONFIG=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; usage; exit 2 ;;
  esac
done

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "not running as root and sudo is not installed" >&2
    exit 1
  fi
  SUDO=sudo
fi

case "$(uname -s)" in
  Linux) ;;
  *) echo "fivem-ebpf only runs on Linux (current: $(uname -s))" >&2; exit 1 ;;
esac

pin_dir() {
  if [ -r "$ETC_DIR/config" ]; then
    configured=$(sed -n 's/^[[:space:]]*PIN_PATH=//p' "$ETC_DIR/config" | tail -n1 | sed 's/[[:space:]]*$//; s/^"//; s/"$//')
    if [ -n "${configured:-}" ]; then
      echo "$configured"
      return
    fi
  fi
  echo "${PIN_DIR:-$DEFAULT_PIN_DIR}"
}

stop_service() {
  if $SUDO systemctl is-active --quiet fivem-ebpf 2>/dev/null; then
    echo "stopping fivem-ebpf"
    $SUDO systemctl stop fivem-ebpf
    return 0
  fi
  return 1
}

if [ "$MODE" = uninstall ]; then
  PIN_DIR_RESOLVED=$(pin_dir)
  stop_service || true
  $SUDO systemctl disable fivem-ebpf >/dev/null 2>&1 || true
  $SUDO rm -f "$SYSD_DIR/fivem-ebpf.service"
  $SUDO systemctl daemon-reload
  $SUDO rm -f "$PREFIX/bin/fivem-ebpf"
  $SUDO rm -rf "$PIN_DIR_RESOLVED"
  if [ "$KEEP_CONFIG" = 0 ]; then
    $SUDO rm -rf "$ETC_DIR"
  else
    echo "kept $ETC_DIR"
  fi
  echo "uninstalled fivem-ebpf"
  echo "the XDP program detaches when the process stops, so traffic is now unfiltered"
  exit 0
fi

HERE=$(cd "$(dirname "$0")" && pwd)

for f in fivem-ebpf fivem-ebpf.service config.example \
         fivem-ebpf-dashboard.json fivem-ebpf-ips-dashboard.json; do
  [ -f "$HERE/$f" ] || {
    echo "missing $f next to install.sh: run install.sh from the unzipped release directory" >&2
    exit 1
  }
done

host_arch=$(uname -m)
case "$host_arch" in
  x86_64|amd64) host_arch=amd64 ;;
  aarch64|arm64) host_arch=arm64 ;;
esac
if [ -f "$HERE/ARCH" ]; then
  zip_arch=$(tr -d '[:space:]' < "$HERE/ARCH")
  if [ "$zip_arch" != "$host_arch" ]; then
    echo "this release is for $zip_arch but the host is $host_arch" >&2
    echo "download the $host_arch zip instead" >&2
    exit 1
  fi
fi

[ -e /sys/kernel/btf/vmlinux ] || {
  echo "kernel BTF missing at /sys/kernel/btf/vmlinux: need CONFIG_DEBUG_INFO_BTF=y" >&2
  exit 1
}

kmajor=$(uname -r | cut -d. -f1)
kminor=$(uname -r | cut -d. -f2)
if [ "$kmajor" -lt 5 ] || { [ "$kmajor" -eq 5 ] && [ "$kminor" -lt 17 ]; }; then
  echo "kernel $(uname -r) too old: need >= 5.17" >&2
  exit 1
fi

if ! [ -e /sys/fs/cgroup/cgroup.controllers ]; then
  echo "cgroup v2 not mounted at /sys/fs/cgroup" >&2
  exit 1
fi

if ! grep -qs ' /sys/fs/bpf bpf ' /proc/mounts; then
  echo "bpffs is not mounted at /sys/fs/bpf, mounting it now"
  $SUDO mount -t bpf bpffs /sys/fs/bpf || {
    echo "could not mount bpffs at /sys/fs/bpf" >&2
    exit 1
  }
fi

PIN_DIR_RESOLVED=$(pin_dir)

WAS_RUNNING=0
if stop_service; then
  WAS_RUNNING=1
fi

if [ -d "$PIN_DIR_RESOLVED" ]; then
  echo "clearing pinned BPF maps in $PIN_DIR_RESOLVED (shapes can change between releases)"
  $SUDO rm -rf "$PIN_DIR_RESOLVED"
fi

$SUDO mkdir -p "$PREFIX/bin" "$ETC_DIR" "$GRAFANA_DIR"
$SUDO install -m 0755 "$HERE/fivem-ebpf" "$PREFIX/bin/fivem-ebpf"
$SUDO install -m 0644 "$HERE/fivem-ebpf.service" "$SYSD_DIR/fivem-ebpf.service"
$SUDO install -m 0644 "$HERE/fivem-ebpf-dashboard.json"     "$GRAFANA_DIR/fivem-ebpf-dashboard.json"
$SUDO install -m 0644 "$HERE/fivem-ebpf-ips-dashboard.json" "$GRAFANA_DIR/fivem-ebpf-ips-dashboard.json"

NEW_CONFIG=0
if [ ! -e "$ETC_DIR/config" ]; then
  $SUDO install -m 0644 "$HERE/config.example" "$ETC_DIR/config"
  NEW_CONFIG=1
else
  ADDED=""
  while IFS='=' read -r key val; do
    case "$key" in
      ''|\#*) continue ;;
    esac
    if ! $SUDO grep -q "^${key}=" "$ETC_DIR/config"; then
      printf "%s=%s\n" "$key" "$val" | $SUDO tee -a "$ETC_DIR/config" >/dev/null
      ADDED="$ADDED $key"
    fi
  done < "$HERE/config.example"
  if [ -n "$ADDED" ]; then
    echo "added new config keys to $ETC_DIR/config (defaults from this release):$ADDED"
  fi
fi

$SUDO systemctl daemon-reload

if [ "$WAS_RUNNING" = 1 ]; then
  echo "starting fivem-ebpf"
  $SUDO systemctl start fivem-ebpf
  sleep 2
  if ! $SUDO systemctl is-active --quiet fivem-ebpf; then
    echo >&2
    echo "fivem-ebpf failed to start, so the server is running unfiltered:" >&2
    $SUDO journalctl -u fivem-ebpf -n 40 --no-pager >&2 || true
    exit 1
  fi
  echo "fivem-ebpf is running"
fi

echo
echo "installed $PREFIX/bin/fivem-ebpf"
echo "  config:     $ETC_DIR/config"
echo "  unit:       $SYSD_DIR/fivem-ebpf.service"
echo "  pin path:   $PIN_DIR_RESOLVED"
echo "  dashboards: $GRAFANA_DIR/ (import both .json files into Grafana)"
if [ "$NEW_CONFIG" = 1 ]; then
  echo
  echo "EDIT $ETC_DIR/config, IFACE is eth0 by default and probably wrong"
  echo "  $SUDO systemctl enable --now fivem-ebpf"
fi
echo "  $SUDO systemctl status fivem-ebpf"
echo "  $SUDO journalctl -u fivem-ebpf -f"
echo "  install.sh --uninstall   removes everything above"
