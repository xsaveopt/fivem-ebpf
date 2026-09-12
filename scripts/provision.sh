#!/usr/bin/env bash
set -euo pipefail

GO_VERSION=1.27.1
BPFTOOL_VERSION=v7.7.0

export DEBIAN_FRONTEND=noninteractive

if [ "$(uname -s)" != "Linux" ]; then
  echo "provision.sh sets up a Linux dev VM (current: $(uname -s))" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "provision.sh only knows Debian and Ubuntu; install the equivalents of" >&2
  echo "clang llvm libbpf-dev libelf-dev bpftool and Go $GO_VERSION by hand" >&2
  exit 1
fi

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO=sudo

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
  clang \
  llvm \
  build-essential \
  libbpf-dev \
  libelf-dev \
  libssl-dev \
  zlib1g-dev \
  git \
  curl \
  ca-certificates \
  pkg-config \
  socat \
  netcat-openbsd \
  tcpdump

if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go$GO_VERSION"; then
  echo "installing Go $GO_VERSION"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -sfL -o "$tmp/go.tar.gz" "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"
  $SUDO rm -rf /usr/local/go
  $SUDO tar -C /usr/local -xzf "$tmp/go.tar.gz"
  $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/go
  $SUDO ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  rm -rf "$tmp"
  trap - EXIT
fi

if ! command -v bpftool >/dev/null 2>&1; then
  echo "installing bpftool $BPFTOOL_VERSION"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -sfL -o "$tmp/bpftool.tar.gz" \
    "https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}/bpftool-${BPFTOOL_VERSION}-${arch}.tar.gz"
  tar -xzf "$tmp/bpftool.tar.gz" -C "$tmp" bpftool
  $SUDO install -m 0755 "$tmp/bpftool" /usr/local/bin/bpftool
  rm -rf "$tmp"
  trap - EXIT
fi

if ! grep -qs ' /sys/fs/bpf bpf ' /proc/mounts; then
  echo "mounting bpffs at /sys/fs/bpf"
  $SUDO mount -t bpf bpffs /sys/fs/bpf
fi

$SUDO mkdir -p /sys/fs/bpf/fivem

go version
bpftool version
