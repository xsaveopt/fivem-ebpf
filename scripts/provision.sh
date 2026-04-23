#!/usr/bin/env bash
#
# Provision a Linux host (OrbStack VM, cloud VM, or bare metal) with the
# toolchain needed to build fivem-ebpf from source. Idempotent — safe to
# re-run.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO=sudo

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
  tcpdump \
  golang-go

# bpftool is a "virtual" package on Ubuntu noble that requires a
# kernel-version-matched linux-tools-<uname-r>. OrbStack runs its own kernel
# whose version isn't in Ubuntu's repos, so the normal apt path fails. Build
# bpftool from source — small, fast, and kernel-version-independent.
if ! command -v bpftool >/dev/null 2>&1; then
  tmp=$(mktemp -d)
  git clone --depth 1 --recurse-submodules \
    https://github.com/libbpf/bpftool "$tmp/bpftool"
  make -C "$tmp/bpftool/src" -j"$(nproc)"
  $SUDO make -C "$tmp/bpftool/src" install
  rm -rf "$tmp"
fi

$SUDO mkdir -p /sys/fs/bpf/fivem
