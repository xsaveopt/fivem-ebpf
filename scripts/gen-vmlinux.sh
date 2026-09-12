#!/usr/bin/env bash
set -euo pipefail

OUT="$(cd "$(dirname "$0")/.." && pwd)/bpf/vmlinux.h"
BTF=/sys/kernel/btf/vmlinux

if [ "$(uname -s)" != "Linux" ]; then
  echo "vmlinux.h can only be generated on Linux (current: $(uname -s))" >&2
  echo "run the build inside the dev VM, see the README" >&2
  exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
  echo "bpftool not found: install it with scripts/provision.sh" >&2
  exit 1
fi

if [ ! -r "$BTF" ]; then
  echo "$BTF is missing or unreadable" >&2
  echo "the kernel needs CONFIG_DEBUG_INFO_BTF=y, and this has to run as root" >&2
  exit 1
fi

tmp="$OUT.tmp"
trap 'rm -f "$tmp"' EXIT

bpftool btf dump file "$BTF" format c > "$tmp"

if [ ! -s "$tmp" ]; then
  echo "bpftool produced an empty vmlinux.h" >&2
  exit 1
fi

mv "$tmp" "$OUT"
echo "wrote $OUT"
