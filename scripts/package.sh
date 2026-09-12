#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <arch> <version>" >&2
  exit 2
fi

arch=$1
version=$2
root="$(cd "$(dirname "$0")/.." && pwd)"
bin="$root/dist/fivem-ebpf-linux-$arch"
zip_name="fivem-ebpf-$version-linux-$arch.zip"

if [ ! -x "$bin" ]; then
  echo "$bin not built: run make release first" >&2
  exit 1
fi

stage="$root/dist/stage-$arch"
rm -rf "$stage"
mkdir -p "$stage"

install -m 0755 "$bin" "$stage/fivem-ebpf"
install -m 0755 "$root/deploy/install.sh" "$stage/install.sh"
install -m 0644 "$root/deploy/fivem-ebpf.service" "$stage/fivem-ebpf.service"
install -m 0644 "$root/deploy/config.example" "$stage/config.example"
install -m 0644 "$root/deploy/grafana/fivem-ebpf-dashboard.json" "$stage/fivem-ebpf-dashboard.json"
install -m 0644 "$root/deploy/grafana/fivem-ebpf-ips-dashboard.json" "$stage/fivem-ebpf-ips-dashboard.json"

printf '%s\n' "$arch" > "$stage/ARCH"

rm -f "$root/dist/$zip_name"
(cd "$stage" && zip -q "$root/dist/$zip_name" \
  fivem-ebpf \
  install.sh \
  fivem-ebpf.service \
  config.example \
  fivem-ebpf-dashboard.json \
  fivem-ebpf-ips-dashboard.json \
  ARCH)

(cd "$root/dist" && sha256sum "$zip_name" > "$zip_name.sha256")
rm -rf "$stage"
echo "dist/$zip_name"
