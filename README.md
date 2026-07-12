# fivem-ebpf

Kernel-level L7 DDoS filter for a FiveM game server. XDP matches the FiveM HTTP handshake on ingress, gates UDP on a per-IP whitelist that only the handshake populates, and token-bucket-rate-limits both UDP gameplay traffic and TCP handshake attempts per source IP. Prometheus metrics for every verdict.

## What it does

FiveM listens on port **30120** for both TCP and UDP. TCP serves the HTTP-style endpoints (`/info.json`, `/players.json`, `/client`); the connection handshake is `POST /client method=initConnect` with `User-Agent: CitizenFX/1`. UDP carries ENet game traffic, allowed only after that handshake.

**TCP path (XDP):**
- non-SYN from an IP with no SYN history and no established socket → drop (`no_syn`, the iptables `! --syn` flood filter)
- new SYN → per-IP open-connection cap, then global SYN rate limit (the new-connection circuit breaker)
- bare `CitizenFX` user-agent (no `/1`) → drop (zero-FP bot fingerprint observed in real captures)
- `POST /client` → per-IP token bucket; on `CitizenFX/1` match over an established socket, promote source IP into `tcp_whitelist`
- `GET /info.json | /dynamic.json | /players.json` → per-IP token bucket. These return multi-KB JSON (25–50× amplification) — this is the primary HTTP-amplification defense.
- whitelisted IPs short-circuit all the above (asset downloads, reconnects)

**UDP path (XDP):** drop if not in `tcp_whitelist`, drop if in `udp_health` blacklist, drop if ENet structurally invalid (bumps an anomaly counter; threshold trips the blacklist), drop if per-IP UDP rate limit exhausted, otherwise pass. Every passed packet refreshes the whitelist timestamp so active sessions don't expire.

**State seeding (sockops):** a `sock_ops` program on cgroup v2 root fires on `PASSIVE_ESTABLISHED_CB` for port 30120 and writes the client IP into `tcp_established`. Kernel TCP-state signal, not a payload guess. Same program tracks `tcp_open_count` via `STATE_CB`.

## Install

Download the release zip for your arch from the [releases page](https://github.com/xsaveopt/fivem-ebpf/releases), unzip, and run the installer:

```sh
VERSION=v0.1.0
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -sfLO "https://github.com/xsaveopt/fivem-ebpf/releases/download/$VERSION/fivem-ebpf-$VERSION-linux-$ARCH.zip"
curl -sfLO "https://github.com/xsaveopt/fivem-ebpf/releases/download/$VERSION/fivem-ebpf-$VERSION-linux-$ARCH.zip.sha256"
sha256sum -c "fivem-ebpf-$VERSION-linux-$ARCH.zip.sha256"
unzip -d fivem-ebpf-$VERSION "fivem-ebpf-$VERSION-linux-$ARCH.zip"
cd fivem-ebpf-$VERSION && sudo sh install.sh
```

Then:

```sh
sudo vim /etc/fivem-ebpf/config          # set IFACE and rate-limit values
sudo systemctl enable --now fivem-ebpf
sudo systemctl status fivem-ebpf
```

Zip contains binary, systemd unit, config example, install script, and two Grafana dashboards (main + per-IP listings) installed under `/etc/fivem-ebpf/grafana/`. **Upgrades:** re-run `install.sh` from the new zip — it stops the daemon, wipes pinned maps (shapes change between releases), installs new files, appends any new config keys with their defaults, and restarts.

## Requirements

- Linux ≥ 6.1 (tested on Ubuntu 24.04 / kernel 6.8). `bpf_loop` needs 5.17+.
- `clang`, `llvm`, `libbpf-dev`, `libelf-dev`, `bpftool`, `linux-headers-$(uname -r)`
- Go 1.22+
- cgroup v2 (default on modern distros)

macOS users (Apple Silicon or Intel): use **OrbStack** for the Linux dev VM — arm64-native, handles BPF/XDP cleanly, mounts your home directory at the same path inside.

## Quick start (OrbStack on macOS)

One-time setup:

```sh
brew install --cask orbstack          # if you don't have it yet
orb create ubuntu:24.04 fivem-ebpf    # creates the VM (~30s)
orb run -m fivem-ebpf -w "$PWD" sudo bash scripts/provision.sh   # install toolchain
```

Day-to-day:

```sh
orb -m fivem-ebpf                     # drops you into a shell inside the VM
# now inside the VM — your Mac home is mounted at /Users/<you>, not $HOME:
cd /Users/<you>/Documents/personal/dev/none/fivem-ebpf
make build
sudo ./bin/fivem-ebpf run --iface eth0
```

From another terminal on your Mac: `curl http://$(orb info -m fivem-ebpf -f '{{.IP}}'):9464/metrics` (or just `curl localhost:9464/metrics` — OrbStack auto-forwards).

## Quick start (bare metal / remote server)

```sh
make build
sudo ./bin/fivem-ebpf run --iface <your-nic>
```

`make build` runs the bpf2go code generator and then `go build`. On first run you'll need `bpf/vmlinux.h` — `make` regenerates it from `/sys/kernel/btf/vmlinux` automatically.

## CLI

```
fivem-ebpf run     [flags]                 attach BPF, serve /metrics + /api/*
fivem-ebpf info                            counters + map sizes
fivem-ebpf stats   [--json] [--watch 1s]   per-CPU stat counters
fivem-ebpf top     --map M [-n 10]         hottest IPs in a per-IP map
fivem-ebpf inspect <ipv4> [--watch 1s]     all per-IP state for one address, including cumulative drop counts by reason
fivem-ebpf dump    --map M                 full listing of a map
fivem-ebpf health  [--all]                 blacklisted IPs (--all: also tracked-but-not-banned)
fivem-ebpf clear   --map M [--ip A]        wipe a map, or one IP from it
```

`M` is one of `whitelist`, `established`, `syn-seen`, `open-count`, `udp-ratelimit`, `initconnect-ratelimit`, `getinfo-ratelimit`, `health`, `drop-history`, or `all`. Run `fivem-ebpf run --help` for the daemon flags. All other subcommands operate directly on the pinned BPF maps; the daemon doesn't need to be reachable over HTTP.

## Metrics & API

`http://<addr>:9464` (configurable via `--metrics-addr`):

- `/metrics` — Prometheus counters. Main counter is `fivem_xdp_packets_total{verdict,proto,reason}`; supporting counters/gauges are `fivem_tcp_*_total`, `fivem_map_entries{map}`, `fivem_health_blacklisted_ips`, `fivem_attached{program}`, `fivem_build_info`. Labels are deliberately low-cardinality: there are no per-IP labels.
- `/api/info` — daemon overview (limits + map sizes + counter totals).
- `/api/stats` — counter values as JSON.
- `/api/top?map=<name>&n=<N>` — hottest IPs in one map (same ranking as `fivem-ebpf top`).
- `/api/health[?all=1]` — blacklisted IPs; `?all=1` includes tracked-but-not-banned.
- `/api/whitelist` `/api/blacklist` `/api/established` `/api/syn-seen` `/api/open-count` — per-map listings.
- `/api/drop-history` — per-IP cumulative drop counts grouped by reason; pair with `/api/top?map=drop-history&reason=<name>` to rank.
- `/api/ip/<addr>` — every map's view of one IPv4 in a single JSON object, including a `drop_history` block. The "why was this player kicked" endpoint.
- `/api/state` — index.

The release ships two Grafana dashboards in `/etc/fivem-ebpf/grafana/`: the main metrics dashboard, and a per-IP listings dashboard that needs the [Infinity datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) plugin (point it at your `:9464`).

## Known limitations

- **No per-packet crypto auth.** Whitelisted IPs are bounded only by ENet validation + per-IP rate limits; a botnet of N IPs can collectively push `N × --udp-rate` pps of valid-looking ENet. ENet check stops random-byte floods, not spec-compliant ones. Statistical per-IP scoring is the planned direction.
- **L7 match is a byte pattern.** An attacker who crafts `POST /client` + `CitizenFX/1` over a real TCP connection passes — same as iptables string-match. This filter buys speed, not new security primitives.
- **Bad-UA blocklist is narrow on purpose.** Only the literal `CitizenFX\r` (no `/1`) is dropped; `curl/`, `python-*`, `Mozilla/*` etc. are kept legal because legitimate server-list scrapers use them. Per-IP GET rate limit catches abusive scraping instead.
- **IPv4 only.** Sockops uses `remote_ip4`. FiveM bound to `::` and reached over native v6 skips the filter — bind `0.0.0.0` explicitly.
- **XDP mode matters.** Native XDP for production numbers. Generic-mode fallback is correct but slow; the daemon logs which mode attached.

## Operational pitfalls

- **Upgrades and fresh installs drop every active UDP session.** `install.sh` wipes `/sys/fs/bpf/fivem/` so map shapes can change between releases. The whitelist resets to empty, but the sockops program only seeds `tcp_established` from `PASSIVE_ESTABLISHED_CB` on **new** TCP connections — already-connected players never re-trigger that callback, so their next `POST /client` will not promote and their UDP gets dropped as `not_whitelisted` until they fully reconnect. Same applies the very first time you install on a live server. Plan for off-peak, or expect a one-time mass reconnect.
- **Plain `systemctl restart` is mostly safe** *only if you didn't change anything that alters pin shape* (stat-slot count, map value types). Pins persist, the new daemon reuses the existing whitelist. If you bumped the binary across a release boundary outside of `install.sh`, hand-wipe `/sys/fs/bpf/fivem/` and accept the reconnect.
- **`clear --map whitelist` (or `--map all`) is production-fatal.** Same blast radius as a wipe-and-restart with no recovery path short of a reconnect storm. Don't run it on a live server unless that's what you want.
- **NAT or a TCP-terminating proxy in front collapses every player into one source IP.** Per-IP rate limits then starve legitimate traffic, and one bad client poisons the whole server. PROXY protocol / `X-Forwarded-For` are not parsed. Attach on the upstream NIC, not behind a load balancer.
- **XDP is per-NIC.** With asymmetric routing or multi-homed setups, traffic that ingresses on a NIC the daemon isn't attached to is unfiltered. `--iface` must match the actual ingress path; multiple ingress NICs need multiple daemons.
- **Whitelist TTL trims idle players.** Default `TTL=10m` — every passed UDP packet refreshes it, but a player whose UDP stalls (loading screens, `/afk` mods that suspend traffic, transient packet loss longer than 10 minutes) drops out and resumes as `expired`. Tune `TTL` in `/etc/fivem-ebpf/config` to your worst-case idle gap.
- **Don't restart while you're under attack.** All of the above gets worse: the wipe window is exactly when an attacker's UDP flood from non-whitelisted IPs would otherwise be dropped — but legitimate players' state is also gone, and they'll fight the attacker's traffic for handshake bandwidth on the way back in.
- **Stale foreground `run` processes lie.** A `./bin/fivem-ebpf run` left in a tmux pane keeps maps pinned and the `fivem_attached=1` gauge true even after you `systemctl start fivem-ebpf`, masking that the service unit failed to attach. Prefer `systemd-run --unit=fivem-dbg` for debug runs, and check `pgrep -a fivem-ebpf` before assuming the unit is the live daemon.

## Troubleshooting

- **`sockops: attach failed: permission denied`** — cgroup v2 not at `--cgroup` (default `/sys/fs/cgroup`). Check `mount | grep cgroup2`.
- **`attach xdp: native: …; generic: …`** — another XDP program is attached. `ip link set dev <iface> xdpgeneric off` and retry.
- **L7 never fires.** Verify the client sends `User-Agent: CitizenFX/1` (`tcpdump -A -i <iface> 'tcp port 30120'`). A TLS-terminating proxy in front of FXServer hides it; attach on the real frontend NIC.
- **Sockops doesn't fire for a containerized FXServer.** Use the container's cgroup path (`cat /proc/<fxserver-pid>/cgroup`), not the root.
