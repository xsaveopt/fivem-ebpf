# fivem-ebpf

Kernel-level L7 DDoS filter for a FiveM game server. XDP matches the FiveM HTTP handshake on ingress, gates UDP on a per-IP whitelist that only the handshake populates, and token-bucket-rate-limits both UDP gameplay traffic and TCP handshake attempts per source IP. Prometheus metrics for every verdict.

## What it does

FiveM listens on port **30120 TCP and UDP**. The TCP side serves the HTTP-style endpoints (`/info.json`, `/players.json`, `/client`) and drives the connection handshake via `POST /client method=initConnect` with `User-Agent: CitizenFX/1`; UDP carries the ENet game traffic after the client has received its endpoint from the TCP flow.

Seven layers of defense, all enforced in XDP / sockops:

1. **TCP 3WHS gate (sockops).** A sock_ops program attached to cgroup v2 root fires on `PASSIVE_ESTABLISHED_CB` for port 30120 and writes the client IP into `tcp_established`. This is the kernel's own TCP state-machine signal, not a payload guess.
2. **Bad-UA drop (XDP, TCP path).** If a TCP segment to `:30120` looks like a FiveM HTTP request (`POST /client` or one of the info GETs) and its User-Agent is literally `CitizenFX` with no `/1` suffix, drop it. Zero-false-positive bot fingerprint observed in real attack captures — real FiveM clients unconditionally send `CitizenFX/1`.
3. **L7 pattern match (XDP, TCP path).** On `POST /client` segments, XDP checks for `CitizenFX/1` within the first 128 payload bytes. If the UA matches _and_ the source IP is in `tcp_established`, the IP is promoted to `tcp_whitelist`. An attacker who completes 3WHS but doesn't run the real FiveM HTTP client never gets whitelisted for UDP.
4. **ENet structural validation (XDP, UDP path).** Every UDP packet from a whitelisted IP is parsed as ENet: reserved peer-ID bits must be zero, the first command type must be 1–12, command flag byte must be a legal combination. Structurally malformed packets drop and increment a per-IP anomaly counter; once the counter trips `health-threshold` in a `health-window`, the IP is blacklisted for `health-blacklist`. Catches lazy "flood random bytes from whitelisted IPs" attacks.
5. **Per-IP UDP token bucket (XDP, UDP path).** Whitelisted healthy UDP is metered against `udp_ratelimit`. Caps the damage a single whitelisted IP can do — attenuates TCP-completing botnet floods.
6. **Per-IP `POST /client` token bucket (XDP, TCP path).** Matched POST /client segments are metered against `initconnect_ratelimit`. Over-limit segments drop. Stops handshake-exhaustion attacks on FXServer's auth path.
7. **Per-IP info-endpoint token bucket (XDP, TCP path).** `GET /info.json`, `/dynamic.json`, `/players.json` are each 25–50× amplification vectors (multi-KB JSON response). Per-IP rate-limited via `getinfo_ratelimit` (default 6/min, burst 5). Real clients hit these once or twice per join; bots hitting them dozens of times per second are throttled. **This is the primary defense against the distributed HTTP amplification attacks seen in real captures.**

```
                     ┌────────── server NIC (XDP) ──────────┐
                     │                                       │
  client ─► pkt ─►   │  parse eth/ip/l4                     │
                     │                                       │
                     │  TCP/30120 data segment:              │
                     │    UA: bare "CitizenFX\r" → DROP      │
                     │    POST /client @ off 0:              │
                     │      + per-IP initconnect ratelimit   │
                     │      + scan for "CitizenFX/1":        │
                     │          ∈ tcp_established → whitelist│
                     │    GET /info.json|/dynamic.json|      │
                     │        /players.json @ off 0:         │
                     │      + per-IP getinfo ratelimit       │
                     │                                       │
                     │  UDP/30120:                           │
                     │    src_ip ∉ tcp_whitelist → DROP      │
                     │    src_ip ∈ udp_health blacklist → DROP│
                     │    ENet structure invalid → DROP      │
                     │      + bump udp_health anomalies      │
                     │    udp_ratelimit empty → DROP         │
                     │    else → PASS                        │
                     │                                       │
                     │  anything else → PASS                 │
                     └───────────────────────────────────────┘

   sockops (cgroup root)
     PASSIVE_ESTABLISHED on local_port=30120 AF_INET
       → tcp_established[src_ip] = boot_ns
```

## Install

Download the release zip for your arch from the [releases page](https://github.com/sratabix/fivem-ebpf/releases), unzip, and run the installer:

```sh
VERSION=v0.1.0
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -sfLO "https://github.com/sratabix/fivem-ebpf/releases/download/$VERSION/fivem-ebpf-$VERSION-linux-$ARCH.zip"
curl -sfLO "https://github.com/sratabix/fivem-ebpf/releases/download/$VERSION/fivem-ebpf-$VERSION-linux-$ARCH.zip.sha256"
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

The release zip contains the binary, systemd unit, config example, install script, and the Grafana dashboard JSON (`/etc/fivem-ebpf/grafana/fivem-ebpf-dashboard.json` after install — import into Grafana).

**Upgrades.** Re-run `install.sh` from the new release. It stops the running daemon, wipes the pinned BPF maps (their shapes change between releases — libbpf refuses to reuse a stale pin), installs the new binary/unit/dashboard, appends any new config keys to `/etc/fivem-ebpf/config` with their defaults (so `${NEW_VAR}` references in the unit don't break), and restarts the service if it was running.

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
fivem-ebpf run     --iface eth0 [--port 30120] [--ttl 10m] [--metrics-addr :9464]
                   [--cgroup /sys/fs/cgroup] [--pin-path /sys/fs/bpf/fivem]
                   [--udp-rate 1500] [--udp-burst 4500]
                   [--tcp-initconnect-per-min 6] [--tcp-initconnect-burst 3]
                   [--tcp-getinfo-per-min 6] [--tcp-getinfo-burst 5]
                   [--tcp-global-rate 5000] [--tcp-global-burst 15000]
                   [--health-window 10s] [--health-threshold 20] [--health-blacklist 5m]
                   [--map-size-interval 30s]
fivem-ebpf dump    [--map whitelist|established|syn-seen|udp-ratelimit|initconnect-ratelimit|getinfo-ratelimit|health|all]
fivem-ebpf stats   [--pin-path /sys/fs/bpf/fivem]
fivem-ebpf clear   [--map whitelist|established|syn-seen|udp-ratelimit|initconnect-ratelimit|getinfo-ratelimit|health|all] [--ip <addr>]
```

`dump`, `stats`, and `clear` operate on the pinned maps and don't require `run` to be live — useful for poking at state while the filter is running. `clear --ip <addr>` removes only that IPv4 from the target map(s) instead of wiping every entry — use it to unblock a single accidentally-blacklisted player without losing protection against everyone else.

### Tuning

- `--udp-rate` / `--udp-burst` — per-IP UDP packets/sec + burst. Ship loose (default 1500/4500). Check `rate(fivem_xdp_packets_total{reason="ratelimit"}[5m])` in Prometheus to see if you're clipping real players.
- `--tcp-initconnect-per-min` / `--tcp-initconnect-burst` — per-IP cap on how often an IP may send `POST /client` payloads. Default 6/min burst 3 — a normal connecting client sits under this comfortably. Tightened from burst 10 after analyzing a real captured attack where 980 attacker IPs × burst-10 flooded the server in the first second.
- `--tcp-getinfo-per-min` / `--tcp-getinfo-burst` — per-IP cap on `GET /info.json` / `/dynamic.json` / `/players.json`. Default 6/min burst 5. Real players hit these 1–2× per join; bots hit 20+ times/sec. **Primary defense against HTTP amplification floods.**
- `--tcp-global-rate` / `--tcp-global-burst` — global circuit breaker on aggregate TCP pps to the target port, regardless of source IP. Default 5000/15000 is "trip only during a real attack." Under active attack, tighten (e.g. `1500/4500`) — sacrifices new joins but keeps the server up. `0` disables.
- `--health-window` / `--health-threshold` / `--health-blacklist` — ENet-anomaly tolerance. Default "20 malformed packets in 10 s → blacklisted for 5 min." A real client shouldn't hit even one malformed event under normal play; loosen only if you see false positives on `fivem_xdp_packets_total{reason="enet_malformed"}`.
- `--map-size-interval` — how often a background ticker iterates the IP-keyed maps to refresh `fivem_map_entries` gauges. Default 30 s. Increase if maps get very large and refresh CPU shows up in profiling.

## Metrics

Exposed at `http://<addr>/metrics`:

| Metric                                    | Type    | Labels                                                                               |
| ----------------------------------------- | ------- | ------------------------------------------------------------------------------------ |
| `fivem_xdp_packets_total`                 | counter | `verdict`, `proto`, `reason`                                                         |
| `fivem_tcp_established_inserts_total`     | counter | —                                                                                    |
| `fivem_tcp_l7_promoted_total`             | counter | —                                                                                    |
| `fivem_tcp_l7_match_no_established_total` | counter | —                                                                                    |
| `fivem_tcp_post_client_seen_total`        | counter | — (bumped on every `POST /client` match, regardless of verdict — ideal for `rate()`) |
| `fivem_tcp_getinfo_seen_total`            | counter | — (bumped on every `GET /info.json` / `/dynamic.json` / `/players.json` match)       |
| `fivem_map_entries`                       | gauge   | `map` — size of each IP-keyed map (refreshed by ticker, default 30s)                 |
| `fivem_health_blacklisted_ips`            | gauge   | — IPs currently with `blacklist_until_ns > now` in `udp_health`                      |
| `fivem_attached`                          | gauge   | `program` (`xdp` / `sockops`)                                                        |
| `fivem_build_info`                        | gauge   | `version`, `iface`, `port`                                                           |

Labels are deliberately low-cardinality — there are no per-IP labels. Observed verdict/proto/reason combinations:

- `verdict="pass", proto="tcp", reason=""`
- `verdict="pass", proto="udp", reason="whitelisted"`
- `verdict="drop", proto="udp", reason="not_whitelisted"`
- `verdict="drop", proto="udp", reason="expired"`
- `verdict="drop", proto="udp", reason="malformed"`
- `verdict="drop", proto="udp", reason="ratelimit"`
- `verdict="drop", proto="tcp", reason="initconnect_ratelimit"`
- `verdict="drop", proto="udp", reason="enet_malformed"`
- `verdict="drop", proto="udp", reason="unhealthy"`
- `verdict="drop", proto="tcp", reason="getinfo_ratelimit"`
- `verdict="drop", proto="tcp", reason="bad_user_agent"`
- `verdict="drop", proto="tcp", reason="no_syn"` — non-SYN packet from an IP that never sent a SYN and isn't established (ACK/FIN/RST flood)
- `verdict="drop", proto="tcp", reason="global_ratelimit"` — aggregate TCP circuit breaker tripped

### Per-IP listings

The metrics server also exposes JSON endpoints for inspecting current per-IP state. These are deliberately separate from `/metrics` to keep Prometheus cardinality bounded; query them on demand.

| Endpoint           | What                                                                       |
| ------------------ | -------------------------------------------------------------------------- |
| `/api/whitelist`   | IPs in `tcp_whitelist` with `age_seconds`                                  |
| `/api/blacklist`   | IPs currently UDP-blacklisted with `anomalies` and `blacklist_remaining_seconds` |
| `/api/established` | IPs in `tcp_established` (completed 3WHS, no L7 yet) with `age_seconds`    |
| `/api/syn-seen`    | IPs in `tcp_syn_seen` with `age_seconds`                                   |
| `/api/open-count`  | Open TCP socket count per IP (`tcp_open_count`)                            |
| `/api/state`       | Index of the above                                                         |

Each endpoint iterates the corresponding pinned LRU map on demand — fine for ad-hoc inspection but a 100k-entry map under attack means a slow response. Don't poll on a tight interval. Treat the response as "current state when queried", not a stream.

The release zip ships a second Grafana dashboard, `fivem-ebpf-ips-dashboard.json`, that surfaces these as table panels (whitelist / blacklist / open-count / established). It needs the [Infinity datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) plugin — install via `grafana-cli plugins install yesoreyeram-infinity-datasource` and configure the URL to your fivem-ebpf metrics endpoint (e.g. `http://server:9464`).

## Known limitations

- **No per-packet crypto auth.** Once an IP is whitelisted, rate-limit + ENet-structure are the only things capping damage — a botnet of N IPs can collectively push `N × --udp-rate` pps of structurally-valid ENet packets. The ENet check catches lazy "random bytes" floods; it does nothing against an attacker who bothered to read the ENet spec. See [Roadmap → Path B](ROADMAP.md) for the statistical-scoring direction that addresses well-formed floods.
- **L7 match is byte-pattern, not semantic.** An attacker that can craft a TCP segment containing `POST /client` and `CitizenFX/1` over a real established TCP connection passes the filter. This matches what comparable iptables string-match rules do — we've moved the check to XDP for speed, not added new security vs. those rules.
- **Bad-UA blocklist is intentionally narrow.** We only drop on the literal `User-Agent: CitizenFX\r` (bare `CitizenFX` with no `/1`, impossible for a real FiveM client to produce). We do **not** blocklist `curl/`, `python-*`, or `Mozilla/*` — those are commonly used by legitimate community server-list scrapers (fivemservers.net, trackyserver, etc.) and blocking them would delist the server. Attackers using those UAs are caught by the per-IP GET rate limit instead.
- **IPv4 only.** Sockops filters on `AF_INET`. If FiveM binds dual-stack (`::`), v4-mapped-v6 connections skip the filter — bind `0.0.0.0` explicitly on the FiveM side. IPv6 is future work.
- **No UDP payload signatures.** Gameplay UDP is ENet-framed; specific attack payloads seen in the wild could be dropped with additional XDP matching — future work.
- **Dev-VM XDP mode.** OrbStack's virtio-net NIC supports native XDP on recent kernels; older kernels or alternative VM tools may fall back to generic XDP (post-`skb` alloc, functionally correct but gives up most of the DDoS perf benefit). The loader auto-falls-back and logs which mode attached. Deploy on bare metal or a virtio-net host with native XDP support for production numbers.

## Troubleshooting

- **`sockops: attach failed: permission denied`** — cgroup v2 must be mounted at `--cgroup` (default `/sys/fs/cgroup`). Check with `mount | grep cgroup2`.
- **`attach xdp: native: <err>; generic: <err>`** — neither mode attached. Check `ip link show <iface>` for existing XDP programs and detach first with `ip link set dev <iface> xdpgeneric off`.
- **L7 match never fires.** Verify the client actually sends `User-Agent: CitizenFX/1` (use `tcpdump -A -i eth1 'tcp port 30120'` and check the first segment of the `POST /client` request). If a reverse proxy or TLS terminator sits in front of FXServer, the filter won't see the plaintext — attach on the real frontend NIC.
- **Maps survive reload but not reboot.** The pin at `/sys/fs/bpf/fivem/` persists across `run` restarts. A reboot clears it — LRU state wouldn't survive a kernel restart anyway.
- **`sockops` doesn't seem to fire.** If FiveM runs in a container with its own cgroup namespace, attach to the container's cgroup path instead of the root. Verify with `cat /proc/<fivem-pid>/cgroup`.
