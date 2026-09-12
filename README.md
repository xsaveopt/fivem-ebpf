# fivem-ebpf

A FiveM game server listens on a single port, 30120, for both TCP and UDP, and that combination is what makes it easy to attack.
The TCP side answers HTTP-style requests, including a handful of endpoints that return several kilobytes of JSON to a request of a couple of hundred bytes, and the UDP side carries the actual gameplay traffic, which anyone can send to whether they have joined or not.
fivem-ebpf sits in front of that port as an XDP program, so packets it rejects are dropped in the network driver before the kernel builds a socket buffer for them, and a flood costs the machine far less than it would if iptables or the game server itself had to answer.

The idea it is built around is that UDP is only allowed from an address that has completed a real TCP handshake and sent a real FiveM connect request.
Everything else is a rate limit or a structural check layered on top of that.
It is a self-hosted daemon that you install on the game server itself, it exports Prometheus metrics for every verdict it reaches, and it ships two Grafana dashboards for reading them.

## Contents

- [How the filter works](#how-the-filter-works)
- [Requirements](#requirements)
- [Installing](#installing)
- [Configuration](#configuration)
- [Using the CLI](#using-the-cli)
- [Metrics and the API](#metrics-and-the-api)
- [What this does not do](#what-this-does-not-do)
- [Operational pitfalls](#operational-pitfalls)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

## How the filter works

State comes from three places, and the order matters.
A sock_ops program attached to the cgroup records the client address in tcp_established when the kernel itself reports a completed three-way handshake on the game port, which is a fact about the connection rather than a guess from packet contents, and the same program keeps a count of how many sockets each address currently holds open.
The XDP program watches for the connect request on the wire, and when it sees POST /client carrying a User-Agent of CitizenFX/1 from an address the kernel has confirmed, it promotes that address into tcp_whitelist.
Passed UDP packets then refresh the whitelist timestamp, so an address stays valid as long as the player keeps playing and falls out after the TTL once they stop.

On the TCP side, a segment that is not a SYN and comes from an address with neither SYN history nor an established socket is dropped outright, which is the same filter as the iptables rule most operators reach for first.
A SYN is checked against the per-IP open-connection cap and the new-connection circuit breaker before anything else happens.
Segments carrying POST /client or one of the JSON endpoints then go through their own per-IP token buckets, and a bare CitizenFX User-Agent with no version suffix is dropped on sight, since real clients always send the version and that exact string showed up throughout a real captured attack.
Being whitelisted skips the SYN-history check, because an address that is mid-session has obviously connected before, but it does not exempt anyone from the rate limits, so a single compromised host that joined legitimately cannot then hammer the join path.

On the UDP side, a packet from an address that is not whitelisted is dropped, and so is one whose whitelist entry has expired.
What survives that is checked for ENet structure, since a random-byte flood does not parse as a valid command, and an address that fails the check often enough within the health window is blocked for a while.
Out-of-band packets, the ones prefixed with four 0xff bytes, and packets ENet has compressed both skip the structural check, because in neither case is there a readable command byte where the parser would look.
Whatever is left goes through the per-IP gameplay rate limit and is passed.

IP fragments addressed to the game port are dropped rather than parsed, because FiveM never sends them and reassembling them would be a way to walk past every check above.
Fragments for any other port are left alone.

## Requirements

Running the released binary needs Linux 5.17 or newer with BTF compiled in, meaning /sys/kernel/btf/vmlinux exists, cgroup v2 mounted, and bpffs available at /sys/fs/bpf, which the installer mounts if it is missing.
It runs as root through systemd and holds CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON and CAP_SYS_RESOURCE.
The binary is statically linked and carries the compiled BPF objects inside it, so nothing else needs installing on the server.

Building from source additionally needs clang, llvm, the libbpf and libelf headers, bpftool, and the Go toolchain named in go.mod, all on a Linux machine.
The Development section below covers how that is set up, including the VM workflow used from macOS.

## Installing

Download the zip for your architecture from the [releases page](https://github.com/xsaveopt/fivem-ebpf/releases), check it against its published checksum, and run the installer out of the unpacked directory.

```sh
VERSION=v0.1.0
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -sfLO "https://github.com/xsaveopt/fivem-ebpf/releases/download/$VERSION/fivem-ebpf-$VERSION-linux-$ARCH.zip"
curl -sfLO "https://github.com/xsaveopt/fivem-ebpf/releases/download/$VERSION/fivem-ebpf-$VERSION-linux-$ARCH.zip.sha256"
sha256sum -c "fivem-ebpf-$VERSION-linux-$ARCH.zip.sha256"
unzip -d fivem-ebpf-$VERSION "fivem-ebpf-$VERSION-linux-$ARCH.zip"
cd fivem-ebpf-$VERSION && sudo sh install.sh
```

The installer refuses to run if the zip was built for a different architecture, if the kernel is too old, or if BTF or cgroup v2 are missing, so a host that cannot run this says so before anything is written.
Then set the interface, since the default of eth0 is wrong on most machines, and start the service.

```sh
sudo vim /etc/fivem-ebpf/config
sudo systemctl enable --now fivem-ebpf
sudo systemctl status fivem-ebpf
```

Every setting in that file is covered under Configuration below, and fivem-ebpf run --help prints the same list with its defaults.
The zip also carries the systemd unit, the config template, and the two Grafana dashboards, which land in /etc/fivem-ebpf/grafana for you to import.

Upgrading is the same command from the new zip.
The installer stops the service, clears the pinned maps because their shape can change between releases, installs the new files, appends any config keys the release has added with their defaults, restarts, and then checks that the daemon actually came back rather than assuming it did.
Removing everything again is install.sh --uninstall, which stops the service, deletes the binary, the unit, the config directory and the pin directory, and reminds you that traffic is unfiltered from that moment.

## Configuration

Settings live in /etc/fivem-ebpf/config, which systemd reads as an EnvironmentFile and turns into flags on the run command line.
The unit passes every key unconditionally, so a key you delete or comment out expands to nothing and the daemon sees a flag with no value; change the value rather than removing the line, and switch a limit off by setting it to the value that disables it.

IFACE is the interface XDP attaches to, and the default of eth0 is wrong on most hosts, so find yours with ip -br link and pick the one traffic actually arrives on.
PORT is the game port, 30120, covering both TCP and UDP, and everything else on the interface passes untouched.
CGROUP_PATH is where the sockops program attaches; a containerised FXServer lives in its own cgroup, which you can read out of /proc/<fxserver-pid>/cgroup, and pointing this at the wrong place means no handshake is ever reported and nobody is whitelisted.
PIN_PATH is where the maps are pinned, and since every subcommand reads them directly, moving it means passing --pin-path to all of them.

The per-IP limits are token buckets, a refill rate plus a burst, and setting either half of a pair to 0 turns that limit off.
UDP_RATE and UDP_BURST govern gameplay traffic from a whitelisted address, and at 1500 per second with a burst of 4500 they leave wide margin over the roughly 60 packets a second a player actually sends.
INITCONNECT_PER_MIN and INITCONNECT_BURST limit how often one address may send a connect request, where three back to back covers an honest retry.
GETINFO_PER_MIN and GETINFO_BURST limit the JSON endpoints, which return several kilobytes against a request of a couple of hundred bytes and are what an amplification attack is really after.

TCP_GLOBAL_RATE and TCP_GLOBAL_BURST are a circuit breaker on new connections, applying only to SYNs from addresses that are not already whitelisted, so a flood of connection attempts is capped while players who have joined keep reconnecting.
The bucket is per CPU and the figure you set is split across the online CPUs, so the aggregate matches.
TCP_MAX_OPEN_PER_IP drops new SYNs from an address already holding that many open sockets, which is what catches bots that complete the handshake and then say nothing; a real client holds four to eight parallel asset downloads plus TIME_WAIT residue, which is where 16 comes from.

HEALTH_WINDOW, HEALTH_THRESHOLD and HEALTH_BLACKLIST control the structural check on UDP payloads: a packet from a whitelisted address that does not parse as ENet counts as an anomaly, and an address that accumulates the threshold within the window is blocked for the blacklist duration.
Compressed and out-of-band packets are exempt, since neither has a readable command byte where the parser looks.
Use fivem-ebpf health --all to see who is climbing towards the threshold before anyone is actually blocked.

METRICS_ADDR defaults to loopback for the reasons in Metrics and the API.
MAP_SIZE_INTERVAL is how often the map population gauges are recalculated, which means walking maps holding up to 100000 keys, so set it to 0 to switch those gauges off on a busy server and the cheap packet counters keep working.
DROP_HISTORY records per-IP drop counts by reason, the data behind inspect and /api/ip, and entries are only created for addresses the filter already knows, so a spoofed-source flood does not churn the map.

## Using the CLI

```
fivem-ebpf run     [flags]                 attach the programs, serve /metrics and /api
fivem-ebpf info                            counters and map populations
fivem-ebpf stats   [--json] [--watch 1s]   raw counters
fivem-ebpf top     --map M [-n 10]         busiest addresses in one map
fivem-ebpf inspect <ipv4> [--watch 1s]     every map's view of one address
fivem-ebpf dump    --map M | all           full listing of a map
fivem-ebpf health  [--all]                 blocked addresses, or everything tracked
fivem-ebpf clear   --map M | all [--ip A]  wipe a map, or one address from it
fivem-ebpf unpin   --yes                   remove the pin directory
```

M is one of whitelist, established, syn-seen, open-count, udp-ratelimit, initconnect-ratelimit, getinfo-ratelimit, health or drop-history.
Only dump and clear also take all.
When ranking drop-history, --reason narrows the ranking to a single cause, and the names it accepts are the ones the drop history uses, such as udp_not_whitelisted or tcp_too_many_open, which are spelled differently from the reason labels on the Prometheus counters.

These subcommands read the pinned maps directly rather than talking to the daemon over HTTP, which means they work when the metrics port is unreachable, and it also means they need root or CAP_BPF.
If you moved PIN_PATH away from the default they need --pin-path pointed at the same place, or they will find nothing and say so.

inspect is the one to reach for when a player reports they cannot join.
It prints where their address stands in every map at once, including the cumulative count of drops by reason, which usually names the problem outright.

## Metrics and the API

The daemon serves Prometheus metrics at /metrics and a small read-only JSON API under /api on METRICS_ADDR, which defaults to 127.0.0.1:9464.
The main series is fivem_xdp_packets_total, labelled by verdict, protocol and reason, alongside counters for each stage of the join funnel, gauges for map populations and the current blacklist size, and fivem_build_info and fivem_attached for the state of the daemon itself.
Labels are kept low cardinality, with no address ever appearing in one.

The API is where per-address detail lives, and /api/state lists what is available.
/api/whitelist, /api/established, /api/syn-seen, /api/open-count, /api/blacklist and /api/health return one map each, /api/drop-history returns cumulative drops per address grouped by reason, /api/top ranks a single map, and /api/ip/<addr> gathers every map's view of one address into a single object.

That data is the address of every connected player, and there is no authentication in front of it, which is why the listener binds to loopback out of the box and the daemon logs a warning if you point it somewhere else.
Exposing it to a Prometheus server on another host means opening the port deliberately and firewalling it to that host.

Both dashboards are in the release zip and are installed under /etc/fivem-ebpf/grafana.
The main one reads Prometheus and has a daemon selector at the top, which matters when a multi-homed host runs one daemon per interface.
The per-address one reads the API directly and needs the [Infinity datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) plugin pointed at the metrics address.

## What this does not do

There is no cryptographic authentication of packets, so a whitelisted address is bounded by the ENet check and the per-IP rate limits and nothing else.
A botnet of many addresses that each complete a real handshake can collectively push a lot of well-formed traffic, and per-IP scoring is the direction that would need to go.

The layer 7 match is a byte pattern, the same thing an iptables string match does, so an attacker who opens a real TCP connection and sends a correctly formed POST /client with the right User-Agent gets through.
What this buys is the speed of rejecting everything else, not a new security property.

The bad User-Agent rule is deliberately narrow, matching only the literal bare CitizenFX with no version, because ordinary tools like curl and browsers are legitimate visitors to the JSON endpoints, and the per-IP rate limit is what handles abusive scraping.

Only IPv4 is filtered.
The sockops program reads remote_ip4 and the maps are keyed on four bytes, so a server reachable over native IPv6 is unprotected on that path, and binding FXServer to 0.0.0.0 rather than :: is the way to avoid that.
VLAN-tagged frames are unwrapped, up to two tags deep, before the IP header is read.

XDP attaches in native mode where the driver supports it and falls back to generic mode otherwise.
Generic mode is correct but much slower, and the daemon logs which one it got.

## Operational pitfalls

A fresh install or an upgrade drops every active session.
install.sh clears the pin directory so map shapes can change between releases, which empties the whitelist, and the sockops program only seeds tcp_established when a new handshake completes, so players who are already connected never re-trigger it.
Their next connect request will not promote them and their gameplay traffic is dropped as not whitelisted until they fully reconnect.
Plan it for a quiet hour and expect everyone to rejoin at once.

A plain systemctl restart is cheap by comparison, because the pins survive and the new process picks up the existing whitelist, but only if the map shapes have not changed.
If you replaced the binary across a release boundary without going through the installer, the daemon will refuse to load and tell you to clear the pin directory, which brings the reconnect storm back.

Wiping the whitelist by hand has the same blast radius, so clear --map whitelist and clear --map all are the two commands not to run on a live server unless a mass reconnect is what you want.

Anything that collapses many players onto one source address defeats the per-IP limits.
NAT in front of the server, or a proxy that terminates TCP, makes every player look like one very busy address, and the PROXY protocol and X-Forwarded-For are not parsed.
Attach on the interface facing the internet, not behind a load balancer.

XDP is per interface, so traffic arriving on a NIC the daemon is not attached to is not filtered at all.
Asymmetric routing and multi-homed hosts need one daemon per ingress interface, and the daemon selector on the dashboard exists for exactly that case.

The whitelist TTL trims idle players.
Every passed packet refreshes it, but a session that goes quiet for longer than the TTL, through a long loading screen or a stretch of packet loss, falls out and comes back as expired.
Ten minutes suits most servers, and TTL is where you raise it.

When the daemon exits, for any reason including a crash or a kill, the XDP program detaches with it and traffic flows unfiltered.
Failing open is the right default for a game server, but it does mean the restart window is genuinely unprotected, and it also means the pinned maps outlive the filter: info, top, dump and inspect will keep printing plausible state from a filter that is no longer attached.
Check systemctl status, or the fivem_attached gauge, before trusting what they say.

For the same reason a stray foreground run left in a tmux pane will hold the pins and report itself as attached, which hides a service unit that failed to start.
pgrep -a fivem-ebpf settles who is actually running, and systemd-run --unit=fivem-dbg is a tidier way to do a one-off debug run.

## Troubleshooting

A sockops attach that fails with permission denied usually means cgroup v2 is not where the daemon is looking.
Check mount | grep cgroup2, and set CGROUP_PATH to the container's own cgroup if FXServer runs in one, which you can read out of /proc/<fxserver-pid>/cgroup.

An XDP attach that fails in both native and generic mode means another XDP program already owns the interface.
ip link set dev <iface> xdpgeneric off clears it.

If the layer 7 match never fires, confirm the client really is sending User-Agent: CitizenFX/1 with tcpdump -A -i <iface> 'tcp port 30120'.
A proxy in front of FXServer hides it, and so does attaching to the wrong interface.
The fivem_tcp_post_client_ua_unknown_total counter rising while promotions stay flat means the request was seen but no User-Agent was found in the part of it that gets scanned.

If players are dropped as not whitelisted despite connecting normally, look at the join funnel panel or the established inserts counter.
Established inserts staying at zero points at the sockops attach rather than anything on the XDP side.

## Development

Building means compiling two BPF C programs against the running kernel's own type information, so it only works on Linux and needs a kernel with BTF enabled.
From macOS that means a VM, and OrbStack is the one used here because it is arm64-native, handles XDP without special configuration, and mounts your home directory at the same path inside.

```sh
brew install --cask orbstack
orb create ubuntu:24.04 fivem-ebpf
orb run -m fivem-ebpf -w "$PWD" sudo bash scripts/provision.sh
```

provision.sh installs clang, llvm, the libbpf headers, bpftool at a pinned release, and the Go toolchain named in go.mod, taken from go.dev rather than the distribution archive, which is several releases behind.
After that, orb -m fivem-ebpf gives you a shell where the checkout is at the same path it has on the host.

make build regenerates bpf/vmlinux.h from the kernel BTF when it is missing, runs bpf2go over the two BPF sources, and builds into bin/fivem-ebpf, skipping the generation step when nothing it depends on has changed.
make check is gofmt, go vet, go test and golangci-lint, the same four the CI workflow runs.
The tests read the compiled BTF back out of the generated object and compare the C struct layouts and the two enums against the Go declarations, which is the one class of drift that has no runtime symptom.

Compiling cleanly is not the same as loading, since the verifier rejects programs clang is happy with, so CI loads both objects with bpftool and you can do the same:

```sh
sudo bpftool prog load internal/loader/fivemxdp_bpfel.o /sys/fs/bpf/check_xdp type xdp
sudo bpftool prog load internal/loader/fivemsockops_bpfel.o /sys/fs/bpf/check_sockops type sockops
sudo rm -f /sys/fs/bpf/check_xdp /sys/fs/bpf/check_sockops
```

Both BPF programs share bpf/shared/maps.h, so every map is declared in both objects even though sockops touches three, and that shared declaration is what lets userspace open one pin and see what either program wrote.
vmlinux.h and the bpf2go outputs are generated rather than committed, so a fresh clone cannot be built or vetted until make generate has run once somewhere with clang and bpftool.
Operator settings reach the programs as compile-time constants patched at load, not map lookups, which keeps them off the per-packet path, and the loader treats a constant it cannot find as fatal rather than silently keeping the compiled-in default.

## License

GPL-2.0, see LICENSE.
The BPF programs are GPL-licensed in their own right, which is what lets them call the GPL-only kernel helpers they use.
