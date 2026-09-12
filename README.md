# fivem-ebpf

An XDP filter for a FiveM server that only lets UDP through from addresses which have completed a real TCP handshake and sent a real connect request.

FiveM answers both TCP and UDP on port 30120, so the same filter covers the HTTP endpoints and the gameplay traffic.
Rejected packets are dropped in the network driver before the kernel builds a socket buffer for them, and every verdict is exported as a Prometheus metric.

## Installing

Download the zip for your architecture from the [releases page](https://github.com/xsaveopt/fivem-ebpf/releases) and run the installer out of the unpacked directory as root.

Then set IFACE in the config and enable the service.

Re-run install.sh from a newer zip to upgrade, or install.sh --uninstall to remove everything.
It needs Linux 5.17 or newer with BTF, cgroup v2, and a kernel whose driver supports XDP.

## Configuration

Settings live in /etc/fivem-ebpf/config and each key is explained in the file.
fivem-ebpf run --help prints the same list with its defaults, and fivem-ebpf on its own lists the subcommands for reading the filter's state.

/metrics and a read only JSON API under /api are served on METRICS_ADDR.
Two Grafana dashboards are installed under /etc/fivem-ebpf/grafana.

## License

GPL-2.0, see LICENSE.
