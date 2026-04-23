package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "run":
		cmdRun(args)
	case "dump":
		cmdDump(args)
	case "stats":
		cmdStats(args)
	case "clear":
		cmdClear(args)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "fivem-ebpf — XDP + sockops DDoS filter for FiveM")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf run     --iface eth0 [--port 30120] [--ttl 10m] [--metrics-addr :9464]")
	fmt.Fprintln(os.Stderr, "                     [--cgroup /sys/fs/cgroup] [--pin-path /sys/fs/bpf/fivem]")
	fmt.Fprintln(os.Stderr, "                     [--udp-rate 1500] [--udp-burst 4500]")
	fmt.Fprintln(os.Stderr, "                     [--tcp-initconnect-per-min 6] [--tcp-initconnect-burst 3]")
	fmt.Fprintln(os.Stderr, "                     [--tcp-getinfo-per-min 6] [--tcp-getinfo-burst 5]")
	fmt.Fprintln(os.Stderr, "                     [--health-window 10s] [--health-threshold 20] [--health-blacklist 5m]")
	fmt.Fprintln(os.Stderr, "                     [--map-size-interval 30s]")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf dump    [--map whitelist|established|udp-ratelimit|initconnect-ratelimit|getinfo-ratelimit|health|all]")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf stats   [--pin-path /sys/fs/bpf/fivem]")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf clear   [--map whitelist|established|udp-ratelimit|initconnect-ratelimit|getinfo-ratelimit|health|all]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "KNOWN LIMITATION: IP-whitelist gating does not stop attackers who can")
	fmt.Fprintln(os.Stderr, "spoof UDP source IP of a legitimate client. Real fix is protocol-level")
	fmt.Fprintln(os.Stderr, "authentication in the FiveM UDP handshake — out of scope for v0.")
}
