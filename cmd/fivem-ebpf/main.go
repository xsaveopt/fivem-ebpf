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
	case "info":
		cmdInfo(args)
	case "dump":
		cmdDump(args)
	case "stats":
		cmdStats(args)
	case "clear":
		cmdClear(args)
	case "inspect":
		cmdInspect(args)
	case "top":
		cmdTop(args)
	case "health":
		cmdHealth(args)
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
	fmt.Fprintln(os.Stderr, "  fivem-ebpf run     [flags]                 daemon (see --help)")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf info                            daemon overview: counters + map sizes")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf stats   [--json] [--watch 1s]   per-CPU stat counters")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf top     --map M [-n 10]         hottest IPs in a per-IP map")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf inspect <ipv4> [--watch 1s]     all per-IP state for one address")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf dump    --map M                 dump a per-IP map")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf health  [--all]                 currently-blacklisted IPs (--all: include tracked-but-not-banned)")
	fmt.Fprintln(os.Stderr, "  fivem-ebpf clear   --map M [--ip A]        wipe a map, or one IP from it")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "M is one of: whitelist, established, syn-seen, open-count, udp-ratelimit, initconnect-ratelimit, getinfo-ratelimit, health, all")
}
