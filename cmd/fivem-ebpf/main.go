package main

import (
	"fmt"
	"os"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

var version = "dev"

const (
	defaultPinPath = "/sys/fs/bpf/fivem"
	pinPathHelp    = "bpf map pin directory (must match PIN_PATH in the daemon config)"
)

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
	case "unpin":
		cmdUnpin(args)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	for _, line := range []string{
		"fivem-ebpf " + version + " — XDP + sockops DDoS filter for FiveM",
		"",
		"Usage:",
		"  fivem-ebpf run     [flags]                 daemon (see --help)",
		"  fivem-ebpf info                            daemon overview: counters + map sizes",
		"  fivem-ebpf stats   [--json] [--watch 1s]   per-CPU stat counters",
		"  fivem-ebpf top     --map M [-n 10]         hottest IPs in a per-IP map",
		"  fivem-ebpf inspect <ipv4> [--watch 1s]     all per-IP state for one address",
		"  fivem-ebpf dump    --map M | all           dump a per-IP map",
		"  fivem-ebpf health  [--all]                 currently-blacklisted IPs (--all: include tracked-but-not-banned)",
		"  fivem-ebpf clear   --map M | all [--ip A]  wipe a map, or one IP from it",
		"  fivem-ebpf unpin   --yes                   remove the pin directory (drops every session)",
		"",
		"M is one of: " + bpfmaps.CLINamesHelp + ".",
		"dump and clear also accept `all`; top and inspect do not.",
		"",
		"Every subcommand reads the pinned maps directly and needs root, or CAP_BPF.",
		"Pass --pin-path if the daemon runs with a PIN_PATH other than " + defaultPinPath + ".",
	} {
		fmt.Fprintln(os.Stderr, line)
	}
}
