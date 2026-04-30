package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sratabix/gameshield-ebpf/internal/module"
	_ "github.com/sratabix/gameshield-ebpf/internal/module/fivem"
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
	case "clear":
		cmdClear(args)
	case "inspect":
		cmdInspect(args)
	case "health":
		cmdHealth(args)
	case "-h", "--help", "help":
		usage()
	default:
		// Module-scoped subcommand: `gameshield <module> <verb> [args]`
		if len(args) >= 1 {
			if dispatchModuleSubcommand(os.Args[1], args[0], args[1:]) {
				return
			}
		}
		usage()
		os.Exit(2)
	}
}

// dispatchModuleSubcommand looks up `<modName> <verb>` against the registry.
// Returns true if it ran a subcommand (success or failure handled inside).
func dispatchModuleSubcommand(modName, verb string, args []string) bool {
	m, err := module.New(modName)
	if err != nil {
		return false
	}
	for _, sc := range m.Subcommands() {
		if sc.Name == verb {
			sc.Run(args)
			return true
		}
	}
	fmt.Fprintf(os.Stderr, "unknown verb for module %s: %s\n", modName, verb)
	fmt.Fprintln(os.Stderr, "available verbs:")
	for _, sc := range m.Subcommands() {
		fmt.Fprintf(os.Stderr, "  %s — %s\n", sc.Name, sc.Description)
	}
	os.Exit(2)
	return true
}

func usage() {
	fmt.Fprintln(os.Stderr, "gameshield-ebpf — modular XDP+sockops DDoS filter for game servers")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  gameshield run     --config FILE              daemon")
	fmt.Fprintln(os.Stderr, "  gameshield info    [--pin-root PATH]          dispatcher overview")
	fmt.Fprintln(os.Stderr, "  gameshield dump    --map M                    dump a shared per-IP map")
	fmt.Fprintln(os.Stderr, "  gameshield clear   --map M [--ip A]           clear a shared map (or one IP)")
	fmt.Fprintln(os.Stderr, "  gameshield inspect <ipv4>                     all per-IP shared state for one IP")
	fmt.Fprintln(os.Stderr, "  gameshield health  [--all]                    blacklisted IPs")
	fmt.Fprintln(os.Stderr, "  gameshield <module> <verb> [args]             module-scoped verbs")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Shared maps (M): whitelist | established | syn-seen | open-count | udp-ratelimit | health")
	fmt.Fprintln(os.Stderr, "")
	names := module.Names()
	sort.Strings(names)
	if len(names) > 0 {
		fmt.Fprintln(os.Stderr, "Compiled-in modules:")
		for _, n := range names {
			m, _ := module.New(n)
			verbs := []string{}
			for _, sc := range m.Subcommands() {
				verbs = append(verbs, sc.Name)
			}
			fmt.Fprintf(os.Stderr, "  %s — verbs: %s\n", n, strings.Join(verbs, ", "))
		}
	}
}
