package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func cmdHealth(args []string) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	pinPath := fs.String("pin-path", defaultPinPath, pinPathHelp)
	all := fs.Bool("all", false, "include IPs that have anomalies but aren't blacklisted")
	_ = fs.Parse(args)

	if err := printHealth(*pinPath, *all); err != nil {
		fmt.Fprintln(os.Stderr, "health:", err)
		os.Exit(1)
	}
}

func printHealth(pinPath string, all bool) error {
	m, err := bpfmaps.Open(pinPath, bpfmaps.Health)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		return err
	}
	fmt.Printf("%-16s %-10s %-12s %s\n", "IP", "ANOMALIES", "WINDOW_AGE", "BLACKLIST")

	var key [4]byte
	var val bpfmaps.UDPHealth
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		blacklisted := val.BlacklistUntilNS > now
		if !all && !blacklisted {
			continue
		}
		bl := "-"
		if blacklisted {
			bl = "in " + secs(ageSeconds(val.BlacklistUntilNS, now)).String()
		}
		fmt.Printf("%-16s %-10d %-12s %s\n",
			ipv4Str(key), val.Anomalies, secs(ageSeconds(now, val.WindowStartNS)), bl)
	}
	return iter.Err()
}
