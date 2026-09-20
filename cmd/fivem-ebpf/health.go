package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

type healthOpts struct {
	pinPath string
	all     bool
}

func parseHealthFlags(args []string) (healthOpts, error) {
	var o healthOpts
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	fs.StringVar(&o.pinPath, "pin-path", defaultPinPath, pinPathHelp)
	fs.BoolVar(&o.all, "all", false, "include IPs that have anomalies but aren't blacklisted")
	return o, fs.Parse(args)
}

func cmdHealth(args []string) {
	o, err := parseHealthFlags(args)
	if err != nil {
		exitFlagError(err)
	}

	if err := printHealth(o.pinPath, o.all); err != nil {
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
	return writeHealthTable(os.Stdout, bpfmaps.Map{M: m}, now, all)
}

func writeHealthTable(w io.Writer, m bpfmaps.Reader, now uint64, all bool) error {
	outf(w, "%-16s %-10s %-12s %s\n", "IP", "ANOMALIES", "WINDOW_AGE", "BLACKLIST")

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
		outf(w, "%-16s %-10d %-12s %s\n",
			ipv4Str(key), val.Anomalies, secs(ageSeconds(now, val.WindowStartNS)), bl)
	}
	return iter.Err()
}
