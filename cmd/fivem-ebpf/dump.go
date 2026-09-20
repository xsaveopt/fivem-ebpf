package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

type dumpOpts struct {
	pinPath string
	which   string
}

func parseDumpFlags(args []string) (dumpOpts, error) {
	var o dumpOpts
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	fs.StringVar(&o.pinPath, "pin-path", defaultPinPath, pinPathHelp)
	fs.StringVar(&o.which, "map", "whitelist", "which map to dump: "+bpfmaps.CLINamesHelp+" | all")
	return o, fs.Parse(args)
}

func cmdDump(args []string) {
	o, err := parseDumpFlags(args)
	if err != nil {
		exitFlagError(err)
	}

	targets, err := resolveMapTargets(o.which)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	for _, name := range targets {
		if len(targets) > 1 {
			fmt.Printf("== %s ==\n", name)
		}
		if err := dumpNamedMap(os.Stdout, o.pinPath, name); err != nil {
			fmt.Fprintln(os.Stderr, "dump:", err)
		}
		if len(targets) > 1 {
			fmt.Println()
		}
	}
}

type dumpRenderer func(w io.Writer, m bpfmaps.Reader, now uint64) error

func dumpRendererFor(name string) (dumpRenderer, error) {
	switch name {
	case bpfmaps.Whitelist, bpfmaps.Established, bpfmaps.SynSeen:
		return writeTimestampDump, nil
	case bpfmaps.OpenCount:
		return writeCountDump, nil
	case bpfmaps.UDPRatelimit, bpfmaps.InitConnectRatelimit, bpfmaps.GetInfoRatelimit:
		return writeRatelimitDump, nil
	case bpfmaps.Health:
		return writeHealthDump, nil
	case bpfmaps.DropHistoryMap:
		return writeDropHistoryDump, nil
	}
	return nil, fmt.Errorf("no dump format for %s", name)
}

func dumpNamedMap(w io.Writer, pinPath, name string) error {
	render, err := dumpRendererFor(name)
	if err != nil {
		return err
	}
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		return err
	}
	return render(w, bpfmaps.Map{M: m}, now)
}

func secs(n int64) time.Duration { return time.Duration(n) * time.Second }

func writeTimestampDump(w io.Writer, m bpfmaps.Reader, now uint64) error {
	outf(w, "%-16s %-12s\n", "IP", "AGE")
	var key [4]byte
	var val uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		outf(w, "%-16s %-12s\n", ipv4Str(key), secs(ageSeconds(now, val)))
	}
	return iter.Err()
}

func writeCountDump(w io.Writer, m bpfmaps.Reader, _ uint64) error {
	outf(w, "%-16s %-10s\n", "IP", "OPEN")
	var key [4]byte
	var val uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		outf(w, "%-16s %-10d\n", ipv4Str(key), val)
	}
	return iter.Err()
}

func writeRatelimitDump(w io.Writer, m bpfmaps.Reader, now uint64) error {
	outf(w, "%-16s %-10s %-12s\n", "IP", "TOKENS", "LAST_REFILL")
	var key [4]byte
	var val bpfmaps.Ratelimit
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		outf(w, "%-16s %-10d %-12s\n", ipv4Str(key), val.Tokens, secs(ageSeconds(now, val.LastRefillNS)))
	}
	return iter.Err()
}

func writeHealthDump(w io.Writer, m bpfmaps.Reader, now uint64) error {
	outf(w, "%-16s %-10s %-12s %-12s\n", "IP", "ANOMALIES", "WINDOW_AGE", "BLACKLIST")
	var key [4]byte
	var val bpfmaps.UDPHealth
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		bl := "-"
		if val.BlacklistUntilNS > now {
			bl = "in " + secs(ageSeconds(val.BlacklistUntilNS, now)).String()
		}
		outf(w, "%-16s %-10d %-12s %-12s\n",
			ipv4Str(key), val.Anomalies, secs(ageSeconds(now, val.WindowStartNS)), bl)
	}
	return iter.Err()
}

func writeDropHistoryDump(w io.Writer, m bpfmaps.Reader, now uint64) error {
	outf(w, "%-16s %-12s %-12s %-10s %s\n", "IP", "FIRST_AGE", "LAST_AGE", "TOTAL", "BY_REASON")
	var key [4]byte
	var val bpfmaps.DropHistory
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		total, by := dropCounts(val)
		outf(w, "%-16s %-12s %-12s %-10d %s\n",
			ipv4Str(key),
			secs(ageSeconds(now, val.FirstDropNS)),
			secs(ageSeconds(now, val.LastDropNS)),
			total,
			strings.Join(dropReasonParts(by), ","))
	}
	return iter.Err()
}

func dropReasonParts(by map[string]uint64) []string {
	parts := make([]string, 0, len(by))
	for _, reason := range bpfmaps.DropReasonNames {
		if c, ok := by[reason]; ok {
			parts = append(parts, fmt.Sprintf("%s=%d", reason, c))
		}
	}
	return parts
}
