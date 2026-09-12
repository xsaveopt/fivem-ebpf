package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func cmdDump(args []string) {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	pinPath := fs.String("pin-path", defaultPinPath, pinPathHelp)
	which := fs.String("map", "whitelist", "which map to dump: "+bpfmaps.CLINamesHelp+" | all")
	_ = fs.Parse(args)

	if *which == "all" {
		for _, name := range bpfmaps.PerIP {
			fmt.Printf("== %s ==\n", name)
			dumpMap(*pinPath, name)
			fmt.Println()
		}
		return
	}

	name, ok := bpfmaps.CLIName[*which]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown map: %s (one of %s | all)\n", *which, bpfmaps.CLINamesHelp)
		os.Exit(2)
	}
	dumpMap(*pinPath, name)
}

func dumpMap(pinPath, name string) {
	var err error
	switch name {
	case bpfmaps.Whitelist, bpfmaps.Established, bpfmaps.SynSeen:
		err = dumpTimestampMap(pinPath, name)
	case bpfmaps.OpenCount:
		err = dumpCountMap(pinPath, name)
	case bpfmaps.UDPRatelimit, bpfmaps.InitConnectRatelimit, bpfmaps.GetInfoRatelimit:
		err = dumpRatelimitMap(pinPath, name)
	case bpfmaps.Health:
		err = dumpHealthMap(pinPath, name)
	case bpfmaps.DropHistoryMap:
		err = dumpDropHistoryMap(pinPath, name)
	default:
		err = fmt.Errorf("no dump format for %s", name)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dump:", err)
	}
}

func secs(n int64) time.Duration { return time.Duration(n) * time.Second }

func dumpTimestampMap(pinPath, name string) error {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		return err
	}
	fmt.Printf("%-16s %-12s\n", "IP", "AGE")
	var key [4]byte
	var val uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		fmt.Printf("%-16s %-12s\n", ipv4Str(key), secs(ageSeconds(now, val)))
	}
	return iter.Err()
}

func dumpCountMap(pinPath, name string) error {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	fmt.Printf("%-16s %-10s\n", "IP", "OPEN")
	var key [4]byte
	var val uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		fmt.Printf("%-16s %-10d\n", ipv4Str(key), val)
	}
	return iter.Err()
}

func dumpRatelimitMap(pinPath, name string) error {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		return err
	}
	fmt.Printf("%-16s %-10s %-12s\n", "IP", "TOKENS", "LAST_REFILL")
	var key [4]byte
	var val bpfmaps.Ratelimit
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		fmt.Printf("%-16s %-10d %-12s\n", ipv4Str(key), val.Tokens, secs(ageSeconds(now, val.LastRefillNS)))
	}
	return iter.Err()
}

func dumpHealthMap(pinPath, name string) error {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		return err
	}
	fmt.Printf("%-16s %-10s %-12s %-12s\n", "IP", "ANOMALIES", "WINDOW_AGE", "BLACKLIST")
	var key [4]byte
	var val bpfmaps.UDPHealth
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		bl := "-"
		if val.BlacklistUntilNS > now {
			bl = "in " + secs(ageSeconds(val.BlacklistUntilNS, now)).String()
		}
		fmt.Printf("%-16s %-10d %-12s %-12s\n",
			ipv4Str(key), val.Anomalies, secs(ageSeconds(now, val.WindowStartNS)), bl)
	}
	return iter.Err()
}

func dumpDropHistoryMap(pinPath, name string) error {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		return err
	}
	fmt.Printf("%-16s %-12s %-12s %-10s %s\n", "IP", "FIRST_AGE", "LAST_AGE", "TOTAL", "BY_REASON")
	var key [4]byte
	var val bpfmaps.DropHistory
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		total, by := dropCounts(val)
		parts := make([]string, 0, len(by))
		for _, reason := range bpfmaps.DropReasonNames {
			if c, ok := by[reason]; ok {
				parts = append(parts, fmt.Sprintf("%s=%d", reason, c))
			}
		}
		fmt.Printf("%-16s %-12s %-12s %-10d %s\n",
			ipv4Str(key),
			secs(ageSeconds(now, val.FirstDropNS)),
			secs(ageSeconds(now, val.LastDropNS)),
			total,
			strings.Join(parts, ","))
	}
	return iter.Err()
}
