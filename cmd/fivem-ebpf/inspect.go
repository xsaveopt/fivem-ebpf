package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func cmdInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	pinPath := fs.String("pin-path", defaultPinPath, pinPathHelp)
	watch := fs.Duration("watch", 0, "repeat every N (e.g. 1s); 0 = run once")
	_ = fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: fivem-ebpf inspect <ipv4> [--watch 1s]")
		os.Exit(2)
	}
	addr := fs.Arg(0)
	key, err := parseIPv4Key(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	dump := func() {
		now, err := bpfmaps.BootTimeNS()
		if err != nil {
			fmt.Fprintln(os.Stderr, "inspect:", err)
			os.Exit(1)
		}
		fmt.Printf("IP %s\n", addr)
		inspectTimestamp(*pinPath, bpfmaps.Whitelist, key, now)
		inspectTimestamp(*pinPath, bpfmaps.Established, key, now)
		inspectTimestamp(*pinPath, bpfmaps.SynSeen, key, now)
		inspectCount(*pinPath, bpfmaps.OpenCount, key)
		inspectRatelimit(*pinPath, bpfmaps.UDPRatelimit, key, now)
		inspectRatelimit(*pinPath, bpfmaps.InitConnectRatelimit, key, now)
		inspectRatelimit(*pinPath, bpfmaps.GetInfoRatelimit, key, now)
		inspectHealth(*pinPath, bpfmaps.Health, key, now)
		inspectDropHistory(*pinPath, bpfmaps.DropHistoryMap, key, now)
	}

	if *watch == 0 {
		dump()
		return
	}
	for {
		fmt.Print("\x1b[H\x1b[2J")
		fmt.Printf("# fivem-ebpf inspect %s (refresh %s)\n", time.Now().Format(time.TimeOnly), *watch)
		dump()
		time.Sleep(*watch)
	}
}

const inspectLabelWidth = 22

func inspectLine(name, body string) {
	fmt.Printf("  %-*s %s\n", inspectLabelWidth, name, body)
}

func lookupInto(pinPath, name string, key [4]byte, out any) bool {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		inspectLine(name, fmt.Sprintf("(%v)", err))
		return false
	}
	defer func() { _ = m.Close() }()

	if err := m.Lookup(&key, out); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return false
	}
	return true
}

func inspectTimestamp(pinPath, name string, key [4]byte, now uint64) {
	var val uint64
	if !lookupInto(pinPath, name, key, &val) {
		return
	}
	inspectLine(name, fmt.Sprintf("age=%s", secs(ageSeconds(now, val))))
}

func inspectCount(pinPath, name string, key [4]byte) {
	var val uint64
	if !lookupInto(pinPath, name, key, &val) {
		return
	}
	inspectLine(name, fmt.Sprintf("count=%d", val))
}

func inspectRatelimit(pinPath, name string, key [4]byte, now uint64) {
	var val bpfmaps.Ratelimit
	if !lookupInto(pinPath, name, key, &val) {
		return
	}
	inspectLine(name, fmt.Sprintf("tokens=%d refill_age=%s",
		val.Tokens, secs(ageSeconds(now, val.LastRefillNS))))
}

func inspectHealth(pinPath, name string, key [4]byte, now uint64) {
	var val bpfmaps.UDPHealth
	if !lookupInto(pinPath, name, key, &val) {
		return
	}
	body := fmt.Sprintf("anomalies=%d window_age=%s",
		val.Anomalies, secs(ageSeconds(now, val.WindowStartNS)))
	if val.BlacklistUntilNS > now {
		body += fmt.Sprintf(" BLACKLISTED unblock_in=%s", secs(ageSeconds(val.BlacklistUntilNS, now)))
	} else {
		body += " blacklisted=no"
	}
	inspectLine(name, body)
}

func inspectDropHistory(pinPath, name string, key [4]byte, now uint64) {
	var val bpfmaps.DropHistory
	if !lookupInto(pinPath, name, key, &val) {
		return
	}
	total, by := dropCounts(val)
	parts := make([]string, 0, len(by))
	for _, reason := range bpfmaps.DropReasonNames {
		if c, ok := by[reason]; ok {
			parts = append(parts, fmt.Sprintf("%s=%d", reason, c))
		}
	}
	body := fmt.Sprintf("first=%s last=%s total=%d",
		secs(ageSeconds(now, val.FirstDropNS)), secs(ageSeconds(now, val.LastDropNS)), total)
	if len(parts) > 0 {
		body += " " + strings.Join(parts, ",")
	}
	inspectLine(name, body)
}
