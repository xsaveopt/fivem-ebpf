package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

type infoOpts struct {
	pinPath string
}

func parseInfoFlags(args []string) (infoOpts, error) {
	var o infoOpts
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	fs.StringVar(&o.pinPath, "pin-path", defaultPinPath, pinPathHelp)
	return o, fs.Parse(args)
}

func mapEntryCount(pinPath, name string) (int64, error) {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return -1, err
	}
	defer func() { _ = m.Close() }()
	return bpfmaps.CountKeys(m)
}

func blacklistedNow(pinPath string) (int64, error) {
	m, err := bpfmaps.Open(pinPath, bpfmaps.Health)
	if err != nil {
		return -1, err
	}
	defer func() { _ = m.Close() }()
	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		return -1, err
	}
	return countBlacklisted(bpfmaps.Map{M: m}, now)
}

func countBlacklisted(m bpfmaps.Reader, now uint64) (int64, error) {
	var n int64
	var key [4]byte
	var val bpfmaps.UDPHealth
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.BlacklistUntilNS > now {
			n++
		}
	}
	return n, iter.Err()
}

type statsSummary struct {
	passTCP     uint64
	dropTCP     uint64
	passUDP     uint64
	dropUDP     uint64
	ipFragments uint64
}

func summariseStats(vals []uint64) statsSummary {
	var s statsSummary
	for i, lbl := range bpfmaps.StatLabels {
		switch {
		case lbl == "pass_tcp":
			s.passTCP = vals[i]
		case lbl == "pass_udp_whitelisted":
			s.passUDP = vals[i]
		case lbl == "drop_ip_fragment":
			s.ipFragments = vals[i]
		case lbl == "drop_malformed", strings.HasPrefix(lbl, "drop_tcp_"):
			s.dropTCP += vals[i]
		case strings.HasPrefix(lbl, "drop_udp_"):
			s.dropUDP += vals[i]
		}
	}
	return s
}

func writeStatsSummary(w io.Writer, s statsSummary) {
	outf(w, "  tcp: %d pass / %d drop\n", s.passTCP, s.dropTCP)
	outf(w, "  udp: %d pass / %d drop\n", s.passUDP, s.dropUDP)
	outf(w, "  ip fragments dropped: %d\n", s.ipFragments)
}

func cmdInfo(args []string) {
	o, err := parseInfoFlags(args)
	if err != nil {
		exitFlagError(err)
	}

	fmt.Printf("fivem-ebpf %s\n", version)
	fmt.Printf("  pin path: %s\n", o.pinPath)

	if _, err := os.Stat(o.pinPath); err != nil {
		fmt.Fprintln(os.Stderr, "  (no pinned maps, daemon not running?)")
		os.Exit(1)
	}

	stats, err := bpfmaps.Open(o.pinPath, bpfmaps.Stats)
	if err != nil {
		fmt.Fprintln(os.Stderr, " ", err)
	} else {
		defer func() { _ = stats.Close() }()
		vals, err := bpfmaps.ReadStats(stats)
		if err != nil {
			fmt.Fprintln(os.Stderr, " ", err)
		} else {
			writeStatsSummary(os.Stdout, summariseStats(vals))
		}
	}

	fmt.Println("  map populations:")
	for _, name := range bpfmaps.PerIP {
		n, err := mapEntryCount(o.pinPath, name)
		if err != nil {
			fmt.Printf("    %-22s (%v)\n", name, err)
			continue
		}
		fmt.Printf("    %-22s %d\n", name, n)
	}
	if bl, err := blacklistedNow(o.pinPath); err == nil {
		fmt.Printf("    %-22s %d\n", "udp_health (blacklisted)", bl)
	}
}
