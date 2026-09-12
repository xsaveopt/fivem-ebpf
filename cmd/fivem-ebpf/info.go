package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

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

func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	pinPath := fs.String("pin-path", defaultPinPath, pinPathHelp)
	_ = fs.Parse(args)

	fmt.Printf("fivem-ebpf %s\n", version)
	fmt.Printf("  pin path: %s\n", *pinPath)

	if _, err := os.Stat(*pinPath); err != nil {
		fmt.Fprintln(os.Stderr, "  (no pinned maps, daemon not running?)")
		os.Exit(1)
	}

	stats, err := bpfmaps.Open(*pinPath, bpfmaps.Stats)
	if err != nil {
		fmt.Fprintln(os.Stderr, " ", err)
	} else {
		defer func() { _ = stats.Close() }()
		vals, err := bpfmaps.ReadStats(stats)
		if err != nil {
			fmt.Fprintln(os.Stderr, " ", err)
		} else {
			byLabel := map[string]uint64{}
			for i, lbl := range bpfmaps.StatLabels {
				byLabel[lbl] = vals[i]
			}
			var dropTCP, dropUDP uint64
			for lbl, v := range byLabel {
				switch {
				case strings.HasPrefix(lbl, "drop_tcp_"):
					dropTCP += v
				case strings.HasPrefix(lbl, "drop_udp_"):
					dropUDP += v
				case lbl == "drop_malformed":
					dropTCP += v
				}
			}
			fmt.Printf("  tcp: %d pass / %d drop\n", byLabel["pass_tcp"], dropTCP)
			fmt.Printf("  udp: %d pass / %d drop\n", byLabel["pass_udp_whitelisted"], dropUDP)
			fmt.Printf("  ip fragments dropped: %d\n", byLabel["drop_ip_fragment"])
		}
	}

	fmt.Println("  map populations:")
	for _, name := range bpfmaps.PerIP {
		n, err := mapEntryCount(*pinPath, name)
		if err != nil {
			fmt.Printf("    %-22s (%v)\n", name, err)
			continue
		}
		fmt.Printf("    %-22s %d\n", name, n)
	}
	if bl, err := blacklistedNow(*pinPath); err == nil {
		fmt.Printf("    %-22s %d\n", "udp_health (blacklisted)", bl)
	}
}
