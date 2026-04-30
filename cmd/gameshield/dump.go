package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"

	"github.com/sratabix/gameshield-ebpf/internal/pinpath"
)

// cmdDump dumps shared per-IP core maps. Module-private maps go through
// `gameshield <module> dump-...` instead.
func cmdDump(args []string) {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	pinRoot := fs.String("pin-root", pinpath.DefaultRoot, "gameshield bpf pin root")
	which := fs.String("map", "whitelist", "whitelist|established|syn-seen|open-count|udp-ratelimit|health|all")
	_ = fs.Parse(args)

	core := pinpath.Core(*pinRoot)
	switch *which {
	case "whitelist":
		dumpTimestampMap(core, "tcp_whitelist")
	case "established":
		dumpTimestampMap(core, "tcp_established")
	case "syn-seen":
		dumpTimestampMap(core, "tcp_syn_seen")
	case "open-count":
		dumpCountMap(core, "tcp_open_count")
	case "udp-ratelimit":
		dumpRatelimitMap(core, "udp_ratelimit")
	case "health":
		dumpHealthMap(core, "udp_health")
	case "all":
		fmt.Println("== tcp_established ==")
		dumpTimestampMap(core, "tcp_established")
		fmt.Println("\n== tcp_syn_seen ==")
		dumpTimestampMap(core, "tcp_syn_seen")
		fmt.Println("\n== tcp_open_count ==")
		dumpCountMap(core, "tcp_open_count")
		fmt.Println("\n== tcp_whitelist ==")
		dumpTimestampMap(core, "tcp_whitelist")
		fmt.Println("\n== udp_ratelimit ==")
		dumpRatelimitMap(core, "udp_ratelimit")
		fmt.Println("\n== udp_health ==")
		dumpHealthMap(core, "udp_health")
	default:
		fmt.Fprintln(os.Stderr, "unknown map:", *which)
		os.Exit(2)
	}
}

func dumpTimestampMap(pinDir, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer m.Close()
	now := bootTimeNS()
	fmt.Printf("%-16s %-12s\n", "IP", "AGE")
	var key [4]byte
	var val uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		age := time.Duration(int64(now) - int64(val))
		if age < 0 {
			age = 0
		}
		fmt.Printf("%-16s %-12s\n", ip.String(), age.Truncate(time.Second))
	}
}

func dumpCountMap(pinDir, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer m.Close()
	fmt.Printf("%-16s %-10s\n", "IP", "OPEN")
	var key [4]byte
	var val uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		fmt.Printf("%-16s %-10d\n", ip.String(), val)
	}
}

func dumpRatelimitMap(pinDir, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer m.Close()
	now := bootTimeNS()
	fmt.Printf("%-16s %-10s %-12s\n", "IP", "TOKENS", "LAST_REFILL")
	var key [4]byte
	var val struct {
		Tokens       uint64
		LastRefillNS uint64
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		age := time.Duration(int64(now) - int64(val.LastRefillNS))
		if age < 0 {
			age = 0
		}
		fmt.Printf("%-16s %-10d %-12s\n", ip.String(), val.Tokens, age.Truncate(time.Millisecond))
	}
}

func dumpHealthMap(pinDir, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer m.Close()
	now := bootTimeNS()
	fmt.Printf("%-16s %-10s %-12s %-12s\n", "IP", "ANOMALIES", "WINDOW_AGE", "BLACKLIST")
	var key [4]byte
	var val struct {
		Anomalies        uint32
		_                uint32
		WindowStartNS    uint64
		BlacklistUntilNS uint64
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		windowAge := time.Duration(int64(now) - int64(val.WindowStartNS))
		if windowAge < 0 {
			windowAge = 0
		}
		bl := "-"
		if val.BlacklistUntilNS > now {
			rem := time.Duration(int64(val.BlacklistUntilNS) - int64(now))
			bl = "in " + rem.Truncate(time.Second).String()
		}
		fmt.Printf("%-16s %-10d %-12s %-12s\n",
			ip.String(), val.Anomalies,
			windowAge.Truncate(time.Second), bl)
	}
}
