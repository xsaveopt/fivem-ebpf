package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func cmdDump(args []string) {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	pinPath := fs.String("pin-path", "/sys/fs/bpf/fivem", "bpf map pin directory")
	which := fs.String("map", "whitelist", "which map to dump: whitelist | established | syn-seen | open-count | udp-ratelimit | initconnect-ratelimit | getinfo-ratelimit | health | all")
	_ = fs.Parse(args)

	switch *which {
	case "whitelist":
		dumpTimestampMap(*pinPath, "tcp_whitelist")
	case "established":
		dumpTimestampMap(*pinPath, "tcp_established")
	case "syn-seen":
		dumpTimestampMap(*pinPath, "tcp_syn_seen")
	case "open-count":
		dumpCountMap(*pinPath, "tcp_open_count")
	case "udp-ratelimit":
		dumpRatelimitMap(*pinPath, "udp_ratelimit")
	case "initconnect-ratelimit":
		dumpRatelimitMap(*pinPath, "initconnect_ratelimit")
	case "getinfo-ratelimit":
		dumpRatelimitMap(*pinPath, "getinfo_ratelimit")
	case "health":
		dumpHealthMap(*pinPath, "udp_health")
	case "all":
		fmt.Println("== tcp_established ==")
		dumpTimestampMap(*pinPath, "tcp_established")
		fmt.Println("\n== tcp_syn_seen ==")
		dumpTimestampMap(*pinPath, "tcp_syn_seen")
		fmt.Println("\n== tcp_open_count ==")
		dumpCountMap(*pinPath, "tcp_open_count")
		fmt.Println("\n== tcp_whitelist ==")
		dumpTimestampMap(*pinPath, "tcp_whitelist")
		fmt.Println("\n== udp_ratelimit ==")
		dumpRatelimitMap(*pinPath, "udp_ratelimit")
		fmt.Println("\n== initconnect_ratelimit ==")
		dumpRatelimitMap(*pinPath, "initconnect_ratelimit")
		fmt.Println("\n== getinfo_ratelimit ==")
		dumpRatelimitMap(*pinPath, "getinfo_ratelimit")
		fmt.Println("\n== udp_health ==")
		dumpHealthMap(*pinPath, "udp_health")
	default:
		fmt.Fprintln(os.Stderr, "unknown map:", *which)
		os.Exit(2)
	}
}

func dumpTimestampMap(pinPath, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
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
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}

func dumpCountMap(pinPath, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
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
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}

func dumpRatelimitMap(pinPath, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer m.Close()

	now := bootTimeNS()
	fmt.Printf("%-16s %-10s %-12s\n", "IP", "TOKENS", "LAST_REFILL")
	var key [4]byte
	var val struct {
		Tokens        uint64
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
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}

func dumpHealthMap(pinPath, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer m.Close()

	now := bootTimeNS()
	fmt.Printf("%-16s %-10s %-12s %-12s\n", "IP", "ANOMALIES", "WINDOW_AGE", "BLACKLIST")
	var key [4]byte
	var val struct {
		Anomalies         uint32
		_                 uint32 // pad to u64 alignment
		WindowStartNS     uint64
		BlacklistUntilNS  uint64
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
			remaining := time.Duration(int64(val.BlacklistUntilNS) - int64(now))
			bl = "in " + remaining.Truncate(time.Second).String()
		}
		fmt.Printf("%-16s %-10d %-12s %-12s\n",
			ip.String(), val.Anomalies,
			windowAge.Truncate(time.Second), bl)
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}

func bootTimeNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}
