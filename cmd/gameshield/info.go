package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/sratabix/gameshield-ebpf/internal/pinpath"
)

func bootTimeNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

var sharedPerIPMaps = []string{
	"tcp_whitelist",
	"tcp_established",
	"tcp_syn_seen",
	"tcp_open_count",
	"udp_ratelimit",
	"udp_health",
}

func mapEntryCount(pinDir, name string) int64 {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
	if err != nil {
		return -1
	}
	defer m.Close()
	var n int64
	var key [4]byte
	val := make([]byte, m.ValueSize())
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		n++
	}
	return n
}

func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	pinRoot := fs.String("pin-root", pinpath.DefaultRoot, "gameshield bpf pin root")
	_ = fs.Parse(args)

	core := pinpath.Core(*pinRoot)
	fmt.Printf("gameshield-ebpf %s\n", version)
	fmt.Printf("  pin root: %s\n", *pinRoot)
	if _, err := os.Stat(core); err != nil {
		fmt.Fprintln(os.Stderr, "  (no core pins — daemon not running?)")
		os.Exit(1)
	}
	fmt.Println("  shared maps:")
	for _, name := range sharedPerIPMaps {
		n := mapEntryCount(core, name)
		if n < 0 {
			fmt.Printf("    %-22s (closed)\n", name)
		} else {
			fmt.Printf("    %-22s %d\n", name, n)
		}
	}
}
