package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"

	"github.com/sratabix/gameshield-ebpf/internal/pinpath"
)

func cmdInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	pinRoot := fs.String("pin-root", pinpath.DefaultRoot, "gameshield bpf pin root")
	watch := fs.Duration("watch", 0, "repeat every N (e.g. 1s); 0 = run once")
	_ = fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: gameshield inspect <ipv4> [--watch 1s]")
		os.Exit(2)
	}
	addr := fs.Arg(0)
	parsed := net.ParseIP(addr)
	if parsed == nil {
		fmt.Fprintln(os.Stderr, "invalid IP:", addr)
		os.Exit(2)
	}
	v4 := parsed.To4()
	if v4 == nil {
		fmt.Fprintln(os.Stderr, "IPv4 only:", addr)
		os.Exit(2)
	}
	var key [4]byte
	copy(key[:], v4)
	core := pinpath.Core(*pinRoot)

	dump := func() {
		now := bootTimeNS()
		fmt.Printf("IP %s\n", addr)
		inspectTimestamp(core, "tcp_whitelist", key, now)
		inspectTimestamp(core, "tcp_established", key, now)
		inspectTimestamp(core, "tcp_syn_seen", key, now)
		inspectCount(core, "tcp_open_count", key)
		inspectRatelimit(core, "udp_ratelimit", key, now)
		inspectHealth(core, "udp_health", key, now)
	}
	if *watch == 0 {
		dump()
		return
	}
	for {
		fmt.Print("\x1b[H\x1b[2J")
		fmt.Printf("# gameshield inspect — %s (refresh %s)\n", time.Now().Format(time.TimeOnly), *watch)
		dump()
		time.Sleep(*watch)
	}
}

const inspectLabelWidth = 22

func inspectLine(name, body string) {
	fmt.Printf("  %-*s %s\n", inspectLabelWidth, name, body)
}

func openPinned(pinDir, name string) (*ebpf.Map, bool) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
	if err != nil {
		inspectLine(name, fmt.Sprintf("(open: %v)", err))
		return nil, false
	}
	return m, true
}

func inspectTimestamp(pinDir, name string, key [4]byte, now uint64) {
	m, ok := openPinned(pinDir, name)
	if !ok {
		return
	}
	defer m.Close()
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return
	}
	age := time.Duration(int64(now) - int64(val))
	if age < 0 {
		age = 0
	}
	inspectLine(name, fmt.Sprintf("age=%s", age.Truncate(time.Second)))
}

func inspectCount(pinDir, name string, key [4]byte) {
	m, ok := openPinned(pinDir, name)
	if !ok {
		return
	}
	defer m.Close()
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return
	}
	inspectLine(name, fmt.Sprintf("count=%d", val))
}

func inspectRatelimit(pinDir, name string, key [4]byte, now uint64) {
	m, ok := openPinned(pinDir, name)
	if !ok {
		return
	}
	defer m.Close()
	var val struct {
		Tokens       uint64
		LastRefillNS uint64
	}
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return
	}
	age := time.Duration(int64(now) - int64(val.LastRefillNS))
	if age < 0 {
		age = 0
	}
	inspectLine(name, fmt.Sprintf("tokens=%d refill_age=%s",
		val.Tokens, age.Truncate(time.Second)))
}

func inspectHealth(pinDir, name string, key [4]byte, now uint64) {
	m, ok := openPinned(pinDir, name)
	if !ok {
		return
	}
	defer m.Close()
	var val struct {
		Anomalies        uint32
		_                uint32
		WindowStartNS    uint64
		BlacklistUntilNS uint64
	}
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return
	}
	wAge := time.Duration(int64(now) - int64(val.WindowStartNS))
	if wAge < 0 {
		wAge = 0
	}
	body := fmt.Sprintf("anomalies=%d window_age=%s",
		val.Anomalies, wAge.Truncate(time.Second))
	if val.BlacklistUntilNS > now {
		remaining := time.Duration(int64(val.BlacklistUntilNS) - int64(now))
		body += fmt.Sprintf(" BLACKLISTED unblock_in=%s",
			remaining.Truncate(time.Second))
	} else {
		body += " blacklisted=no"
	}
	inspectLine(name, body)
}
