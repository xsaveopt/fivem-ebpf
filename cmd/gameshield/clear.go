package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/sratabix/gameshield-ebpf/internal/pinpath"
)

func cmdClear(args []string) {
	fs := flag.NewFlagSet("clear", flag.ExitOnError)
	pinRoot := fs.String("pin-root", pinpath.DefaultRoot, "gameshield bpf pin root")
	which := fs.String("map", "whitelist", "whitelist|established|syn-seen|open-count|udp-ratelimit|health|all")
	ipFlag := fs.String("ip", "", "if set, clear only this IPv4 instead of every entry")
	_ = fs.Parse(args)

	core := pinpath.Core(*pinRoot)
	var targets []string
	switch *which {
	case "whitelist":
		targets = []string{"tcp_whitelist"}
	case "established":
		targets = []string{"tcp_established"}
	case "syn-seen":
		targets = []string{"tcp_syn_seen"}
	case "open-count":
		targets = []string{"tcp_open_count"}
	case "udp-ratelimit":
		targets = []string{"udp_ratelimit"}
	case "health":
		targets = []string{"udp_health"}
	case "all":
		targets = []string{"tcp_whitelist", "tcp_established", "tcp_syn_seen", "tcp_open_count", "udp_ratelimit", "udp_health"}
	default:
		fmt.Fprintln(os.Stderr, "unknown map:", *which)
		os.Exit(2)
	}

	if *ipFlag != "" {
		key, err := parseIPv4Key(*ipFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, name := range targets {
			n, err := clearMapKey(filepath.Join(core, name), key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
				continue
			}
			if n == 1 {
				fmt.Printf("%s: removed %s\n", name, *ipFlag)
			} else {
				fmt.Printf("%s: %s not present\n", name, *ipFlag)
			}
		}
		return
	}

	for _, name := range targets {
		n, err := clearMap(filepath.Join(core, name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			continue
		}
		fmt.Printf("%s: cleared %d entries\n", name, n)
	}
}

func parseIPv4Key(s string) ([4]byte, error) {
	var key [4]byte
	parsed := net.ParseIP(s)
	if parsed == nil {
		return key, fmt.Errorf("invalid IP: %q", s)
	}
	v4 := parsed.To4()
	if v4 == nil {
		return key, fmt.Errorf("not an IPv4 address: %q", s)
	}
	copy(key[:], v4)
	return key, nil
}

func clearMapKey(path string, key [4]byte) (int, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return 0, err
	}
	defer m.Close()
	if err := m.Delete(&key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, nil
		}
		return 0, err
	}
	return 1, nil
}

func clearMap(path string) (int, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return 0, err
	}
	defer m.Close()
	var key [4]byte
	valBuf := make([]byte, m.ValueSize())
	var keys [][4]byte
	iter := m.Iterate()
	for iter.Next(&key, &valBuf) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		_ = m.Delete(&k)
	}
	return len(keys), nil
}
