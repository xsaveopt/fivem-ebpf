package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func cmdClear(args []string) {
	fs := flag.NewFlagSet("clear", flag.ExitOnError)
	pinPath := fs.String("pin-path", defaultPinPath, pinPathHelp)
	which := fs.String("map", "whitelist", "which map to clear: "+bpfmaps.CLINamesHelp+" | all")
	ipFlag := fs.String("ip", "", "if set, only clear this single IPv4 from the target map(s) instead of wiping every entry")
	_ = fs.Parse(args)

	var targets []string
	if *which == "all" {
		targets = bpfmaps.PerIP
	} else {
		name, ok := bpfmaps.CLIName[*which]
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown map: %s (one of %s | all)\n", *which, bpfmaps.CLINamesHelp)
			os.Exit(2)
		}
		targets = []string{name}
	}

	if *ipFlag != "" {
		key, err := parseIPv4Key(*ipFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, name := range targets {
			n, err := clearMapKey(*pinPath, name, key)
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
		n, err := clearWholeMap(*pinPath, name)
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
		return key, fmt.Errorf("IPv4 only: %q", s)
	}
	copy(key[:], v4)
	return key, nil
}

func clearMapKey(pinPath, name string, key [4]byte) (int, error) {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return 0, err
	}
	defer func() { _ = m.Close() }()

	if err := m.Delete(&key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, nil
		}
		return 0, err
	}
	return 1, nil
}

func clearWholeMap(pinPath, name string) (int, error) {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return 0, err
	}
	defer func() { _ = m.Close() }()

	keys, err := collectKeys(m)
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		if err := m.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, err
		}
	}
	return len(keys), nil
}

func collectKeys(m *ebpf.Map) ([][4]byte, error) {
	var keys [][4]byte
	var cur, next [4]byte
	var prev any
	for {
		if err := m.NextKey(prev, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return keys, nil
			}
			return keys, err
		}
		keys = append(keys, next)
		cur = next
		prev = &cur
	}
}
