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

type clearOpts struct {
	pinPath string
	which   string
	ip      string
}

func parseClearFlags(args []string) (clearOpts, error) {
	var o clearOpts
	fs := flag.NewFlagSet("clear", flag.ContinueOnError)
	fs.StringVar(&o.pinPath, "pin-path", defaultPinPath, pinPathHelp)
	fs.StringVar(&o.which, "map", "whitelist", "which map to clear: "+bpfmaps.CLINamesHelp+" | all")
	fs.StringVar(&o.ip, "ip", "", "if set, only clear this single IPv4 from the target map(s) instead of wiping every entry")
	return o, fs.Parse(args)
}

func cmdClear(args []string) {
	o, err := parseClearFlags(args)
	if err != nil {
		exitFlagError(err)
	}

	targets, err := resolveMapTargets(o.which)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if o.ip != "" {
		key, err := parseIPv4Key(o.ip)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, name := range targets {
			n, err := clearMapKey(o.pinPath, name, key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
				continue
			}
			if n == 1 {
				fmt.Printf("%s: removed %s\n", name, o.ip)
			} else {
				fmt.Printf("%s: %s not present\n", name, o.ip)
			}
		}
		return
	}

	for _, name := range targets {
		n, err := clearWholeMap(o.pinPath, name)
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

type mapMutator interface {
	NextKey(key, nextKeyOut any) error
	Delete(key any) error
}

func clearMapKey(pinPath, name string, key [4]byte) (int, error) {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return 0, err
	}
	defer func() { _ = m.Close() }()

	return deleteKey(m, key)
}

func clearWholeMap(pinPath, name string) (int, error) {
	m, err := bpfmaps.Open(pinPath, name)
	if err != nil {
		return 0, err
	}
	defer func() { _ = m.Close() }()

	return deleteAllKeys(m)
}

func deleteKey(m mapMutator, key [4]byte) (int, error) {
	if err := m.Delete(&key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, nil
		}
		return 0, err
	}
	return 1, nil
}

func deleteAllKeys(m mapMutator) (int, error) {
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

func collectKeys(m mapMutator) ([][4]byte, error) {
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
