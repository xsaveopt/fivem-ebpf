package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

type inspectOpts struct {
	pinPath string
	watch   time.Duration
	addr    string
}

func parseInspectFlags(args []string) (inspectOpts, error) {
	var o inspectOpts
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.StringVar(&o.pinPath, "pin-path", defaultPinPath, pinPathHelp)
	fs.DurationVar(&o.watch, "watch", 0, "repeat every N (e.g. 1s); 0 = run once")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	o.addr = fs.Arg(0)
	return o, nil
}

func cmdInspect(args []string) {
	o, err := parseInspectFlags(args)
	if err != nil {
		exitFlagError(err)
	}
	if o.addr == "" {
		fmt.Fprintln(os.Stderr, "usage: fivem-ebpf inspect <ipv4> [--watch 1s]")
		os.Exit(2)
	}
	key, err := parseIPv4Key(o.addr)
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
		inspectAll(os.Stdout, o.pinPath, o.addr, key, now)
	}

	if o.watch == 0 {
		dump()
		return
	}
	for {
		fmt.Print("\x1b[H\x1b[2J")
		fmt.Printf("# fivem-ebpf inspect %s (refresh %s)\n", time.Now().Format(time.TimeOnly), o.watch)
		dump()
		time.Sleep(o.watch)
	}
}

const inspectLabelWidth = 22

type inspectStep struct {
	name   string
	render func(w io.Writer, m bpfmaps.Reader, name string, key [4]byte, now uint64)
}

var inspectSteps = []inspectStep{
	{bpfmaps.Whitelist, inspectTimestamp},
	{bpfmaps.Established, inspectTimestamp},
	{bpfmaps.SynSeen, inspectTimestamp},
	{bpfmaps.OpenCount, inspectCount},
	{bpfmaps.UDPRatelimit, inspectRatelimit},
	{bpfmaps.InitConnectRatelimit, inspectRatelimit},
	{bpfmaps.GetInfoRatelimit, inspectRatelimit},
	{bpfmaps.Health, inspectHealth},
	{bpfmaps.DropHistoryMap, inspectDropHistory},
}

func inspectAll(w io.Writer, pinPath, addr string, key [4]byte, now uint64) {
	outf(w, "IP %s\n", addr)
	for _, step := range inspectSteps {
		m, err := bpfmaps.Open(pinPath, step.name)
		if err != nil {
			inspectLine(w, step.name, fmt.Sprintf("(%v)", err))
			continue
		}
		step.render(w, bpfmaps.Map{M: m}, step.name, key, now)
		_ = m.Close()
	}
}

func inspectLine(w io.Writer, name, body string) {
	outf(w, "  %-*s %s\n", inspectLabelWidth, name, body)
}

func lookupInto(w io.Writer, m bpfmaps.Reader, name string, key [4]byte, out any) bool {
	if err := m.Lookup(&key, out); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(w, name, "-")
		} else {
			inspectLine(w, name, fmt.Sprintf("(lookup: %v)", err))
		}
		return false
	}
	return true
}

func inspectTimestamp(w io.Writer, m bpfmaps.Reader, name string, key [4]byte, now uint64) {
	var val uint64
	if !lookupInto(w, m, name, key, &val) {
		return
	}
	inspectLine(w, name, fmt.Sprintf("age=%s", secs(ageSeconds(now, val))))
}

func inspectCount(w io.Writer, m bpfmaps.Reader, name string, key [4]byte, _ uint64) {
	var val uint64
	if !lookupInto(w, m, name, key, &val) {
		return
	}
	inspectLine(w, name, fmt.Sprintf("count=%d", val))
}

func inspectRatelimit(w io.Writer, m bpfmaps.Reader, name string, key [4]byte, now uint64) {
	var val bpfmaps.Ratelimit
	if !lookupInto(w, m, name, key, &val) {
		return
	}
	inspectLine(w, name, fmt.Sprintf("tokens=%d refill_age=%s",
		val.Tokens, secs(ageSeconds(now, val.LastRefillNS))))
}

func inspectHealth(w io.Writer, m bpfmaps.Reader, name string, key [4]byte, now uint64) {
	var val bpfmaps.UDPHealth
	if !lookupInto(w, m, name, key, &val) {
		return
	}
	body := fmt.Sprintf("anomalies=%d window_age=%s",
		val.Anomalies, secs(ageSeconds(now, val.WindowStartNS)))
	if val.BlacklistUntilNS > now {
		body += fmt.Sprintf(" BLACKLISTED unblock_in=%s", secs(ageSeconds(val.BlacklistUntilNS, now)))
	} else {
		body += " blacklisted=no"
	}
	inspectLine(w, name, body)
}

func inspectDropHistory(w io.Writer, m bpfmaps.Reader, name string, key [4]byte, now uint64) {
	var val bpfmaps.DropHistory
	if !lookupInto(w, m, name, key, &val) {
		return
	}
	total, by := dropCounts(val)
	body := fmt.Sprintf("first=%s last=%s total=%d",
		secs(ageSeconds(now, val.FirstDropNS)), secs(ageSeconds(now, val.LastDropNS)), total)
	if parts := dropReasonParts(by); len(parts) > 0 {
		body += " " + strings.Join(parts, ",")
	}
	inspectLine(w, name, body)
}
