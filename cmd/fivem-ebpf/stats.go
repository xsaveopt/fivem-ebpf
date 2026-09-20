package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

type statsOpts struct {
	pinPath string
	asJSON  bool
	watch   time.Duration
}

func parseStatsFlags(args []string) (statsOpts, error) {
	var o statsOpts
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.StringVar(&o.pinPath, "pin-path", defaultPinPath, pinPathHelp)
	fs.BoolVar(&o.asJSON, "json", false, "emit JSON instead of text")
	fs.DurationVar(&o.watch, "watch", 0, "repeat every N (e.g. 1s); 0 = run once")
	return o, fs.Parse(args)
}

func writeStats(w io.Writer, vals []uint64, asJSON bool) error {
	if asJSON {
		obj := make(map[string]uint64, len(bpfmaps.StatLabels))
		for i, lbl := range bpfmaps.StatLabels {
			obj[lbl] = vals[i]
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(obj)
	}
	for i, lbl := range bpfmaps.StatLabels {
		outf(w, "%-32s %d\n", lbl, vals[i])
	}
	return nil
}

func cmdStats(args []string) {
	o, err := parseStatsFlags(args)
	if err != nil {
		exitFlagError(err)
	}

	dump := func() error {
		m, err := bpfmaps.Open(o.pinPath, bpfmaps.Stats)
		if err != nil {
			return err
		}
		defer func() { _ = m.Close() }()
		vals, err := bpfmaps.ReadStats(m)
		if err != nil {
			return err
		}
		return writeStats(os.Stdout, vals, o.asJSON)
	}

	if o.watch == 0 {
		if err := dump(); err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
			os.Exit(1)
		}
		return
	}

	for {
		fmt.Print("\x1b[H\x1b[2J")
		fmt.Printf("# fivem-ebpf stats %s (refresh %s)\n", time.Now().Format(time.TimeOnly), o.watch)
		if err := dump(); err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
		}
		time.Sleep(o.watch)
	}
}
