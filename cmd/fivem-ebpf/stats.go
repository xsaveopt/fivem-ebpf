package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func cmdStats(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	pinPath := fs.String("pin-path", defaultPinPath, pinPathHelp)
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	watch := fs.Duration("watch", 0, "repeat every N (e.g. 1s); 0 = run once")
	_ = fs.Parse(args)

	dump := func() error {
		m, err := bpfmaps.Open(*pinPath, bpfmaps.Stats)
		if err != nil {
			return err
		}
		defer func() { _ = m.Close() }()
		vals, err := bpfmaps.ReadStats(m)
		if err != nil {
			return err
		}
		if *asJSON {
			obj := make(map[string]uint64, len(bpfmaps.StatLabels))
			for i, lbl := range bpfmaps.StatLabels {
				obj[lbl] = vals[i]
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(obj)
		}
		for i, lbl := range bpfmaps.StatLabels {
			fmt.Printf("%-32s %d\n", lbl, vals[i])
		}
		return nil
	}

	if *watch == 0 {
		if err := dump(); err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
			os.Exit(1)
		}
		return
	}

	for {
		fmt.Print("\x1b[H\x1b[2J")
		fmt.Printf("# fivem-ebpf stats %s (refresh %s)\n", time.Now().Format(time.TimeOnly), *watch)
		if err := dump(); err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
		}
		time.Sleep(*watch)
	}
}
