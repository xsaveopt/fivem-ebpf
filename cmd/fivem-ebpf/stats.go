package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
)

// statLabels indexes match the slot enum in bpf/shared/stats.h.
var statLabels = []string{
	"pass_tcp",
	"pass_udp_whitelisted",
	"drop_udp_not_whitelisted",
	"drop_udp_expired",
	"drop_malformed",
	"tcp_established_inserts",
	"tcp_l7_promoted",
	"tcp_l7_match_no_est",
	"drop_udp_ratelimit",
	"drop_tcp_initconnect_ratelimit",
	"drop_udp_enet_malformed",
	"drop_udp_unhealthy",
	"tcp_post_client_seen",
	"tcp_getinfo_seen",
	"drop_tcp_getinfo_ratelimit",
	"drop_tcp_bad_user_agent",
	"drop_tcp_no_syn",
	"drop_tcp_global_ratelimit",
	"drop_tcp_too_many_open",
}

// readStatsMap returns slot→sum-across-CPUs for every entry in `stats`.
// Index aligns with statLabels.
func readStatsMap(m *ebpf.Map) ([]uint64, error) {
	ncpu, err := ebpf.PossibleCPU()
	if err != nil || ncpu <= 0 {
		ncpu = 1
	}
	perCPU := make([]uint64, ncpu)
	out := make([]uint64, len(statLabels))
	for i := range statLabels {
		k := uint32(i)
		if err := m.Lookup(&k, &perCPU); err != nil {
			return nil, fmt.Errorf("slot %d: %w", i, err)
		}
		var s uint64
		for _, v := range perCPU {
			s += v
		}
		out[i] = s
	}
	return out, nil
}

func cmdStats(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	pinPath := fs.String("pin-path", "/sys/fs/bpf/fivem", "bpf map pin directory")
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	watch := fs.Duration("watch", 0, "repeat every N (e.g. 1s); 0 = run once")
	_ = fs.Parse(args)

	dump := func() error {
		m, err := ebpf.LoadPinnedMap(filepath.Join(*pinPath, "stats"), nil)
		if err != nil {
			return err
		}
		defer m.Close()
		vals, err := readStatsMap(m)
		if err != nil {
			return err
		}
		if *asJSON {
			obj := make(map[string]uint64, len(statLabels))
			for i, lbl := range statLabels {
				obj[lbl] = vals[i]
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(obj)
		}
		for i, lbl := range statLabels {
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
		fmt.Print("\x1b[H\x1b[2J") // clear
		fmt.Printf("# fivem-ebpf stats — %s (refresh %s)\n", time.Now().Format(time.TimeOnly), *watch)
		if err := dump(); err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
		}
		time.Sleep(*watch)
	}
}
