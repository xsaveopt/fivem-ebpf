package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

func cmdStats(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	pinPath := fs.String("pin-path", "/sys/fs/bpf/fivem", "bpf map pin directory")
	_ = fs.Parse(args)

	m, err := ebpf.LoadPinnedMap(filepath.Join(*pinPath, "stats"), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open stats:", err)
		os.Exit(1)
	}
	defer m.Close()

	labels := []string{
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

	ncpu, err := ebpf.PossibleCPU()
	if err != nil || ncpu <= 0 {
		ncpu = 1
	}
	perCPU := make([]uint64, ncpu)

	for i, label := range labels {
		k := uint32(i)
		if err := m.Lookup(&k, &perCPU); err != nil {
			fmt.Printf("%-32s (lookup error: %v)\n", label, err)
			continue
		}
		var s uint64
		for _, v := range perCPU {
			s += v
		}
		fmt.Printf("%-32s %d\n", label, s)
	}
}
