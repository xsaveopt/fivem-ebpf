package fivem

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"

	"github.com/sratabix/gameshield-ebpf/internal/module"
	"github.com/sratabix/gameshield-ebpf/internal/pinpath"
)

func subcommands() []module.Subcommand {
	return []module.Subcommand{
		{
			Name:        "dump-ratelimits",
			Description: "dump initconnect_ratelimit / getinfo_ratelimit per IP",
			Run:         runDumpRatelimits,
		},
		{
			Name:        "dump-drops",
			Description: "dump fivem_drop_history per IP",
			Run:         runDumpDrops,
		},
		{
			Name:        "stats",
			Description: "per-CPU FiveM stat counters",
			Run:         runStats,
		},
	}
}

func runDumpRatelimits(args []string) {
	fs := flag.NewFlagSet("fivem dump-ratelimits", flag.ExitOnError)
	pinRoot := fs.String("pin-root", "/sys/fs/bpf/gameshield", "gameshield bpf pin root")
	_ = fs.Parse(args)

	pin := pinpath.Module(*pinRoot, Name)
	for _, n := range []string{"initconnect_ratelimit", "getinfo_ratelimit"} {
		fmt.Printf("== %s ==\n", n)
		dumpRatelimitMap(pin, n)
	}
}

func runDumpDrops(args []string) {
	fs := flag.NewFlagSet("fivem dump-drops", flag.ExitOnError)
	pinRoot := fs.String("pin-root", "/sys/fs/bpf/gameshield", "gameshield bpf pin root")
	_ = fs.Parse(args)

	dumpDropHistory(pinpath.Module(*pinRoot, Name), "fivem_drop_history")
}

func runStats(args []string) {
	fs := flag.NewFlagSet("fivem stats", flag.ExitOnError)
	pinRoot := fs.String("pin-root", "/sys/fs/bpf/gameshield", "gameshield bpf pin root")
	watch := fs.Duration("watch", 0, "repeat every N (e.g. 1s); 0 = run once")
	_ = fs.Parse(args)

	pin := pinpath.Module(*pinRoot, Name)
	dump := func() error {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pin, "fivem_stats"), nil)
		if err != nil {
			return err
		}
		defer m.Close()
		ncpu, err := ebpf.PossibleCPU()
		if err != nil || ncpu <= 0 {
			ncpu = 1
		}
		perCPU := make([]uint64, ncpu)
		for i, lbl := range StatLabels {
			k := uint32(i)
			if err := m.Lookup(&k, &perCPU); err != nil {
				return fmt.Errorf("slot %d: %w", i, err)
			}
			var s uint64
			for _, v := range perCPU {
				s += v
			}
			fmt.Printf("%-32s %d\n", lbl, s)
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
		fmt.Printf("# gameshield fivem stats — %s (refresh %s)\n", time.Now().Format(time.TimeOnly), *watch)
		if err := dump(); err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
		}
		time.Sleep(*watch)
	}
}

func dumpRatelimitMap(pinDir, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer m.Close()
	now := bootTimeNS()
	fmt.Printf("%-16s %-10s %-12s\n", "IP", "TOKENS", "LAST_REFILL")
	var key [4]byte
	var val struct {
		Tokens       uint64
		LastRefillNS uint64
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		age := time.Duration(int64(now) - int64(val.LastRefillNS))
		if age < 0 {
			age = 0
		}
		fmt.Printf("%-16s %-10d %-12s\n", ip.String(), val.Tokens, age.Truncate(time.Millisecond))
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}

func dumpDropHistory(pinDir, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer m.Close()
	now := bootTimeNS()
	fmt.Printf("%-16s %-12s %-12s %-10s %s\n", "IP", "FIRST_AGE", "LAST_AGE", "TOTAL", "BY_REASON")
	var key [4]byte
	var val struct {
		FirstDropNS uint64
		LastDropNS  uint64
		Counts      [12]uint64
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		first := time.Duration(int64(now) - int64(val.FirstDropNS))
		if first < 0 {
			first = 0
		}
		last := time.Duration(int64(now) - int64(val.LastDropNS))
		if last < 0 {
			last = 0
		}
		var total uint64
		var parts []string
		for i, c := range val.Counts {
			if c == 0 {
				continue
			}
			total += c
			parts = append(parts, fmt.Sprintf("%s=%d", DropReasonNames[i], c))
		}
		fmt.Printf("%-16s %-12s %-12s %-10d %s\n",
			ip.String(),
			first.Truncate(time.Second),
			last.Truncate(time.Second),
			total,
			strings.Join(parts, ","))
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}
