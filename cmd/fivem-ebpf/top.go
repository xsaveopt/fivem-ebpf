package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

type topRow struct {
	IP          string            `json:"ip"`
	Sort        int64             `json:"-"`
	Display     string            `json:"-"`
	Tokens      uint64            `json:"tokens"`
	Count       uint64            `json:"count"`
	AgeSeconds  int64             `json:"age_seconds"`
	Anomalies   uint32            `json:"anomalies"`
	Blacklisted bool              `json:"blacklisted"`
	Total       uint64            `json:"total"`
	ByReason    map[string]uint64 `json:"by_reason,omitempty"`
}

type topMapKind struct {
	pinned string
	kind   string
}

var topMapKinds = map[string]topMapKind{
	"whitelist":             {bpfmaps.Whitelist, "timestamp"},
	"established":           {bpfmaps.Established, "timestamp"},
	"syn-seen":              {bpfmaps.SynSeen, "timestamp"},
	"open-count":            {bpfmaps.OpenCount, "count"},
	"udp-ratelimit":         {bpfmaps.UDPRatelimit, "ratelimit"},
	"initconnect-ratelimit": {bpfmaps.InitConnectRatelimit, "ratelimit"},
	"getinfo-ratelimit":     {bpfmaps.GetInfoRatelimit, "ratelimit"},
	"health":                {bpfmaps.Health, "health"},
	"drop-history":          {bpfmaps.DropHistoryMap, "drop-reasons"},
}

func dropReasonIndex(reason string) (int, error) {
	if reason == "" {
		return -1, nil
	}
	for i, name := range bpfmaps.DropReasonNames {
		if name == reason {
			return i, nil
		}
	}
	return -1, fmt.Errorf("unknown reason: %s (one of %s)",
		reason, strings.Join(bpfmaps.DropReasonNames[:], ", "))
}

func topRows(m bpfmaps.Reader, kind string, now uint64, n, reasonIdx int, withDisplay bool) ([]topRow, error) {
	var err error
	var rows []topRow
	var key [4]byte

	switch kind {
	case "timestamp":
		var v uint64
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			age := ageSeconds(now, v)
			row := topRow{IP: ipv4Str(key), Sort: -age, AgeSeconds: age}
			if withDisplay {
				row.Display = fmt.Sprintf("age=%s", time.Duration(age)*time.Second)
			}
			rows = append(rows, row)
		}
		err = iter.Err()
	case "count":
		var v uint64
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			row := topRow{IP: ipv4Str(key), Sort: int64(v), Count: v}
			if withDisplay {
				row.Display = fmt.Sprintf("count=%d", v)
			}
			rows = append(rows, row)
		}
		err = iter.Err()
	case "ratelimit":
		var v bpfmaps.Ratelimit
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			age := ageSeconds(now, v.LastRefillNS)
			row := topRow{
				IP:         ipv4Str(key),
				Sort:       -int64(v.Tokens),
				Tokens:     v.Tokens,
				AgeSeconds: age,
			}
			if withDisplay {
				row.Display = fmt.Sprintf("tokens=%d refill_age=%s", v.Tokens, time.Duration(age)*time.Second)
			}
			rows = append(rows, row)
		}
		err = iter.Err()
	case "health":
		var v bpfmaps.UDPHealth
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			blacklisted := v.BlacklistUntilNS > now
			row := topRow{
				IP:          ipv4Str(key),
				Sort:        int64(v.Anomalies),
				Anomalies:   v.Anomalies,
				Blacklisted: blacklisted,
				AgeSeconds:  ageSeconds(now, v.WindowStartNS),
			}
			if withDisplay {
				tag := ""
				if blacklisted {
					tag = fmt.Sprintf(" BLACKLISTED unblock_in=%s",
						time.Duration(ageSeconds(v.BlacklistUntilNS, now))*time.Second)
				}
				row.Display = fmt.Sprintf("anomalies=%d window_age=%s%s",
					v.Anomalies, time.Duration(row.AgeSeconds)*time.Second, tag)
			}
			rows = append(rows, row)
		}
		err = iter.Err()
	case "drop-reasons":
		var v bpfmaps.DropHistory
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			total, by := dropCounts(v)
			sortKey := int64(total)
			if reasonIdx >= 0 {
				sortKey = int64(v.Counts[reasonIdx])
			}
			row := topRow{
				IP:         ipv4Str(key),
				Sort:       sortKey,
				Total:      total,
				ByReason:   by,
				AgeSeconds: ageSeconds(now, v.LastDropNS),
			}
			if withDisplay {
				parts := make([]string, 0, len(by))
				for _, name := range bpfmaps.DropReasonNames {
					if c, ok := by[name]; ok {
						parts = append(parts, fmt.Sprintf("%s=%d", name, c))
					}
				}
				row.Display = fmt.Sprintf("total=%d %s", total, strings.Join(parts, ","))
			}
			rows = append(rows, row)
		}
		err = iter.Err()
	default:
		return nil, fmt.Errorf("unknown map kind: %s", kind)
	}
	if err != nil {
		return nil, err
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].Sort > rows[j].Sort })
	if n > 0 && len(rows) > n {
		rows = rows[:n]
	}
	return rows, nil
}

func cmdTop(args []string) {
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	pinPath := fs.String("pin-path", defaultPinPath, pinPathHelp)
	which := fs.String("map", "open-count", "which map: "+bpfmaps.CLINamesHelp)
	n := fs.Int("n", 10, "max entries to print (0 for all)")
	reason := fs.String("reason", "", "for --map drop-history: rank by this reason instead of total drops (e.g. tcp_too_many_open)")
	_ = fs.Parse(args)

	if err := printTop(*pinPath, *which, *reason, *n); err != nil {
		fmt.Fprintln(os.Stderr, "top:", err)
		os.Exit(1)
	}
}

func printTop(pinPath, which, reason string, n int) error {
	kind, ok := topMapKinds[which]
	if !ok {
		return fmt.Errorf("unknown map: %s (one of %s)", which, bpfmaps.CLINamesHelp)
	}
	reasonIdx, err := dropReasonIndex(reason)
	if err != nil {
		return err
	}
	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		return err
	}

	m, err := bpfmaps.Open(pinPath, kind.pinned)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()

	rows, err := topRows(bpfmaps.Map{M: m}, kind.kind, now, n, reasonIdx, true)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("(empty)")
		return nil
	}
	for _, r := range rows {
		fmt.Printf("%-16s %s\n", r.IP, r.Display)
	}
	return nil
}
