package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

const testNow = 1_000_000_000_000

func secsAgo(n uint64) uint64 { return testNow - n*1_000_000_000 }

func ips(rows []topRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.IP)
	}
	return out
}

func displays(rows []topRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.IP+" "+r.Display)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTopMapKindsMatchTheCLIMapNames(t *testing.T) {
	if len(topMapKinds) != len(bpfmaps.CLIName) {
		t.Errorf("topMapKinds has %d entries, CLIName has %d", len(topMapKinds), len(bpfmaps.CLIName))
	}
	for name, kind := range topMapKinds {
		pinned, ok := bpfmaps.CLIName[name]
		if !ok {
			t.Errorf("--map %s is accepted by top but is not a CLI map name", name)
			continue
		}
		if kind.pinned != pinned {
			t.Errorf("top resolves %s to %s, the CLI resolves it to %s", name, kind.pinned, pinned)
		}
	}
}

func TestTopRowsRanksTimestampsNewestFirst(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: secsAgo(90)},
		{key: [4]byte{10, 0, 0, 2}, val: secsAgo(1)},
		{key: [4]byte{10, 0, 0, 3}, val: secsAgo(30)},
	}}
	rows, err := topRows(m, "timestamp", testNow, 0, -1, true)
	if err != nil {
		t.Fatalf("topRows: %v", err)
	}
	want := []string{"10.0.0.2 age=1s", "10.0.0.3 age=30s", "10.0.0.1 age=1m30s"}
	if got := displays(rows); !equal(got, want) {
		t.Errorf("rows = %v, want %v", got, want)
	}
	if rows[0].AgeSeconds != 1 {
		t.Errorf("AgeSeconds = %d, want 1", rows[0].AgeSeconds)
	}
}

func TestTopRowsRanksRatelimitsByFewestTokens(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: bpfmaps.Ratelimit{Tokens: 900, LastRefillNS: secsAgo(2)}},
		{key: [4]byte{10, 0, 0, 2}, val: bpfmaps.Ratelimit{Tokens: 0, LastRefillNS: secsAgo(5)}},
		{key: [4]byte{10, 0, 0, 3}, val: bpfmaps.Ratelimit{Tokens: 12, LastRefillNS: secsAgo(0)}},
	}}
	rows, err := topRows(m, "ratelimit", testNow, 0, -1, true)
	if err != nil {
		t.Fatalf("topRows: %v", err)
	}
	want := []string{
		"10.0.0.2 tokens=0 refill_age=5s",
		"10.0.0.3 tokens=12 refill_age=0s",
		"10.0.0.1 tokens=900 refill_age=2s",
	}
	if got := displays(rows); !equal(got, want) {
		t.Errorf("rows = %v, want %v", got, want)
	}
}

func TestTopRowsFlagsBlacklistedHealthEntries(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: bpfmaps.UDPHealth{
			Anomalies: 5, WindowStartNS: secsAgo(10),
		}},
		{key: [4]byte{10, 0, 0, 2}, val: bpfmaps.UDPHealth{
			Anomalies: 400, WindowStartNS: secsAgo(3), BlacklistUntilNS: testNow + 60_000_000_000,
		}},
	}}
	rows, err := topRows(m, "health", testNow, 0, -1, true)
	if err != nil {
		t.Fatalf("topRows: %v", err)
	}
	want := []string{
		"10.0.0.2 anomalies=400 window_age=3s BLACKLISTED unblock_in=1m0s",
		"10.0.0.1 anomalies=5 window_age=10s",
	}
	if got := displays(rows); !equal(got, want) {
		t.Errorf("rows = %v, want %v", got, want)
	}
	if !rows[0].Blacklisted || rows[1].Blacklisted {
		t.Errorf("blacklist flags = (%v, %v), want (true, false)", rows[0].Blacklisted, rows[1].Blacklisted)
	}
}

func dropHistory(last uint64, counts map[string]uint64) bpfmaps.DropHistory {
	v := bpfmaps.DropHistory{FirstDropNS: secsAgo(600), LastDropNS: last}
	for reason, n := range counts {
		idx, err := dropReasonIndex(reason)
		if err != nil {
			panic(err)
		}
		v.Counts[idx] = n
	}
	return v
}

func TestTopRowsRanksDropHistoryByTotal(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: dropHistory(secsAgo(4), map[string]uint64{
			"tcp_no_syn": 2, "udp_ratelimit": 1,
		})},
		{key: [4]byte{10, 0, 0, 2}, val: dropHistory(secsAgo(1), map[string]uint64{
			"tcp_too_many_open": 40,
		})},
	}}
	rows, err := topRows(m, "drop-reasons", testNow, 0, -1, true)
	if err != nil {
		t.Fatalf("topRows: %v", err)
	}
	want := []string{
		"10.0.0.2 total=40 tcp_too_many_open=40",
		"10.0.0.1 total=3 tcp_no_syn=2,udp_ratelimit=1",
	}
	if got := displays(rows); !equal(got, want) {
		t.Errorf("rows = %v, want %v", got, want)
	}
	if rows[0].Total != 40 || rows[0].ByReason["tcp_too_many_open"] != 40 {
		t.Errorf("row totals not carried through: %+v", rows[0])
	}
}

func TestTopRowsRanksDropHistoryByChosenReason(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: dropHistory(secsAgo(4), map[string]uint64{
			"udp_ratelimit": 9,
		})},
		{key: [4]byte{10, 0, 0, 2}, val: dropHistory(secsAgo(1), map[string]uint64{
			"tcp_too_many_open": 40, "udp_ratelimit": 1,
		})},
	}}
	idx, err := dropReasonIndex("udp_ratelimit")
	if err != nil {
		t.Fatalf("dropReasonIndex: %v", err)
	}
	rows, err := topRows(m, "drop-reasons", testNow, 0, idx, false)
	if err != nil {
		t.Fatalf("topRows: %v", err)
	}
	if got := ips(rows); !equal(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Errorf("rows = %v, want the IP with the most udp_ratelimit drops first", got)
	}
}

func TestTopRowsRejectsAnUnknownKind(t *testing.T) {
	if _, err := topRows(&fakeMap{}, "no-such-kind", testNow, 10, -1, false); err == nil {
		t.Error("topRows accepted an unknown map kind")
	}
}

func TestTopRowsReturnsEveryRowWhenNIsZero(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: uint64(1)},
		{key: [4]byte{10, 0, 0, 2}, val: uint64(2)},
		{key: [4]byte{10, 0, 0, 3}, val: uint64(3)},
	}}
	rows, err := topRows(m, "count", testNow, 0, -1, false)
	if err != nil {
		t.Fatalf("topRows: %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("got %d rows for n=0, want all 3", len(rows))
	}
}

func TestTopRowsOnAnEmptyMap(t *testing.T) {
	rows, err := topRows(&fakeMap{}, "count", testNow, 10, -1, true)
	if err != nil {
		t.Fatalf("topRows: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("got %d rows from an empty map", len(rows))
	}
}

func TestPrintTopRejectsBadArgumentsBeforeOpeningAMap(t *testing.T) {
	err := printTop("/nonexistent-pin-path", "nope", "", 10)
	if err == nil {
		t.Fatal("printTop accepted an unknown map")
	}
	if !strings.Contains(err.Error(), "unknown map: nope") {
		t.Errorf("error = %v", err)
	}
	err = printTop("/nonexistent-pin-path", "drop-history", "not-a-reason", 10)
	if err == nil {
		t.Fatal("printTop accepted an unknown drop reason")
	}
	if !strings.Contains(err.Error(), "unknown reason: not-a-reason") {
		t.Errorf("error = %v", err)
	}
}

func TestPrintTopFailsWithoutPinnedMaps(t *testing.T) {
	if err := printTop("/nonexistent-pin-path", "whitelist", "", 10); err == nil {
		t.Error("printTop succeeded with no pinned maps")
	}
}

func TestDropCountsOmitsUntouchedReasons(t *testing.T) {
	v := dropHistory(secsAgo(1), map[string]uint64{"malformed": 4, "ip_fragment": 1})
	total, by := dropCounts(v)
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(by) != 2 {
		t.Errorf("by_reason has %d entries, want 2: zero counts must be omitted", len(by))
	}
	if by["malformed"] != 4 || by["ip_fragment"] != 1 {
		t.Errorf("by_reason = %v", by)
	}
}

func TestDropCountsOnAnUntouchedEntry(t *testing.T) {
	total, by := dropCounts(bpfmaps.DropHistory{})
	if total != 0 || len(by) != 0 {
		t.Errorf("dropCounts of an empty entry = (%d, %v), want (0, empty)", total, by)
	}
}

func TestTopRowsPropagatesIterationErrorForEveryKind(t *testing.T) {
	for _, kind := range []string{"timestamp", "count", "ratelimit", "health", "drop-reasons"} {
		m := &fakeMap{
			entries: []fakeEntry{{key: [4]byte{10, 0, 0, 1}, val: valueFor(kind)}},
			iterErr: errors.New("iteration aborted"),
		}
		if _, err := topRows(m, kind, testNow, 10, -1, false); err == nil {
			t.Errorf("%s: topRows swallowed an aborted iteration", kind)
		}
	}
}

func valueFor(kind string) any {
	switch kind {
	case "ratelimit":
		return bpfmaps.Ratelimit{}
	case "health":
		return bpfmaps.UDPHealth{}
	case "drop-reasons":
		return bpfmaps.DropHistory{}
	default:
		return uint64(0)
	}
}
