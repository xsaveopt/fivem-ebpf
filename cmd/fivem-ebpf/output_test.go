package main

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func rendered(t *testing.T, render func(w io.Writer) error) []string {
	t.Helper()
	var b strings.Builder
	if err := render(&b); err != nil {
		t.Fatalf("render: %v", err)
	}
	return columns(b.String())
}

func columns(out string) []string {
	trimmed := strings.TrimRight(out, "\n")
	if trimmed == "" {
		return nil
	}
	rows := strings.Split(trimmed, "\n")
	for i, row := range rows {
		rows[i] = strings.Join(strings.Fields(row), " ")
	}
	return rows
}

func wantRows(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d:\ngot:\n%s\nwant:\n%s",
			len(got), len(want), strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDumpRendererForCoversEveryPerIPMap(t *testing.T) {
	for _, name := range bpfmaps.PerIP {
		if _, err := dumpRendererFor(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := dumpRendererFor(bpfmaps.Stats); err == nil {
		t.Error("dumpRendererFor claims to format the per-CPU stats map as a per-IP table")
	}
	if _, err := dumpRendererFor("nope"); err == nil {
		t.Error("dumpRendererFor accepted an unknown map")
	}
}

func TestDumpNamedMapFailsWithoutPinnedMaps(t *testing.T) {
	if err := dumpNamedMap(io.Discard, "/nonexistent-pin-path", bpfmaps.Whitelist); err == nil {
		t.Error("dumpNamedMap succeeded with no pinned maps")
	}
	if err := dumpNamedMap(io.Discard, "/nonexistent-pin-path", "no_such_map"); err == nil {
		t.Error("dumpNamedMap accepted a map it has no format for")
	}
}

func TestWriteTimestampDump(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: secsAgo(90)},
		{key: [4]byte{10, 0, 0, 2}, val: uint64(testNow + 5_000_000_000)},
	}}
	wantRows(t, rendered(t, func(w io.Writer) error {
		return writeTimestampDump(w, m, testNow)
	}), []string{
		"IP AGE",
		"10.0.0.1 1m30s",
		"10.0.0.2 0s",
	})
}

func TestWriteCountDump(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: uint64(0)},
		{key: [4]byte{10, 0, 0, 2}, val: uint64(17)},
	}}
	wantRows(t, rendered(t, func(w io.Writer) error {
		return writeCountDump(w, m, testNow)
	}), []string{
		"IP OPEN",
		"10.0.0.1 0",
		"10.0.0.2 17",
	})
}

func TestWriteRatelimitDump(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: bpfmaps.Ratelimit{Tokens: 12, LastRefillNS: secsAgo(3)}},
	}}
	wantRows(t, rendered(t, func(w io.Writer) error {
		return writeRatelimitDump(w, m, testNow)
	}), []string{
		"IP TOKENS LAST_REFILL",
		"10.0.0.1 12 3s",
	})
}

func TestWriteHealthDumpShowsTimeLeftOnABlacklist(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: bpfmaps.UDPHealth{
			Anomalies: 5, WindowStartNS: secsAgo(10),
		}},
		{key: [4]byte{10, 0, 0, 2}, val: bpfmaps.UDPHealth{
			Anomalies: 400, WindowStartNS: secsAgo(3), BlacklistUntilNS: testNow + 60_000_000_000,
		}},
	}}
	wantRows(t, rendered(t, func(w io.Writer) error {
		return writeHealthDump(w, m, testNow)
	}), []string{
		"IP ANOMALIES WINDOW_AGE BLACKLIST",
		"10.0.0.1 5 10s -",
		"10.0.0.2 400 3s in 1m0s",
	})
}

func TestWriteDropHistoryDumpOrdersReasonsCanonically(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: dropHistory(secsAgo(4), map[string]uint64{
			"udp_ratelimit": 1, "tcp_no_syn": 2, "malformed": 3,
		})},
	}}
	wantRows(t, rendered(t, func(w io.Writer) error {
		return writeDropHistoryDump(w, m, testNow)
	}), []string{
		"IP FIRST_AGE LAST_AGE TOTAL BY_REASON",
		"10.0.0.1 10m0s 4s 6 tcp_no_syn=2,malformed=3,udp_ratelimit=1",
	})
}

func TestDumpRenderersPropagateIterationError(t *testing.T) {
	for _, name := range bpfmaps.PerIP {
		render, err := dumpRendererFor(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		m := &fakeMap{iterErr: errors.New("iteration aborted")}
		if err := render(io.Discard, m, testNow); err == nil {
			t.Errorf("%s: the dump swallowed an aborted iteration", name)
		}
	}
}

func TestWriteHealthTableHidesHealthyIPsByDefault(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: bpfmaps.UDPHealth{Anomalies: 5, WindowStartNS: secsAgo(10)}},
		{key: [4]byte{10, 0, 0, 2}, val: bpfmaps.UDPHealth{
			Anomalies: 400, WindowStartNS: secsAgo(3), BlacklistUntilNS: testNow + 90_000_000_000,
		}},
		{key: [4]byte{10, 0, 0, 3}, val: bpfmaps.UDPHealth{
			Anomalies: 9, WindowStartNS: secsAgo(1), BlacklistUntilNS: testNow,
		}},
	}}
	wantRows(t, rendered(t, func(w io.Writer) error {
		return writeHealthTable(w, m, testNow, false)
	}), []string{
		"IP ANOMALIES WINDOW_AGE BLACKLIST",
		"10.0.0.2 400 3s in 1m30s",
	})
	wantRows(t, rendered(t, func(w io.Writer) error {
		return writeHealthTable(w, m, testNow, true)
	}), []string{
		"IP ANOMALIES WINDOW_AGE BLACKLIST",
		"10.0.0.1 5 10s -",
		"10.0.0.2 400 3s in 1m30s",
		"10.0.0.3 9 1s -",
	})
}

func TestWriteHealthTablePropagatesIterationError(t *testing.T) {
	m := &fakeMap{iterErr: errors.New("iteration aborted")}
	if err := writeHealthTable(io.Discard, m, testNow, true); err == nil {
		t.Error("writeHealthTable swallowed an aborted iteration")
	}
}

func TestCountBlacklistedIgnoresExpiredBans(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: bpfmaps.UDPHealth{BlacklistUntilNS: testNow + 1}},
		{key: [4]byte{10, 0, 0, 2}, val: bpfmaps.UDPHealth{BlacklistUntilNS: testNow}},
		{key: [4]byte{10, 0, 0, 3}, val: bpfmaps.UDPHealth{}},
	}}
	n, err := countBlacklisted(m, testNow)
	if err != nil {
		t.Fatalf("countBlacklisted: %v", err)
	}
	if n != 1 {
		t.Errorf("countBlacklisted = %d, want 1: a ban expiring exactly now is over", n)
	}
}

func TestCountBlacklistedPropagatesIterationError(t *testing.T) {
	m := &fakeMap{iterErr: errors.New("iteration aborted")}
	if _, err := countBlacklisted(m, testNow); err == nil {
		t.Error("countBlacklisted swallowed an aborted iteration")
	}
}

func statsWith(t *testing.T, counts map[int]uint64) []uint64 {
	t.Helper()
	vals := make([]uint64, bpfmaps.StatMax)
	for slot, v := range counts {
		vals[slot] = v
	}
	return vals
}

func TestSummariseStatsGroupsDropsByProtocol(t *testing.T) {
	s := summariseStats(statsWith(t, map[int]uint64{
		bpfmaps.StatPassTCP:                     100,
		bpfmaps.StatPassUDPWhitelisted:          200,
		bpfmaps.StatDropMalformed:               1,
		bpfmaps.StatDropTCPNoSyn:                2,
		bpfmaps.StatDropTCPTooManyOpen:          4,
		bpfmaps.StatDropTCPGlobalRatelimit:      8,
		bpfmaps.StatDropTCPBadUserAgent:         16,
		bpfmaps.StatDropTCPInitconnectRatelimit: 32,
		bpfmaps.StatDropTCPGetinfoRatelimit:     64,
		bpfmaps.StatDropUDPNotWhitelisted:       3,
		bpfmaps.StatDropUDPExpired:              5,
		bpfmaps.StatDropUDPRatelimit:            7,
		bpfmaps.StatDropUDPUnhealthy:            9,
		bpfmaps.StatDropUDPEnetMalformed:        11,
		bpfmaps.StatDropIPFragment:              13,
		bpfmaps.StatTCPL7Promoted:               999,
	}))

	want := statsSummary{passTCP: 100, dropTCP: 127, passUDP: 200, dropUDP: 35, ipFragments: 13}
	if s != want {
		t.Errorf("summariseStats = %+v, want %+v", s, want)
	}
}

func TestSummariseStatsCountsMalformedAsTCP(t *testing.T) {
	s := summariseStats(statsWith(t, map[int]uint64{bpfmaps.StatDropMalformed: 6}))
	if s.dropTCP != 6 || s.dropUDP != 0 {
		t.Errorf("drop_malformed landed as (tcp %d, udp %d), want (6, 0)", s.dropTCP, s.dropUDP)
	}
}

func TestSummariseStatsKeepsFragmentsOutOfTheProtocolTotals(t *testing.T) {
	s := summariseStats(statsWith(t, map[int]uint64{bpfmaps.StatDropIPFragment: 13}))
	if s.dropTCP != 0 || s.dropUDP != 0 {
		t.Errorf("ip fragments were counted as protocol drops: %+v", s)
	}
	if s.ipFragments != 13 {
		t.Errorf("ipFragments = %d, want 13", s.ipFragments)
	}
}

func TestWriteStatsSummary(t *testing.T) {
	var b strings.Builder
	writeStatsSummary(&b, statsSummary{passTCP: 100, dropTCP: 7, passUDP: 200, dropUDP: 9, ipFragments: 3})
	wantRows(t, columns(b.String()), []string{
		"tcp: 100 pass / 7 drop",
		"udp: 200 pass / 9 drop",
		"ip fragments dropped: 3",
	})
}

func TestWriteStatsTextListsEveryLabelledSlot(t *testing.T) {
	vals := statsWith(t, map[int]uint64{bpfmaps.StatPassTCP: 42})
	var b strings.Builder
	if err := writeStats(&b, vals, false); err != nil {
		t.Fatalf("writeStats: %v", err)
	}
	rows := columns(b.String())
	if len(rows) != int(bpfmaps.StatMax) {
		t.Fatalf("got %d rows, want one per stat slot (%d)", len(rows), bpfmaps.StatMax)
	}
	if rows[bpfmaps.StatPassTCP] != "pass_tcp 42" {
		t.Errorf("pass_tcp row = %q", rows[bpfmaps.StatPassTCP])
	}
}

func TestWriteStatsJSONKeysEverySlotByLabel(t *testing.T) {
	vals := statsWith(t, map[int]uint64{
		bpfmaps.StatPassTCP:          42,
		bpfmaps.StatDropTCPNoSyn:     7,
		bpfmaps.StatTCPPostUAUnknown: 1,
	})
	var b strings.Builder
	if err := writeStats(&b, vals, true); err != nil {
		t.Fatalf("writeStats: %v", err)
	}
	var out map[string]uint64
	if err := json.Unmarshal([]byte(b.String()), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != int(bpfmaps.StatMax) {
		t.Errorf("JSON has %d keys, want %d", len(out), bpfmaps.StatMax)
	}
	for slot, want := range map[int]uint64{
		bpfmaps.StatPassTCP:          42,
		bpfmaps.StatDropTCPNoSyn:     7,
		bpfmaps.StatTCPPostUAUnknown: 1,
		bpfmaps.StatDropUDPExpired:   0,
	} {
		lbl := bpfmaps.StatLabels[slot]
		if out[lbl] != want {
			t.Errorf("%s = %d, want %d", lbl, out[lbl], want)
		}
	}
}

func TestInspectStepsCoverEveryPerIPMap(t *testing.T) {
	if len(inspectSteps) != len(bpfmaps.PerIP) {
		t.Fatalf("inspect covers %d maps, there are %d per-IP maps", len(inspectSteps), len(bpfmaps.PerIP))
	}
	for i, step := range inspectSteps {
		if step.name != bpfmaps.PerIP[i] {
			t.Errorf("inspect step %d is %s, want %s", i, step.name, bpfmaps.PerIP[i])
		}
	}
}

func inspectRow(t *testing.T, render func(w io.Writer, m bpfmaps.Reader, name string, key [4]byte, now uint64),
	name string, m *fakeMap,
) string {
	t.Helper()
	var b strings.Builder
	render(&b, m, name, [4]byte{10, 0, 0, 1}, testNow)
	rows := columns(b.String())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1:\n%s", len(rows), strings.Join(rows, "\n"))
	}
	return rows[0]
}

func oneEntry(val any) *fakeMap {
	return &fakeMap{entries: []fakeEntry{{key: [4]byte{10, 0, 0, 1}, val: val}}}
}

func TestInspectRendersEachValueKind(t *testing.T) {
	for _, tc := range []struct {
		name   string
		render func(w io.Writer, m bpfmaps.Reader, name string, key [4]byte, now uint64)
		m      *fakeMap
		want   string
	}{
		{
			bpfmaps.Whitelist, inspectTimestamp,
			oneEntry(secsAgo(65)),
			"tcp_whitelist age=1m5s",
		},
		{
			bpfmaps.OpenCount, inspectCount,
			oneEntry(uint64(4)),
			"tcp_open_count count=4",
		},
		{
			bpfmaps.UDPRatelimit, inspectRatelimit,
			oneEntry(bpfmaps.Ratelimit{Tokens: 900, LastRefillNS: secsAgo(2)}),
			"udp_ratelimit tokens=900 refill_age=2s",
		},
		{
			bpfmaps.Health, inspectHealth,
			oneEntry(bpfmaps.UDPHealth{Anomalies: 5, WindowStartNS: secsAgo(10)}),
			"udp_health anomalies=5 window_age=10s blacklisted=no",
		},
		{
			bpfmaps.Health, inspectHealth,
			oneEntry(bpfmaps.UDPHealth{
				Anomalies: 400, WindowStartNS: secsAgo(3), BlacklistUntilNS: testNow + 30_000_000_000,
			}),
			"udp_health anomalies=400 window_age=3s BLACKLISTED unblock_in=30s",
		},
		{
			bpfmaps.DropHistoryMap, inspectDropHistory,
			oneEntry(dropHistory(secsAgo(4), map[string]uint64{"tcp_no_syn": 2, "udp_ratelimit": 1})),
			"ip_drop_history first=10m0s last=4s total=3 tcp_no_syn=2,udp_ratelimit=1",
		},
		{
			bpfmaps.DropHistoryMap, inspectDropHistory,
			oneEntry(bpfmaps.DropHistory{}),
			"ip_drop_history first=16m40s last=16m40s total=0",
		},
	} {
		if got := inspectRow(t, tc.render, tc.name, tc.m); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestInspectReportsAMissingKeyAsADash(t *testing.T) {
	empty := &fakeMap{}
	if got := inspectRow(t, inspectTimestamp, bpfmaps.Whitelist, empty); got != "tcp_whitelist -" {
		t.Errorf("row = %q", got)
	}
	if got := inspectRow(t, inspectHealth, bpfmaps.Health, empty); got != "udp_health -" {
		t.Errorf("row = %q", got)
	}
}

func TestInspectReportsALookupFailureSeparately(t *testing.T) {
	broken := &fakeMap{lookupErr: errors.New("bad value size")}
	got := inspectRow(t, inspectCount, bpfmaps.OpenCount, broken)
	if !strings.HasPrefix(got, "tcp_open_count (lookup: ") {
		t.Errorf("a failed lookup was reported as %q, want it distinguished from a missing key", got)
	}
}

func TestInspectAllReportsUnopenableMaps(t *testing.T) {
	var b strings.Builder
	inspectAll(&b, "/nonexistent-pin-path", "10.0.0.1", [4]byte{10, 0, 0, 1}, testNow)
	rows := columns(b.String())
	if len(rows) != 1+len(bpfmaps.PerIP) {
		t.Fatalf("got %d rows, want a header plus one per map:\n%s", len(rows), strings.Join(rows, "\n"))
	}
	if rows[0] != "IP 10.0.0.1" {
		t.Errorf("header = %q", rows[0])
	}
	for i, name := range bpfmaps.PerIP {
		row := rows[i+1]
		if !strings.HasPrefix(row, name+" (open "+name+":") {
			t.Errorf("%s reported as %q", name, row)
		}
	}
}
