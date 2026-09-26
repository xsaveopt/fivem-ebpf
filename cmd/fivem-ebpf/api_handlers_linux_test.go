package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
	"github.com/xsaveopt/fivem-ebpf/internal/loader"
)

const nsPerSec = 1_000_000_000

func bootNow(t *testing.T) uint64 {
	t.Helper()
	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		t.Fatalf("BootTimeNS: %v", err)
	}
	if now < 1000*nsPerSec {
		t.Skip("boot clock too young to place timestamps in the past")
	}
	return now
}

func within(got, want int64) bool { return got >= want-1 && got <= want+1 }

func decode(t *testing.T, body []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}

func TestTimestampMapReportsAges(t *testing.T) {
	now := bootNow(t)
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: now - 30*nsPerSec},
		{key: [4]byte{10, 0, 0, 2}, val: now + 60*nsPerSec},
	}}
	rec := serve(t, handleTimestampMap(m), "/api/whitelist")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var out []timestampEntry
	decode(t, rec.Body.Bytes(), &out)
	if len(out) != 2 {
		t.Fatalf("got %d rows, want 2", len(out))
	}
	if out[0].IP != "10.0.0.1" || !within(out[0].AgeSeconds, 30) {
		t.Errorf("row 0 = %+v, want 10.0.0.1 aged about 30s", out[0])
	}
	if out[1].AgeSeconds != 0 {
		t.Errorf("a future timestamp gave age %d, want 0", out[1].AgeSeconds)
	}
}

func TestBlacklistListsOnlyActiveBans(t *testing.T) {
	now := bootNow(t)
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: bpfmaps.UDPHealth{
			Anomalies: 7, WindowStartNS: now - 20*nsPerSec, BlacklistUntilNS: now + 300*nsPerSec,
		}},
		{key: [4]byte{10, 0, 0, 2}, val: bpfmaps.UDPHealth{
			Anomalies: 9, WindowStartNS: now - 20*nsPerSec, BlacklistUntilNS: now - nsPerSec,
		}},
		{key: [4]byte{10, 0, 0, 3}, val: bpfmaps.UDPHealth{Anomalies: 1, WindowStartNS: now - 5*nsPerSec}},
	}}
	rec := serve(t, handleBlacklist(m), "/api/blacklist")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var out []blacklistEntry
	decode(t, rec.Body.Bytes(), &out)
	if len(out) != 1 {
		t.Fatalf("got %d rows, want only the active ban: %+v", len(out), out)
	}
	e := out[0]
	if e.IP != "10.0.0.1" || e.Anomalies != 7 {
		t.Errorf("row = %+v", e)
	}
	if !within(e.WindowAgeSeconds, 20) {
		t.Errorf("window age = %d, want about 20", e.WindowAgeSeconds)
	}
	if !within(e.BlacklistRemainingSeconds, 300) {
		t.Errorf("remaining = %d, want about 300", e.BlacklistRemainingSeconds)
	}
}

func TestHealthHidesHealthyIPsUnlessAllIsSet(t *testing.T) {
	now := bootNow(t)
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: bpfmaps.UDPHealth{
			Anomalies: 7, WindowStartNS: now - 20*nsPerSec, BlacklistUntilNS: now + 300*nsPerSec,
		}},
		{key: [4]byte{10, 0, 0, 2}, val: bpfmaps.UDPHealth{Anomalies: 1, WindowStartNS: now - 5*nsPerSec}},
	}}

	var def []healthEntry
	decode(t, serve(t, handleHealth(m), "/api/health").Body.Bytes(), &def)
	if len(def) != 1 || def[0].IP != "10.0.0.1" || !def[0].Blacklisted {
		t.Fatalf("default listing = %+v, want only the blacklisted IP", def)
	}
	if !within(def[0].BlacklistRemainingSeconds, 300) {
		t.Errorf("remaining = %d, want about 300", def[0].BlacklistRemainingSeconds)
	}

	var all []healthEntry
	decode(t, serve(t, handleHealth(m), "/api/health?all=1").Body.Bytes(), &all)
	if len(all) != 2 {
		t.Fatalf("?all=1 listing = %+v, want both IPs", all)
	}
	h := all[1]
	if h.IP != "10.0.0.2" || h.Blacklisted || h.BlacklistRemainingSeconds != 0 || h.Anomalies != 1 {
		t.Errorf("healthy row = %+v", h)
	}
	if !within(h.WindowAgeSeconds, 5) {
		t.Errorf("window age = %d, want about 5", h.WindowAgeSeconds)
	}

	var other []healthEntry
	decode(t, serve(t, handleHealth(m), "/api/health?all=true").Body.Bytes(), &other)
	if len(other) != 1 {
		t.Errorf("?all=true listed %d rows, only all=1 should widen the listing", len(other))
	}
}

func TestDropHistoryReportsTotalsAndReasons(t *testing.T) {
	now := bootNow(t)
	var v bpfmaps.DropHistory
	v.FirstDropNS = now - 100*nsPerSec
	v.LastDropNS = now - 10*nsPerSec
	mal, _ := dropReasonIndex("malformed")
	frag, _ := dropReasonIndex("ip_fragment")
	v.Counts[mal] = 4
	v.Counts[frag] = 2
	m := &fakeMap{entries: []fakeEntry{{key: [4]byte{10, 0, 0, 1}, val: v}}}

	rec := serve(t, handleDropHistory(m), "/api/drop-history")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var out []dropHistoryEntry
	decode(t, rec.Body.Bytes(), &out)
	if len(out) != 1 {
		t.Fatalf("got %d rows, want 1", len(out))
	}
	e := out[0]
	if e.IP != "10.0.0.1" || e.Total != 6 {
		t.Errorf("row = %+v", e)
	}
	if !within(e.FirstDropAgeSeconds, 100) || !within(e.LastDropAgeSeconds, 10) {
		t.Errorf("ages = %d/%d, want about 100/10", e.FirstDropAgeSeconds, e.LastDropAgeSeconds)
	}
	if !reflect.DeepEqual(e.ByReason, map[string]uint64{"malformed": 4, "ip_fragment": 2}) {
		t.Errorf("by_reason = %v", e.ByReason)
	}
}

func TestClockedHandlersFailOnAnAbortedIteration(t *testing.T) {
	quietLog(t)
	aborted := func(val any) *fakeMap {
		return &fakeMap{
			entries: []fakeEntry{{key: [4]byte{10, 0, 0, 1}, val: val}},
			iterErr: errors.New("iteration aborted"),
		}
	}
	for name, h := range map[string]http.HandlerFunc{
		"timestamp":    handleTimestampMap(aborted(uint64(0))),
		"blacklist":    handleBlacklist(aborted(bpfmaps.UDPHealth{})),
		"health":       handleHealth(aborted(bpfmaps.UDPHealth{})),
		"drop-history": handleDropHistory(aborted(bpfmaps.DropHistory{})),
	} {
		rec := serve(t, h, "/?all=1")
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status %d, want 500 for a truncated listing", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "iterate") {
			t.Errorf("%s: body %q", name, rec.Body)
		}
	}
}

func TestIPLookupWithNoMapsLoadedReportsNulls(t *testing.T) {
	rec := serve(t, apiMux(apiCfg{Loaded: &loader.Loaded{}}), "/api/ip/192.0.2.7")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var out map[string]any
	decode(t, rec.Body.Bytes(), &out)
	if out["ip"] != "192.0.2.7" {
		t.Errorf("ip = %v", out["ip"])
	}
	fields := []string{
		"tcp_whitelist", "tcp_established", "tcp_syn_seen", "tcp_open_count",
		"udp_ratelimit", "initconnect_ratelimit", "getinfo_ratelimit",
		"udp_health", "drop_history",
	}
	for _, name := range fields {
		v, ok := out[name]
		if !ok {
			t.Errorf("%s missing from the lookup", name)
			continue
		}
		if v != nil {
			t.Errorf("%s = %v, want null for a map that is not loaded", name, v)
		}
	}
	if len(out) != 1+len(fields) {
		t.Errorf("lookup has %d keys, want ip plus one per map", len(out))
	}
}

func TestCmdInspectReportsEveryMapForAnAddress(t *testing.T) {
	out := capture(t, &os.Stdout, func() {
		cmdInspect([]string{"--pin-path", "/nonexistent-pin-path", "10.0.0.1"})
	})
	rows := columns(out)
	if len(rows) != 1+len(bpfmaps.PerIP) {
		t.Fatalf("got %d rows, want a header plus one per map:\n%s", len(rows), out)
	}
	if rows[0] != "IP 10.0.0.1" {
		t.Errorf("header = %q", rows[0])
	}
}
