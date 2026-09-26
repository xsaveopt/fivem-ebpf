package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
	"github.com/xsaveopt/fivem-ebpf/internal/loader"
)

var (
	ipA = [4]byte{192, 0, 2, 10}
	ipB = [4]byte{198, 51, 100, 20}
	ipC = [4]byte{203, 0, 113, 30}
)

func skipIfUnprivileged(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, unix.EPERM) || errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("needs BPF privileges: %v", err)
	}
}

func realMap(t *testing.T, typ ebpf.MapType, valueSize, maxEntries uint32) *ebpf.Map {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("needs BPF privileges: %v", err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: typ, KeySize: 4, ValueSize: valueSize, MaxEntries: maxEntries})
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("create map: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func realLoaded(t *testing.T) *loader.Loaded {
	t.Helper()
	hash := func(valueSize uint32) *ebpf.Map { return realMap(t, ebpf.LRUHash, valueSize, 1024) }
	return &loader.Loaded{
		TCPEstablished:       hash(8),
		TCPSynSeen:           hash(8),
		TCPWhitelist:         hash(8),
		UDPRatelimit:         hash(16),
		InitConnectRatelimit: hash(16),
		GetInfoRatelimit:     hash(16),
		TCPGlobalRatelimit:   realMap(t, ebpf.PerCPUArray, 16, 1),
		TCPOpenCount:         hash(8),
		UDPHealth:            hash(24),
		IPDropHistory:        hash(8 * (2 + bpfmaps.NumDropReasons)),
		Stats:                realMap(t, ebpf.PerCPUArray, 8, bpfmaps.StatMax),
		XDPMode:              "generic",
	}
}

func put(t *testing.T, m *ebpf.Map, key [4]byte, val any) {
	t.Helper()
	if err := m.Put(&key, val); err != nil {
		t.Fatalf("put: %v", err)
	}
}

func setStat(t *testing.T, m *ebpf.Map, slot int, perCPU ...uint64) {
	t.Helper()
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible cpus: %v", err)
	}
	vals := make([]uint64, ncpu)
	copy(vals, perCPU)
	if err := m.Put(uint32(slot), vals); err != nil {
		t.Fatalf("put stat: %v", err)
	}
}

func TestStatsReportsEveryCounterSummedAcrossCPUs(t *testing.T) {
	l := realLoaded(t)
	setStat(t, l.Stats, bpfmaps.StatPassTCP, 3, 4)
	setStat(t, l.Stats, bpfmaps.StatDropIPFragment, 9)

	rec := serve(t, apiMux(apiCfg{Loaded: l}), "/api/stats")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var out map[string]uint64
	decode(t, rec.Body.Bytes(), &out)
	if len(out) != bpfmaps.StatMax {
		t.Errorf("got %d counters, want %d", len(out), bpfmaps.StatMax)
	}
	for i, lbl := range bpfmaps.StatLabels {
		want := uint64(0)
		switch i {
		case bpfmaps.StatPassTCP:
			want = 7
		case bpfmaps.StatDropIPFragment:
			want = 9
		}
		if got, ok := out[lbl]; !ok || got != want {
			t.Errorf("%s = %d (present %v), want %d", lbl, got, ok, want)
		}
	}
}

func TestMapPopulationsCountsEveryPerIPMap(t *testing.T) {
	l := realLoaded(t)
	put(t, l.TCPWhitelist, ipA, uint64(1))
	put(t, l.TCPWhitelist, ipB, uint64(1))
	put(t, l.TCPEstablished, ipC, uint64(1))
	put(t, l.UDPHealth, ipA, bpfmaps.UDPHealth{Anomalies: 1})

	got, err := mapPopulations(l)
	if err != nil {
		t.Fatalf("mapPopulations: %v", err)
	}
	want := map[string]int64{}
	for _, name := range bpfmaps.PerIP {
		want[name] = 0
	}
	want[bpfmaps.Whitelist] = 2
	want[bpfmaps.Established] = 1
	want[bpfmaps.Health] = 1
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestInfoReportsConfigurationPopulationsAndCounters(t *testing.T) {
	l := realLoaded(t)
	l.XDPLink = fakeLink{}
	put(t, l.TCPOpenCount, ipA, uint64(3))
	setStat(t, l.Stats, bpfmaps.StatPassUDPWhitelisted, 11)
	cfg := apiCfg{
		Loaded:  l,
		Version: "v1.2.3",
		Iface:   "eth9",
		Port:    30120,
		PinPath: "/sys/fs/bpf/fivem-test",
		Limits: apiLimits{
			UDPRatePerSec: 1500,
			UDPBurst:      4500,
			WhitelistTTL:  10 * time.Minute,
			DropHistory:   true,
		},
	}

	rec := serve(t, apiMux(cfg), "/api/info")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var out struct {
		Version  string            `json:"version"`
		Iface    string            `json:"iface"`
		Port     uint16            `json:"port"`
		PinPath  string            `json:"pin_path"`
		XDPMode  string            `json:"xdp_mode"`
		Attached map[string]bool   `json:"attached"`
		Limits   apiLimits         `json:"limits"`
		Maps     map[string]int64  `json:"maps"`
		Counters map[string]uint64 `json:"counters"`
	}
	decode(t, rec.Body.Bytes(), &out)
	if out.Version != "v1.2.3" || out.Iface != "eth9" || out.Port != 30120 ||
		out.PinPath != "/sys/fs/bpf/fivem-test" || out.XDPMode != "generic" {
		t.Errorf("header fields = %+v", out)
	}
	if !reflect.DeepEqual(out.Attached, map[string]bool{"xdp": true, "sockops": false}) {
		t.Errorf("attached = %v", out.Attached)
	}
	if out.Limits != cfg.Limits {
		t.Errorf("limits = %+v, want %+v", out.Limits, cfg.Limits)
	}
	if len(out.Maps) != len(bpfmaps.PerIP) || out.Maps[bpfmaps.OpenCount] != 1 || out.Maps[bpfmaps.Whitelist] != 0 {
		t.Errorf("maps = %v", out.Maps)
	}
	if out.Counters["pass_udp_whitelisted"] != 11 || len(out.Counters) != bpfmaps.StatMax {
		t.Errorf("counters = %v", out.Counters)
	}

	var raw map[string]json.RawMessage
	decode(t, rec.Body.Bytes(), &raw)
	if len(raw) != 9 {
		t.Errorf("info has %d top-level keys, want 9: %s", len(raw), rec.Body)
	}
}

func TestTopRanksARealMap(t *testing.T) {
	l := realLoaded(t)
	put(t, l.TCPOpenCount, ipA, uint64(2))
	put(t, l.TCPOpenCount, ipB, uint64(9))
	put(t, l.TCPOpenCount, ipC, uint64(5))

	rec := serve(t, apiMux(apiCfg{Loaded: l}), "/api/top?map=open-count&n=2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var rows []topRow
	decode(t, rec.Body.Bytes(), &rows)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].IP != "198.51.100.20" || rows[0].Count != 9 || rows[1].IP != "203.0.113.30" || rows[1].Count != 5 {
		t.Errorf("rows = %+v", rows)
	}
}

func TestTopRanksDropHistoryByAReason(t *testing.T) {
	now := bootNow(t)
	l := realLoaded(t)
	mal, _ := dropReasonIndex("malformed")
	rl, _ := dropReasonIndex("udp_ratelimit")
	var a, b bpfmaps.DropHistory
	a.LastDropNS, b.LastDropNS = now-5*nsPerSec, now-8*nsPerSec
	a.Counts[mal], a.Counts[rl] = 1, 50
	b.Counts[mal] = 7
	put(t, l.IPDropHistory, ipA, a)
	put(t, l.IPDropHistory, ipB, b)

	rec := serve(t, apiMux(apiCfg{Loaded: l}), "/api/top?map=drop-history&reason=malformed")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var rows []topRow
	decode(t, rec.Body.Bytes(), &rows)
	if len(rows) != 2 || rows[0].IP != "198.51.100.20" || rows[1].IP != "192.0.2.10" {
		t.Fatalf("rows = %+v, want the most malformed first", rows)
	}
	if rows[1].Total != 51 || !within(rows[1].AgeSeconds, 5) {
		t.Errorf("row = %+v", rows[1])
	}
	if !reflect.DeepEqual(rows[1].ByReason, map[string]uint64{"malformed": 1, "udp_ratelimit": 50}) {
		t.Errorf("by_reason = %v", rows[1].ByReason)
	}

	bad := serve(t, apiMux(apiCfg{Loaded: l}), "/api/top?map=drop-history&reason=bogus")
	if bad.Code != http.StatusBadRequest {
		t.Errorf("unknown reason on a loaded map: status %d, want 400", bad.Code)
	}
}

func TestIPLookupReportsEveryMapForAnAddress(t *testing.T) {
	now := bootNow(t)
	l := realLoaded(t)
	put(t, l.TCPWhitelist, ipA, now-12*nsPerSec)
	put(t, l.TCPEstablished, ipA, now-40*nsPerSec)
	put(t, l.TCPOpenCount, ipA, uint64(4))
	put(t, l.UDPRatelimit, ipA, bpfmaps.Ratelimit{Tokens: 99, LastRefillNS: now - 2*nsPerSec})
	put(t, l.UDPHealth, ipA, bpfmaps.UDPHealth{
		Anomalies: 5, WindowStartNS: now - 20*nsPerSec, BlacklistUntilNS: now + 60*nsPerSec,
	})
	var hist bpfmaps.DropHistory
	hist.FirstDropNS, hist.LastDropNS = now-90*nsPerSec, now-3*nsPerSec
	hist.Counts[0] = 2
	put(t, l.IPDropHistory, ipA, hist)
	put(t, l.TCPWhitelist, ipB, now)

	rec := serve(t, apiMux(apiCfg{Loaded: l}), "/api/ip/192.0.2.10")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var out map[string]map[string]any
	var ip struct {
		IP string `json:"ip"`
	}
	decode(t, rec.Body.Bytes(), &ip)
	if ip.IP != "192.0.2.10" {
		t.Errorf("ip = %q", ip.IP)
	}
	var raw map[string]json.RawMessage
	decode(t, rec.Body.Bytes(), &raw)
	delete(raw, "ip")
	b, _ := json.Marshal(raw)
	decode(t, b, &out)

	num := func(section, field string) float64 {
		v, _ := out[section][field].(float64)
		return v
	}
	for _, c := range []struct {
		section, field string
		want           float64
	}{
		{"tcp_whitelist", "age_seconds", 12},
		{"tcp_established", "age_seconds", 40},
		{"tcp_open_count", "count", 4},
		{"udp_ratelimit", "tokens", 99},
		{"udp_ratelimit", "last_refill_age_seconds", 2},
		{"udp_health", "anomalies", 5},
		{"udp_health", "window_age_seconds", 20},
		{"udp_health", "blacklist_remaining_seconds", 60},
		{"drop_history", "total", 2},
		{"drop_history", "first_drop_age_seconds", 90},
		{"drop_history", "last_drop_age_seconds", 3},
	} {
		if got := num(c.section, c.field); !within(int64(got), int64(c.want)) {
			t.Errorf("%s.%s = %v, want about %v", c.section, c.field, got, c.want)
		}
	}
	if out["udp_health"]["blacklisted"] != true {
		t.Errorf("udp_health.blacklisted = %v", out["udp_health"]["blacklisted"])
	}
	for _, absent := range []string{"tcp_syn_seen", "initconnect_ratelimit", "getinfo_ratelimit"} {
		if v, ok := out[absent]; !ok || v != nil {
			t.Errorf("%s = %v (present %v), want null for an address the map does not hold", absent, v, ok)
		}
	}
}
