package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

type fakeEntry struct {
	key [4]byte
	val any
}

type fakeMap struct {
	entries []fakeEntry
	iterErr error
}

func (f *fakeMap) Iterate() bpfmaps.Iterator { return &fakeIter{m: f} }

func (f *fakeMap) Lookup(key, valueOut any) error {
	k := *key.(*[4]byte)
	for _, e := range f.entries {
		if e.key == k {
			assign(valueOut, e.val)
			return nil
		}
	}
	return errors.New("not found")
}

type fakeIter struct {
	m *fakeMap
	i int
}

func (it *fakeIter) Next(keyOut, valueOut any) bool {
	if it.i >= len(it.m.entries) {
		return false
	}
	e := it.m.entries[it.i]
	it.i++
	*keyOut.(*[4]byte) = e.key
	assign(valueOut, e.val)
	return true
}

func (it *fakeIter) Err() error { return it.m.iterErr }

func assign(dst, src any) {
	reflect.ValueOf(dst).Elem().Set(reflect.ValueOf(src))
}

func health(anomalies uint32, windowStart, blacklistUntil uint64) bpfmaps.UDPHealth {
	return bpfmaps.UDPHealth{
		Anomalies:        anomalies,
		WindowStartNS:    windowStart,
		BlacklistUntilNS: blacklistUntil,
	}
}

func newTestCollector() *Collector {
	return NewCollector(
		Maps{},
		"eth0", 30120, "v1.2.3",
		func() bool { return true },
		func() bool { return false },
	)
}

func statsReturning(sums []uint64) func(*ebpf.Map) ([]uint64, error) {
	return func(*ebpf.Map) ([]uint64, error) { return sums, nil }
}

func statsFailing() func(*ebpf.Map) ([]uint64, error) {
	return func(*ebpf.Map) ([]uint64, error) { return nil, errors.New("stats map not available") }
}

func countingSums() []uint64 {
	sums := make([]uint64, bpfmaps.StatMax)
	for i := range sums {
		sums[i] = uint64(i+1) * 10
	}
	return sums
}

func expose(t *testing.T, c *Collector, name string) []string {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape returned %d: %s", rec.Code, rec.Body)
	}

	var out []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "+name+" "),
			strings.HasPrefix(line, "# TYPE "+name+" "),
			strings.HasPrefix(line, name+" "),
			strings.HasPrefix(line, name+"{"):
			out = append(out, line)
		}
	}
	return out
}

func compare(t *testing.T, c *Collector, name string, want ...string) {
	t.Helper()
	got := expose(t, c, name)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s exposition:\ngot:\n%s\nwant:\n%s",
			name, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestCountHealthCountsBlacklistedSeparately(t *testing.T) {
	const now = 1_000_000_000_000
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: health(3, now-1, now+1)},
		{key: [4]byte{10, 0, 0, 2}, val: health(1, now-1, now)},
		{key: [4]byte{10, 0, 0, 3}, val: health(0, now-1, 0)},
		{key: [4]byte{10, 0, 0, 4}, val: health(9, now-1, now+5_000_000_000)},
	}}
	total, blacklisted, err := countHealth(m, now)
	if err != nil {
		t.Fatalf("countHealth: %v", err)
	}
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	if blacklisted != 2 {
		t.Errorf("blacklisted = %d, want 2: an expiry exactly at now is not blacklisted", blacklisted)
	}
}

func TestCountHealthNilMapReportsUnknown(t *testing.T) {
	total, blacklisted, err := countHealth(nil, 0)
	if err != nil {
		t.Fatalf("countHealth: %v", err)
	}
	if total != -1 || blacklisted != -1 {
		t.Errorf("countHealth(nil) = (%d, %d), want (-1, -1) so the gauges stay unset", total, blacklisted)
	}
}

func TestCountHealthPropagatesIterationError(t *testing.T) {
	m := &fakeMap{
		entries: []fakeEntry{{key: [4]byte{10, 0, 0, 1}, val: health(1, 0, 0)}},
		iterErr: errors.New("iteration aborted"),
	}
	if _, _, err := countHealth(m, 1); err == nil {
		t.Error("countHealth swallowed an aborted iteration")
	}
}

func TestRefreshSizesMarksAbsentMapsUnknown(t *testing.T) {
	c := newTestCollector()
	c.refreshSizes()

	for _, tc := range []struct {
		name string
		got  *atomic.Int64
	}{
		{bpfmaps.Whitelist, &c.sizes.whitelist},
		{bpfmaps.Established, &c.sizes.established},
		{bpfmaps.SynSeen, &c.sizes.synSeen},
		{bpfmaps.OpenCount, &c.sizes.openCount},
		{bpfmaps.UDPRatelimit, &c.sizes.udpRL},
		{bpfmaps.InitConnectRatelimit, &c.sizes.initcRL},
		{bpfmaps.GetInfoRatelimit, &c.sizes.getinfoRL},
		{bpfmaps.DropHistoryMap, &c.sizes.dropHistory},
	} {
		if got := tc.got.Load(); got != -1 {
			t.Errorf("%s size = %d after a refresh with no map, want -1", tc.name, got)
		}
	}
}

func TestDescribeCoversEveryCollectedMetric(t *testing.T) {
	c := newTestCollector()
	c.readStats = statsReturning(countingSums())

	descs := make(chan *prometheus.Desc, 64)
	c.Describe(descs)
	close(descs)

	described := map[string]bool{}
	for d := range descs {
		s := d.String()
		if described[s] {
			t.Errorf("Describe emitted %s twice", s)
		}
		described[s] = true
	}
	if len(described) != 11 {
		t.Errorf("Describe emitted %d descriptors, want 11", len(described))
	}

	collected := make(chan prometheus.Metric, 256)
	c.Collect(collected)
	close(collected)
	n := 0
	for m := range collected {
		n++
		if !described[m.Desc().String()] {
			t.Errorf("Collect emitted an undescribed metric: %s", m.Desc())
		}
	}
	if n == 0 {
		t.Error("Collect emitted nothing")
	}
}

func TestCollectLabelsEveryPacketStatSlot(t *testing.T) {
	sums := countingSums()
	c := newTestCollector()
	c.readStats = statsReturning(sums)

	var series []string
	for _, tc := range []struct {
		verdict, proto, reason string
		slot                   int
	}{
		{"pass", "tcp", "", bpfmaps.StatPassTCP},
		{"pass", "udp", "whitelisted", bpfmaps.StatPassUDPWhitelisted},
		{"drop", "udp", "not_whitelisted", bpfmaps.StatDropUDPNotWhitelisted},
		{"drop", "udp", "expired", bpfmaps.StatDropUDPExpired},
		{"drop", "udp", "ratelimit", bpfmaps.StatDropUDPRatelimit},
		{"drop", "udp", "enet_malformed", bpfmaps.StatDropUDPEnetMalformed},
		{"drop", "udp", "unhealthy", bpfmaps.StatDropUDPUnhealthy},
		{"drop", "tcp", "malformed", bpfmaps.StatDropMalformed},
		{"drop", "tcp", "initconnect_ratelimit", bpfmaps.StatDropTCPInitconnectRatelimit},
		{"drop", "tcp", "getinfo_ratelimit", bpfmaps.StatDropTCPGetinfoRatelimit},
		{"drop", "tcp", "bad_user_agent", bpfmaps.StatDropTCPBadUserAgent},
		{"drop", "tcp", "no_syn", bpfmaps.StatDropTCPNoSyn},
		{"drop", "tcp", "global_ratelimit", bpfmaps.StatDropTCPGlobalRatelimit},
		{"drop", "tcp", "too_many_open", bpfmaps.StatDropTCPTooManyOpen},
		{"drop", "ip", "fragment", bpfmaps.StatDropIPFragment},
	} {
		series = append(series, fmt.Sprintf(
			"fivem_xdp_packets_total{proto=%q,reason=%q,verdict=%q} %d",
			tc.proto, tc.reason, tc.verdict, sums[tc.slot]))
	}
	sort.Strings(series)

	lines := []string{
		"# HELP fivem_xdp_packets_total Packets observed by the FiveM XDP filter.",
		"# TYPE fivem_xdp_packets_total counter",
	}
	compare(t, c, "fivem_xdp_packets_total", append(lines, series...)...)
}

func TestCollectMapsEverySingletonCounter(t *testing.T) {
	sums := countingSums()
	c := newTestCollector()
	c.readStats = statsReturning(sums)

	for _, tc := range []struct {
		name, help string
		slot       int
	}{
		{
			"fivem_tcp_established_inserts_total",
			"TCP connections promoted to tcp_established by sockops (3WHS completed on port).",
			bpfmaps.StatTCPEstablishedInserts,
		},
		{
			"fivem_tcp_l7_promoted_total",
			"IPs promoted to tcp_whitelist after L7 match + TCP established confirmation.",
			bpfmaps.StatTCPL7Promoted,
		},
		{
			"fivem_tcp_l7_match_no_established_total",
			"L7 pattern matched on a TCP segment but tcp_established missing (spoofed or racy).",
			bpfmaps.StatTCPL7MatchNoEst,
		},
		{
			"fivem_tcp_post_client_seen_total",
			"TCP data segments matching POST /client at offset 0 (regardless of verdict).",
			bpfmaps.StatTCPPostClientSeen,
		},
		{
			"fivem_tcp_post_client_ua_unknown_total",
			"POST /client segments carrying no recognisable User-Agent, so no promotion happened.",
			bpfmaps.StatTCPPostUAUnknown,
		},
		{
			"fivem_tcp_getinfo_seen_total",
			"TCP data segments matching GET /info.json, /dynamic.json, or /players.json (regardless of verdict).",
			bpfmaps.StatTCPGetinfoSeen,
		},
	} {
		compare(t, c, tc.name,
			"# HELP "+tc.name+" "+tc.help,
			"# TYPE "+tc.name+" counter",
			fmt.Sprintf("%s %d", tc.name, sums[tc.slot]))
	}
}

func TestCollectSkipsPacketCountersWhenStatsUnreadable(t *testing.T) {
	c := newTestCollector()
	c.readStats = statsFailing()

	for _, name := range []string{
		"fivem_xdp_packets_total",
		"fivem_tcp_established_inserts_total",
		"fivem_tcp_l7_promoted_total",
		"fivem_tcp_getinfo_seen_total",
	} {
		if lines := expose(t, c, name); len(lines) != 0 {
			t.Errorf("%s was exposed from an unreadable stats map:\n%s", name, strings.Join(lines, "\n"))
		}
	}
	compare(t, c, "fivem_build_info",
		"# HELP fivem_build_info Build and runtime configuration.",
		"# TYPE fivem_build_info gauge",
		`fivem_build_info{iface="eth0",port="30120",version="v1.2.3"} 1`)
}

func TestCollectReportsAttachmentState(t *testing.T) {
	c := newTestCollector()
	c.readStats = statsFailing()

	compare(t, c, "fivem_attached",
		"# HELP fivem_attached Program attachment state (1=attached, 0=not).",
		"# TYPE fivem_attached gauge",
		`fivem_attached{program="sockops"} 0`,
		`fivem_attached{program="xdp"} 1`)
}

func TestCollectOmitsUnknownMapSizes(t *testing.T) {
	c := newTestCollector()
	c.readStats = statsFailing()
	c.sizes.whitelist.Store(7)
	c.sizes.established.Store(0)
	c.sizes.synSeen.Store(-1)
	c.sizes.openCount.Store(-1)
	c.sizes.udpRL.Store(-1)
	c.sizes.initcRL.Store(-1)
	c.sizes.getinfoRL.Store(-1)
	c.sizes.health.Store(3)
	c.sizes.dropHistory.Store(-1)
	c.sizes.blacklisted.Store(2)

	compare(t, c, "fivem_map_entries",
		"# HELP fivem_map_entries Number of entries in each pinned IP-keyed map "+
			"(refreshed by background ticker, default every 30s).",
		"# TYPE fivem_map_entries gauge",
		`fivem_map_entries{map="tcp_established"} 0`,
		`fivem_map_entries{map="tcp_whitelist"} 7`,
		`fivem_map_entries{map="udp_health"} 3`)
	compare(t, c, "fivem_health_blacklisted_ips",
		"# HELP fivem_health_blacklisted_ips IPs currently in the udp_health blacklist "+
			"(blacklist_until_ns > now).",
		"# TYPE fivem_health_blacklisted_ips gauge",
		"fivem_health_blacklisted_ips 2")
}

func TestStartSizeTickerDisabledByNonPositiveInterval(t *testing.T) {
	c := newTestCollector()
	c.sizes.whitelist.Store(42)

	c.StartSizeTicker(t.Context(), 0)()

	if got := c.sizes.whitelist.Load(); got != 42 {
		t.Errorf("whitelist size = %d, want the gauge left untouched at 42", got)
	}
}

func TestStartSizeTickerRefreshesOnceThenStops(t *testing.T) {
	c := newTestCollector()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.StartSizeTicker(ctx, time.Hour)()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the size ticker did not stop after its context was cancelled")
	}
	if got := c.sizes.whitelist.Load(); got != -1 {
		t.Errorf("whitelist size = %d, want -1 from the initial refresh", got)
	}
}

func TestBoolToF(t *testing.T) {
	if boolToF(true) != 1 || boolToF(false) != 0 {
		t.Errorf("boolToF gave (%v, %v), want (1, 0)", boolToF(true), boolToF(false))
	}
}
