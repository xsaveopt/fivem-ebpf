package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/link"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
	"github.com/xsaveopt/fivem-ebpf/internal/loader"
)

type fakeLink struct{ link.Link }

func serve(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func quietLog(t *testing.T) {
	t.Helper()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })
}

func apiMux(cfg apiCfg) *http.ServeMux {
	mux := http.NewServeMux()
	registerAPI(mux, cfg)
	return mux
}

func TestWriteJSONSetsHeadersAndKeepsHTMLUnescaped(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, map[string]string{"k": "<a&b>"})

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	want := "{\n  \"k\": \"<a&b>\"\n}\n"
	if rec.Body.String() != want {
		t.Errorf("body = %q, want %q", rec.Body.String(), want)
	}
}

func TestListHandlersOnAMissingMapReturnAnEmptyArray(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"timestamp":    handleTimestampMap(nil),
		"count":        handleCountMap(nil),
		"blacklist":    handleBlacklist(nil),
		"health":       handleHealth(nil),
		"drop-history": handleDropHistory(nil),
	} {
		rec := serve(t, h, "/")
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, body %s", name, rec.Code, rec.Body)
			continue
		}
		if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
			t.Errorf("%s: body %q, want [] rather than null", name, got)
		}
	}
}

func TestCountMapReportsEachEntry(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: uint64(4)},
		{key: [4]byte{10, 0, 0, 2}, val: uint64(7)},
	}}
	rec := serve(t, handleCountMap(m), "/api/open-count")
	var out []countEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []countEntry{{IP: "10.0.0.1", Count: 4}, {IP: "10.0.0.2", Count: 7}}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("got %+v, want %+v", out, want)
	}
}

func TestHealthzReportsDegradedWhenAProgramIsDetached(t *testing.T) {
	for name, l := range map[string]*loader.Loaded{
		"nothing": {},
		"xdp":     {XDPLink: fakeLink{}},
		"sockops": {SockopsLink: fakeLink{}},
	} {
		rec := serve(t, handleHealthz(l), "/health")
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s attached: status %d, want 503", name, rec.Code)
		}
		if rec.Body.String() != "degraded" {
			t.Errorf("%s attached: body %q", name, rec.Body)
		}
	}
}

func TestHealthzReportsUpWhenBothProgramsAreAttached(t *testing.T) {
	rec := serve(t, handleHealthz(&loader.Loaded{XDPLink: fakeLink{}, SockopsLink: fakeLink{}}), "/health")
	if rec.Code != http.StatusOK {
		t.Errorf("status %d, want 200", rec.Code)
	}
	if rec.Body.String() != "up" {
		t.Errorf("body %q, want up", rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestReadCountersWithoutAStatsMapIsAnError(t *testing.T) {
	if _, err := readCounters(&loader.Loaded{}); err == nil {
		t.Error("readCounters succeeded with no stats map")
	}
}

func TestMapPopulationsMarksUnloadedMapsWithMinusOne(t *testing.T) {
	got, err := mapPopulations(&loader.Loaded{})
	if err != nil {
		t.Fatalf("mapPopulations: %v", err)
	}
	if len(got) != len(bpfmaps.PerIP) {
		t.Errorf("got %d maps, want %d", len(got), len(bpfmaps.PerIP))
	}
	for _, name := range bpfmaps.PerIP {
		n, ok := got[name]
		if !ok {
			t.Errorf("%s missing from the populations", name)
			continue
		}
		if n != -1 {
			t.Errorf("%s = %d, want -1 for a map that is not loaded", name, n)
		}
	}
}

func TestStatsAndInfoFailWithoutAStatsMap(t *testing.T) {
	quietLog(t)
	cfg := apiCfg{Loaded: &loader.Loaded{}}
	for name, h := range map[string]http.HandlerFunc{
		"stats": handleStats(cfg.Loaded),
		"info":  handleInfo(cfg),
	} {
		rec := serve(t, h, "/")
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status %d, want 500", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "read counters") {
			t.Errorf("%s: body %q", name, rec.Body)
		}
	}
}

func TestTopRejectsBadQueries(t *testing.T) {
	h := handleTop(apiCfg{Loaded: &loader.Loaded{}})
	for _, tc := range []struct {
		target string
		code   int
		body   string
	}{
		{"/api/top", http.StatusBadRequest, "missing ?map="},
		{"/api/top?map=whitelist&n=0", http.StatusBadRequest, "n must be a positive integer"},
		{"/api/top?map=whitelist&n=abc", http.StatusBadRequest, "n must be a positive integer"},
		{"/api/top?map=nope", http.StatusBadRequest, "unknown map: nope"},
		{"/api/top?map=tcp_whitelist", http.StatusBadRequest, "unknown map: tcp_whitelist"},
		{"/api/top?map=whitelist", http.StatusServiceUnavailable, "map not loaded: " + bpfmaps.Whitelist},
		{"/api/top?map=drop-history&reason=bogus", http.StatusServiceUnavailable, "map not loaded: " + bpfmaps.DropHistoryMap},
	} {
		rec := serve(t, h, tc.target)
		if rec.Code != tc.code {
			t.Errorf("%s: status %d, want %d", tc.target, rec.Code, tc.code)
		}
		if !strings.Contains(rec.Body.String(), tc.body) {
			t.Errorf("%s: body %q, want it to mention %q", tc.target, rec.Body, tc.body)
		}
	}
}

func TestIPLookupRejectsABadAddress(t *testing.T) {
	h := handleIPLookup(apiCfg{Loaded: &loader.Loaded{}})
	rec := serve(t, h, "/api/ip/")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "missing IP") {
		t.Errorf("no address: status %d, body %q", rec.Code, rec.Body)
	}

	mux := apiMux(apiCfg{Loaded: &loader.Loaded{}})
	for _, bad := range []string{"not-an-ip", "999.1.1.1", "2001:db8::1"} {
		rec := serve(t, mux, "/api/ip/"+bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, rec.Code)
		}
	}
}

func TestRegisterAPIServesEveryListRoute(t *testing.T) {
	mux := apiMux(apiCfg{Loaded: &loader.Loaded{}})
	for _, path := range []string{
		"/api/health",
		"/api/health?all=1",
		"/api/whitelist",
		"/api/blacklist",
		"/api/established",
		"/api/syn-seen",
		"/api/open-count",
		"/api/drop-history",
	} {
		rec := serve(t, mux, path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", path, rec.Code)
			continue
		}
		if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
			t.Errorf("%s: body %q, want []", path, got)
		}
	}
}

func TestRegisterAPIWiresTheCounterAndTopRoutes(t *testing.T) {
	quietLog(t)
	mux := apiMux(apiCfg{Loaded: &loader.Loaded{}})
	for path, code := range map[string]int{
		"/api/info":            http.StatusInternalServerError,
		"/api/stats":           http.StatusInternalServerError,
		"/api/top":             http.StatusBadRequest,
		"/api/top?map=health":  http.StatusServiceUnavailable,
		"/api/ip/not-an-ip":    http.StatusBadRequest,
		"/api/no-such-route":   http.StatusNotFound,
		"/api/whitelist/extra": http.StatusNotFound,
	} {
		rec := serve(t, mux, path)
		if rec.Code != code {
			t.Errorf("%s: status %d, want %d", path, rec.Code, code)
		}
	}
}

func TestRegisterAPIOnlyAnswersGET(t *testing.T) {
	mux := apiMux(apiCfg{Loaded: &loader.Loaded{}})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/whitelist", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/whitelist: status %d, want 405", rec.Code)
	}
}

func TestStateListsTheAPIRoutes(t *testing.T) {
	rec := serve(t, apiMux(apiCfg{Loaded: &loader.Loaded{}}), "/api/state")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var out []string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(out, apiRoutes) {
		t.Errorf("got %v, want %v", out, apiRoutes)
	}
}

func TestLookupHelpersOnAMissingMapOrKey(t *testing.T) {
	key := [4]byte{10, 0, 0, 1}
	empty := &fakeMap{}
	for name, got := range map[string]any{
		"timestamp nil":       lookupTimestamp(nil, key, testNow),
		"timestamp absent":    lookupTimestamp(empty, key, testNow),
		"count nil":           lookupCount(nil, key),
		"count absent":        lookupCount(empty, key),
		"ratelimit nil":       lookupRatelimit(nil, key, testNow),
		"ratelimit absent":    lookupRatelimit(empty, key, testNow),
		"health nil":          lookupHealth(nil, key, testNow),
		"health absent":       lookupHealth(empty, key, testNow),
		"drop history nil":    lookupDropHistory(nil, key, testNow),
		"drop history absent": lookupDropHistory(empty, key, testNow),
	} {
		if got != nil {
			t.Errorf("%s = %v, want nil", name, got)
		}
	}
}

func TestLookupHelpersRenderEachValueKind(t *testing.T) {
	key := [4]byte{10, 0, 0, 1}
	hit := func(val any) *fakeMap { return &fakeMap{entries: []fakeEntry{{key: key, val: val}}} }

	for _, tc := range []struct {
		name string
		got  any
		want map[string]any
	}{
		{
			"timestamp",
			lookupTimestamp(hit(secsAgo(42)), key, testNow),
			map[string]any{"age_seconds": int64(42)},
		},
		{
			"count",
			lookupCount(hit(uint64(3)), key),
			map[string]any{"count": uint64(3)},
		},
		{
			"ratelimit",
			lookupRatelimit(hit(bpfmaps.Ratelimit{Tokens: 8, LastRefillNS: secsAgo(5)}), key, testNow),
			map[string]any{"tokens": uint64(8), "last_refill_age_seconds": int64(5)},
		},
		{
			"healthy",
			lookupHealth(hit(bpfmaps.UDPHealth{Anomalies: 2, WindowStartNS: secsAgo(9)}), key, testNow),
			map[string]any{"anomalies": uint32(2), "window_age_seconds": int64(9), "blacklisted": false},
		},
		{
			"blacklisted",
			lookupHealth(hit(bpfmaps.UDPHealth{
				Anomalies:        6,
				WindowStartNS:    secsAgo(9),
				BlacklistUntilNS: testNow + 120_000_000_000,
			}), key, testNow),
			map[string]any{
				"anomalies":                   uint32(6),
				"window_age_seconds":          int64(9),
				"blacklisted":                 true,
				"blacklist_remaining_seconds": int64(120),
			},
		},
		{
			"drop history",
			lookupDropHistory(hit(dropHistory(secsAgo(3), map[string]uint64{"malformed": 2, "udp_ratelimit": 5})), key, testNow),
			map[string]any{
				"first_drop_age_seconds": int64(600),
				"last_drop_age_seconds":  int64(3),
				"total":                  uint64(7),
				"by_reason":              map[string]uint64{"malformed": 2, "udp_ratelimit": 5},
			},
		},
	} {
		got, ok := tc.got.(map[string]any)
		if !ok {
			t.Errorf("%s: got %T, want map[string]any", tc.name, tc.got)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
