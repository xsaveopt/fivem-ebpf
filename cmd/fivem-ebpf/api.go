package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/cilium/ebpf"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
	"github.com/xsaveopt/fivem-ebpf/internal/loader"
)

const maxTopRows = 1000

type timestampEntry struct {
	IP         string `json:"ip"`
	AgeSeconds int64  `json:"age_seconds"`
}

type blacklistEntry struct {
	IP                        string `json:"ip"`
	Anomalies                 uint32 `json:"anomalies"`
	WindowAgeSeconds          int64  `json:"window_age_seconds"`
	BlacklistRemainingSeconds int64  `json:"blacklist_remaining_seconds"`
}

type countEntry struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

type dropHistoryEntry struct {
	IP                  string            `json:"ip"`
	FirstDropAgeSeconds int64             `json:"first_drop_age_seconds"`
	LastDropAgeSeconds  int64             `json:"last_drop_age_seconds"`
	Total               uint64            `json:"total"`
	ByReason            map[string]uint64 `json:"by_reason"`
}

type healthEntry struct {
	IP                        string `json:"ip"`
	Anomalies                 uint32 `json:"anomalies"`
	WindowAgeSeconds          int64  `json:"window_age_seconds"`
	Blacklisted               bool   `json:"blacklisted"`
	BlacklistRemainingSeconds int64  `json:"blacklist_remaining_seconds"`
}

func ageSeconds(now, then uint64) int64 {
	d := int64(now) - int64(then)
	if d < 0 {
		return 0
	}
	return d / 1_000_000_000
}

func parseTopN(s string) (int, error) {
	if s == "" {
		return 10, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("n must be a positive integer, got %q", s)
	}
	return min(n, maxTopRows), nil
}

func ipv4Str(key [4]byte) string {
	return net.IPv4(key[0], key[1], key[2], key[3]).String()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func failed(w http.ResponseWriter, what string, err error) {
	log.Printf("api: %s: %v", what, err)
	http.Error(w, what+": "+err.Error(), http.StatusInternalServerError)
}

func handleTimestampMap(m bpfmaps.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []timestampEntry{}
		if m != nil {
			now, err := bpfmaps.BootTimeNS()
			if err != nil {
				failed(w, "clock", err)
				return
			}
			var key [4]byte
			var val uint64
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				out = append(out, timestampEntry{
					IP:         ipv4Str(key),
					AgeSeconds: ageSeconds(now, val),
				})
			}
			if err := iter.Err(); err != nil {
				failed(w, "iterate", err)
				return
			}
		}
		writeJSON(w, out)
	}
}

func handleCountMap(m bpfmaps.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []countEntry{}
		if m != nil {
			var key [4]byte
			var val uint64
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				out = append(out, countEntry{IP: ipv4Str(key), Count: val})
			}
			if err := iter.Err(); err != nil {
				failed(w, "iterate", err)
				return
			}
		}
		writeJSON(w, out)
	}
}

func handleBlacklist(m bpfmaps.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []blacklistEntry{}
		if m != nil {
			now, err := bpfmaps.BootTimeNS()
			if err != nil {
				failed(w, "clock", err)
				return
			}
			var key [4]byte
			var val bpfmaps.UDPHealth
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				if val.BlacklistUntilNS <= now {
					continue
				}
				out = append(out, blacklistEntry{
					IP:                        ipv4Str(key),
					Anomalies:                 val.Anomalies,
					WindowAgeSeconds:          ageSeconds(now, val.WindowStartNS),
					BlacklistRemainingSeconds: ageSeconds(val.BlacklistUntilNS, now),
				})
			}
			if err := iter.Err(); err != nil {
				failed(w, "iterate", err)
				return
			}
		}
		writeJSON(w, out)
	}
}

func handleHealth(m bpfmaps.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all := r.URL.Query().Get("all") == "1"
		out := []healthEntry{}
		if m != nil {
			now, err := bpfmaps.BootTimeNS()
			if err != nil {
				failed(w, "clock", err)
				return
			}
			var key [4]byte
			var val bpfmaps.UDPHealth
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				blacklisted := val.BlacklistUntilNS > now
				if !all && !blacklisted {
					continue
				}
				entry := healthEntry{
					IP:               ipv4Str(key),
					Anomalies:        val.Anomalies,
					WindowAgeSeconds: ageSeconds(now, val.WindowStartNS),
					Blacklisted:      blacklisted,
				}
				if blacklisted {
					entry.BlacklistRemainingSeconds = ageSeconds(val.BlacklistUntilNS, now)
				}
				out = append(out, entry)
			}
			if err := iter.Err(); err != nil {
				failed(w, "iterate", err)
				return
			}
		}
		writeJSON(w, out)
	}
}

func handleDropHistory(m bpfmaps.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []dropHistoryEntry{}
		if m != nil {
			now, err := bpfmaps.BootTimeNS()
			if err != nil {
				failed(w, "clock", err)
				return
			}
			var key [4]byte
			var val bpfmaps.DropHistory
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				total, by := dropCounts(val)
				out = append(out, dropHistoryEntry{
					IP:                  ipv4Str(key),
					FirstDropAgeSeconds: ageSeconds(now, val.FirstDropNS),
					LastDropAgeSeconds:  ageSeconds(now, val.LastDropNS),
					Total:               total,
					ByReason:            by,
				})
			}
			if err := iter.Err(); err != nil {
				failed(w, "iterate", err)
				return
			}
		}
		writeJSON(w, out)
	}
}

func dropCounts(v bpfmaps.DropHistory) (uint64, map[string]uint64) {
	var total uint64
	by := make(map[string]uint64)
	for i, c := range v.Counts {
		if c == 0 {
			continue
		}
		total += c
		by[bpfmaps.DropReasonNames[i]] = c
	}
	return total, by
}

func handleIPLookup(cfg apiCfg) http.HandlerFunc {
	l := cfg.Loaded
	return func(w http.ResponseWriter, r *http.Request) {
		addr := r.PathValue("addr")
		if addr == "" {
			http.Error(w, "missing IP: GET /api/ip/<addr>", http.StatusBadRequest)
			return
		}
		key, err := parseIPv4Key(addr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		now, err := bpfmaps.BootTimeNS()
		if err != nil {
			failed(w, "clock", err)
			return
		}
		out := map[string]any{
			"ip":                    addr,
			"tcp_whitelist":         lookupTimestamp(reader(l.TCPWhitelist), key, now),
			"tcp_established":       lookupTimestamp(reader(l.TCPEstablished), key, now),
			"tcp_syn_seen":          lookupTimestamp(reader(l.TCPSynSeen), key, now),
			"tcp_open_count":        lookupCount(reader(l.TCPOpenCount), key),
			"udp_ratelimit":         lookupRatelimit(reader(l.UDPRatelimit), key, now),
			"initconnect_ratelimit": lookupRatelimit(reader(l.InitConnectRatelimit), key, now),
			"getinfo_ratelimit":     lookupRatelimit(reader(l.GetInfoRatelimit), key, now),
			"udp_health":            lookupHealth(reader(l.UDPHealth), key, now),
			"drop_history":          lookupDropHistory(reader(l.IPDropHistory), key, now),
		}
		writeJSON(w, out)
	}
}

func lookupTimestamp(m bpfmaps.Reader, key [4]byte, now uint64) any {
	if m == nil {
		return nil
	}
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	return map[string]any{"age_seconds": ageSeconds(now, val)}
}

func lookupCount(m bpfmaps.Reader, key [4]byte) any {
	if m == nil {
		return nil
	}
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	return map[string]any{"count": val}
}

func lookupRatelimit(m bpfmaps.Reader, key [4]byte, now uint64) any {
	if m == nil {
		return nil
	}
	var val bpfmaps.Ratelimit
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	return map[string]any{
		"tokens":                  val.Tokens,
		"last_refill_age_seconds": ageSeconds(now, val.LastRefillNS),
	}
}

func lookupDropHistory(m bpfmaps.Reader, key [4]byte, now uint64) any {
	if m == nil {
		return nil
	}
	var val bpfmaps.DropHistory
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	total, by := dropCounts(val)
	return map[string]any{
		"first_drop_age_seconds": ageSeconds(now, val.FirstDropNS),
		"last_drop_age_seconds":  ageSeconds(now, val.LastDropNS),
		"total":                  total,
		"by_reason":              by,
	}
}

func lookupHealth(m bpfmaps.Reader, key [4]byte, now uint64) any {
	if m == nil {
		return nil
	}
	var val bpfmaps.UDPHealth
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	out := map[string]any{
		"anomalies":          val.Anomalies,
		"window_age_seconds": ageSeconds(now, val.WindowStartNS),
		"blacklisted":        val.BlacklistUntilNS > now,
	}
	if val.BlacklistUntilNS > now {
		out["blacklist_remaining_seconds"] = ageSeconds(val.BlacklistUntilNS, now)
	}
	return out
}

type apiCfg struct {
	Loaded  *loader.Loaded
	Version string
	Iface   string
	Port    uint16
	PinPath string
	Limits  apiLimits
}

type apiLimits struct {
	UDPRatePerSec     uint64        `json:"udp_rate_per_sec"`
	UDPBurst          uint64        `json:"udp_burst"`
	InitConnectPerMin uint64        `json:"initconnect_per_min"`
	InitConnectBurst  uint64        `json:"initconnect_burst"`
	GetInfoPerMin     uint64        `json:"getinfo_per_min"`
	GetInfoBurst      uint64        `json:"getinfo_burst"`
	TCPGlobalPerSec   uint64        `json:"tcp_global_syn_per_sec"`
	TCPGlobalBurst    uint64        `json:"tcp_global_syn_burst"`
	TCPMaxOpenPerIP   uint64        `json:"tcp_max_open_per_ip"`
	WhitelistTTL      time.Duration `json:"whitelist_ttl_ns"`
	HealthWindow      time.Duration `json:"health_window_ns"`
	HealthThreshold   uint32        `json:"health_threshold"`
	HealthBlacklist   time.Duration `json:"health_blacklist_ns"`
	DropHistory       bool          `json:"drop_history_enabled"`
}

func handleInfo(cfg apiCfg) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		counters, err := readCounters(cfg.Loaded)
		if err != nil {
			failed(w, "read counters", err)
			return
		}
		populations, err := mapPopulations(cfg.Loaded)
		if err != nil {
			failed(w, "count map entries", err)
			return
		}
		out := map[string]any{
			"version":  cfg.Version,
			"iface":    cfg.Iface,
			"port":     cfg.Port,
			"pin_path": cfg.PinPath,
			"xdp_mode": cfg.Loaded.XDPMode,
			"attached": map[string]bool{
				"xdp":     cfg.Loaded.XDPLink != nil,
				"sockops": cfg.Loaded.SockopsLink != nil,
			},
			"limits":   cfg.Limits,
			"maps":     populations,
			"counters": counters,
		}
		writeJSON(w, out)
	}
}

func handleStats(l *loader.Loaded) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		counters, err := readCounters(l)
		if err != nil {
			failed(w, "read counters", err)
			return
		}
		writeJSON(w, counters)
	}
}

func handleTop(cfg apiCfg) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		which := r.URL.Query().Get("map")
		if which == "" {
			http.Error(w, "missing ?map=... (one of "+bpfmaps.CLINamesHelp+")", http.StatusBadRequest)
			return
		}
		n, err := parseTopN(r.URL.Query().Get("n"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		kind, ok := topMapKinds[which]
		if !ok {
			http.Error(w, "unknown map: "+which, http.StatusBadRequest)
			return
		}
		m := cfg.Loaded.ByPinnedName(kind.pinned)
		if m == nil {
			http.Error(w, "map not loaded: "+kind.pinned, http.StatusServiceUnavailable)
			return
		}
		reasonIdx, err := dropReasonIndex(r.URL.Query().Get("reason"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now, err := bpfmaps.BootTimeNS()
		if err != nil {
			failed(w, "clock", err)
			return
		}
		rows, err := topRows(bpfmaps.Map{M: m}, kind.kind, now, n, reasonIdx, false)
		if err != nil {
			failed(w, "read "+kind.pinned, err)
			return
		}
		writeJSON(w, rows)
	}
}

func mapPopulations(l *loader.Loaded) (map[string]int64, error) {
	out := make(map[string]int64, len(bpfmaps.PerIP))
	for _, name := range bpfmaps.PerIP {
		n, err := bpfmaps.CountKeys(l.ByPinnedName(name))
		if err != nil {
			return nil, err
		}
		out[name] = n
	}
	return out, nil
}

func readCounters(l *loader.Loaded) (map[string]uint64, error) {
	vals, err := bpfmaps.ReadStats(l.Stats)
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint64, len(bpfmaps.StatLabels))
	for i, lbl := range bpfmaps.StatLabels {
		out[lbl] = vals[i]
	}
	return out, nil
}

func reader(m *ebpf.Map) bpfmaps.Reader { return bpfmaps.NewReader(m) }

var apiRoutes = []string{
	"/api/info",
	"/api/stats",
	"/api/top?map=<name>&n=<N>&reason=<reason>",
	"/api/health",
	"/api/health?all=1",
	"/api/whitelist",
	"/api/blacklist",
	"/api/established",
	"/api/syn-seen",
	"/api/open-count",
	"/api/drop-history",
	"/api/ip/<addr>",
	"/api/state",
}

func registerAPI(mux *http.ServeMux, cfg apiCfg) {
	l := cfg.Loaded
	mux.HandleFunc("GET /api/info", handleInfo(cfg))
	mux.HandleFunc("GET /api/stats", handleStats(l))
	mux.HandleFunc("GET /api/top", handleTop(cfg))
	mux.HandleFunc("GET /api/health", handleHealth(reader(l.UDPHealth)))
	mux.HandleFunc("GET /api/whitelist", handleTimestampMap(reader(l.TCPWhitelist)))
	mux.HandleFunc("GET /api/established", handleTimestampMap(reader(l.TCPEstablished)))
	mux.HandleFunc("GET /api/syn-seen", handleTimestampMap(reader(l.TCPSynSeen)))
	mux.HandleFunc("GET /api/open-count", handleCountMap(reader(l.TCPOpenCount)))
	mux.HandleFunc("GET /api/blacklist", handleBlacklist(reader(l.UDPHealth)))
	mux.HandleFunc("GET /api/drop-history", handleDropHistory(reader(l.IPDropHistory)))
	mux.HandleFunc("GET /api/ip/{addr}", handleIPLookup(cfg))
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, apiRoutes)
	})
}
