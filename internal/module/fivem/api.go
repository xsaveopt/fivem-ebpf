package fivem

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/cilium/ebpf"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func ipv4Str(key [4]byte) string {
	return net.IPv4(key[0], key[1], key[2], key[3]).String()
}

// registerAPI wires module-specific HTTP endpoints onto mux under prefix
// (e.g. /api/fivem/). Generic shared-map endpoints (whitelist, blacklist,
// ...) are owned by the daemon, not the module.
func registerAPI(mux *http.ServeMux, prefix string, m *Module) {
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	mux.HandleFunc(prefix+"stats", handleStats(m))
	mux.HandleFunc(prefix+"drop-history", handleDropHistory(m))
	mux.HandleFunc(prefix+"ratelimits", handleRatelimits(m))
}

func handleStats(m *Module) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats := m.Maps().Stats
		out := map[string]uint64{}
		if stats != nil {
			ncpu, _ := ebpf.PossibleCPU()
			if ncpu <= 0 {
				ncpu = 1
			}
			perCPU := make([]uint64, ncpu)
			for i, lbl := range StatLabels {
				k := uint32(i)
				if err := stats.Lookup(&k, &perCPU); err != nil {
					continue
				}
				var s uint64
				for _, v := range perCPU {
					s += v
				}
				out[lbl] = s
			}
		}
		writeJSON(w, out)
	}
}

func handleDropHistory(m *Module) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []map[string]any{}
		dh := m.Maps().DropHistory
		if dh != nil {
			now := bootTimeNS()
			var key [4]byte
			var val struct {
				FirstDropNS uint64
				LastDropNS  uint64
				Counts      [12]uint64
			}
			iter := dh.Iterate()
			for iter.Next(&key, &val) {
				first := int64(now) - int64(val.FirstDropNS)
				if first < 0 {
					first = 0
				}
				last := int64(now) - int64(val.LastDropNS)
				if last < 0 {
					last = 0
				}
				var total uint64
				by := map[string]uint64{}
				for i, c := range val.Counts {
					if c == 0 {
						continue
					}
					total += c
					by[DropReasonNames[i]] = c
				}
				out = append(out, map[string]any{
					"ip":                     ipv4Str(key),
					"first_drop_age_seconds": first / 1_000_000_000,
					"last_drop_age_seconds":  last / 1_000_000_000,
					"total":                  total,
					"by_reason":              by,
				})
			}
		}
		writeJSON(w, out)
	}
}

func handleRatelimits(m *Module) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{
			"initconnect": readRatelimit(m.Maps().InitcRL),
			"getinfo":     readRatelimit(m.Maps().GetinfoRL),
		}
		writeJSON(w, out)
	}
}

func readRatelimit(rl *ebpf.Map) []map[string]any {
	out := []map[string]any{}
	if rl == nil {
		return out
	}
	now := bootTimeNS()
	var key [4]byte
	var val struct {
		Tokens       uint64
		LastRefillNS uint64
	}
	iter := rl.Iterate()
	for iter.Next(&key, &val) {
		age := int64(now) - int64(val.LastRefillNS)
		if age < 0 {
			age = 0
		}
		out = append(out, map[string]any{
			"ip":                      ipv4Str(key),
			"tokens":                  val.Tokens,
			"last_refill_age_seconds": age / 1_000_000_000,
		})
	}
	return out
}
