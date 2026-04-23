package main

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/sratabix/fivem-ebpf/internal/loader"
)

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

func bootNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

func ipv4Str(key [4]byte) string {
	return net.IPv4(key[0], key[1], key[2], key[3]).String()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func handleTimestampMap(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []timestampEntry{}
		if m != nil {
			now := bootNS()
			var key [4]byte
			var val uint64
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				age := int64(now) - int64(val)
				if age < 0 {
					age = 0
				}
				out = append(out, timestampEntry{
					IP:         ipv4Str(key),
					AgeSeconds: age / 1_000_000_000,
				})
			}
		}
		writeJSON(w, out)
	}
}

func handleCountMap(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []countEntry{}
		if m != nil {
			var key [4]byte
			var val uint64
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				out = append(out, countEntry{IP: ipv4Str(key), Count: val})
			}
		}
		writeJSON(w, out)
	}
}

func handleBlacklist(m *ebpf.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []blacklistEntry{}
		if m != nil {
			now := bootNS()
			var key [4]byte
			var val struct {
				Anomalies        uint32
				_                uint32
				WindowStartNS    uint64
				BlacklistUntilNS uint64
			}
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				if val.BlacklistUntilNS <= now {
					continue
				}
				out = append(out, blacklistEntry{
					IP:                        ipv4Str(key),
					Anomalies:                 val.Anomalies,
					WindowAgeSeconds:          int64(now-val.WindowStartNS) / 1_000_000_000,
					BlacklistRemainingSeconds: int64(val.BlacklistUntilNS-now) / 1_000_000_000,
				})
			}
		}
		writeJSON(w, out)
	}
}

// registerAPI wires the per-IP listing endpoints onto the metrics server's
// mux. Each endpoint iterates the corresponding pinned BPF map on demand —
// safe for ad-hoc inspection but a 100k-entry LRU under attack means a slow
// response. Don't poll these on a tight interval.
func registerAPI(mux *http.ServeMux, l *loader.Loaded) {
	mux.HandleFunc("/api/whitelist", handleTimestampMap(l.TCPWhitelist))
	mux.HandleFunc("/api/established", handleTimestampMap(l.TCPEstablished))
	mux.HandleFunc("/api/syn-seen", handleTimestampMap(l.TCPSynSeen))
	mux.HandleFunc("/api/open-count", handleCountMap(l.TCPOpenCount))
	mux.HandleFunc("/api/blacklist", handleBlacklist(l.UDPHealth))
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []string{
			"/api/whitelist",
			"/api/blacklist",
			"/api/established",
			"/api/syn-seen",
			"/api/open-count",
		})
	})
}
