package fivem

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

func bootTimeNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

const metricNamespace = "gameshield_fivem"

type mapSizes struct {
	whitelist    atomic.Int64
	established  atomic.Int64
	synSeen      atomic.Int64
	openCount    atomic.Int64
	udpRL        atomic.Int64
	initcRL      atomic.Int64
	getinfoRL    atomic.Int64
	health       atomic.Int64
	dropHistory  atomic.Int64
	blacklisted  atomic.Int64
}

type collector struct {
	mod *Module

	sizes mapSizes

	packets     *prometheus.Desc
	inserts     *prometheus.Desc
	promoted    *prometheus.Desc
	noEst       *prometheus.Desc
	postSeen    *prometheus.Desc
	getinfoSeen *prometheus.Desc
	mapEntries  *prometheus.Desc
	blacklisted *prometheus.Desc
}

func newCollector(m *Module) *collector {
	return &collector{
		mod: m,
		packets: prometheus.NewDesc(
			metricNamespace+"_xdp_packets_total",
			"Packets observed by the FiveM module's XDP program.",
			[]string{"verdict", "proto", "reason"}, nil,
		),
		inserts: prometheus.NewDesc(
			metricNamespace+"_tcp_established_inserts_total",
			"TCP connections promoted to tcp_established by sockops (3WHS completed on a FiveM port).",
			nil, nil,
		),
		promoted: prometheus.NewDesc(
			metricNamespace+"_tcp_l7_promoted_total",
			"IPs promoted to tcp_whitelist after L7 match + TCP established confirmation.",
			nil, nil,
		),
		noEst: prometheus.NewDesc(
			metricNamespace+"_tcp_l7_match_no_established_total",
			"L7 pattern matched on a TCP segment but tcp_established missing (spoofed or racy).",
			nil, nil,
		),
		postSeen: prometheus.NewDesc(
			metricNamespace+"_tcp_post_client_seen_total",
			"TCP data segments matching POST /client at offset 0 (regardless of verdict).",
			nil, nil,
		),
		getinfoSeen: prometheus.NewDesc(
			metricNamespace+"_tcp_getinfo_seen_total",
			"TCP data segments matching GET /info.json, /dynamic.json, or /players.json (regardless of verdict).",
			nil, nil,
		),
		mapEntries: prometheus.NewDesc(
			metricNamespace+"_map_entries",
			"Number of entries in each pinned IP-keyed map (refreshed by background ticker).",
			[]string{"map"}, nil,
		),
		blacklisted: prometheus.NewDesc(
			metricNamespace+"_health_blacklisted_ips",
			"IPs currently in the udp_health blacklist (blacklist_until_ns > now).",
			nil, nil,
		),
	}
}

// StartSizeTicker refreshes map-size gauges at the given interval. Cancel
// via the context. Iterating 100k-entry LRU maps every Prometheus scrape
// is too expensive — this background ticker amortizes the cost.
func (c *collector) StartSizeTicker(ctx context.Context, interval time.Duration) {
	go func() {
		c.refreshSizes()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.refreshSizes()
			}
		}
	}()
}

func (c *collector) refreshSizes() {
	priv := c.mod.Maps()
	shared := c.mod.SharedMaps()
	c.sizes.whitelist.Store(countKeys(shared.TCPWhitelist))
	c.sizes.established.Store(countKeys(shared.TCPEstablished))
	c.sizes.synSeen.Store(countKeys(shared.TCPSynSeen))
	c.sizes.openCount.Store(countKeys(shared.TCPOpenCount))
	c.sizes.udpRL.Store(countKeys(shared.UDPRatelimit))
	c.sizes.initcRL.Store(countKeys(priv.InitcRL))
	c.sizes.getinfoRL.Store(countKeys(priv.GetinfoRL))
	c.sizes.dropHistory.Store(countKeys(priv.DropHistory))
	total, blacklisted := countHealth(shared.UDPHealth)
	c.sizes.health.Store(total)
	c.sizes.blacklisted.Store(blacklisted)
}

func countKeys(m *ebpf.Map) int64 {
	if m == nil {
		return -1
	}
	var n int64
	var key [4]byte
	valBuf := make([]byte, m.ValueSize())
	iter := m.Iterate()
	for iter.Next(&key, &valBuf) {
		n++
	}
	return n
}

func countHealth(m *ebpf.Map) (total, blacklisted int64) {
	if m == nil {
		return -1, -1
	}
	now := bootTimeNS()
	var key [4]byte
	var val struct {
		Anomalies        uint32
		_                uint32
		WindowStartNS    uint64
		BlacklistUntilNS uint64
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		total++
		if val.BlacklistUntilNS > now {
			blacklisted++
		}
	}
	return
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packets
	ch <- c.inserts
	ch <- c.promoted
	ch <- c.noEst
	ch <- c.postSeen
	ch <- c.getinfoSeen
	ch <- c.mapEntries
	ch <- c.blacklisted
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	stats := c.mod.Maps().Stats
	if stats == nil {
		return
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil || ncpu <= 0 {
		ncpu = 1
	}
	perCPU := make([]uint64, ncpu)
	sums := make([]uint64, len(StatLabels))
	for slot := uint32(0); slot < uint32(len(StatLabels)); slot++ {
		if err := stats.Lookup(&slot, &perCPU); err != nil {
			continue
		}
		var s uint64
		for _, v := range perCPU {
			s += v
		}
		sums[slot] = s
	}

	emit := func(slot int, verdict, proto, reason string) {
		ch <- prometheus.MustNewConstMetric(
			c.packets, prometheus.CounterValue, float64(sums[slot]),
			verdict, proto, reason,
		)
	}
	emit(StatPassTCP, "pass", "tcp", "")
	emit(StatPassUDPWhitelisted, "pass", "udp", "whitelisted")
	emit(StatDropUDPNotWhitelisted, "drop", "udp", "not_whitelisted")
	emit(StatDropUDPExpired, "drop", "udp", "expired")
	emit(StatDropMalformed, "drop", "udp", "malformed")
	emit(StatDropUDPRatelimit, "drop", "udp", "ratelimit")
	emit(StatDropTCPInitconnectRatelimit, "drop", "tcp", "initconnect_ratelimit")
	emit(StatDropUDPEnetMalformed, "drop", "udp", "enet_malformed")
	emit(StatDropUDPUnhealthy, "drop", "udp", "unhealthy")
	emit(StatDropTCPGetinfoRatelimit, "drop", "tcp", "getinfo_ratelimit")
	emit(StatDropTCPBadUserAgent, "drop", "tcp", "bad_user_agent")
	emit(StatDropTCPNoSyn, "drop", "tcp", "no_syn")
	emit(StatDropTCPGlobalRatelimit, "drop", "tcp", "global_ratelimit")
	emit(StatDropTCPTooManyOpen, "drop", "tcp", "too_many_open")

	ch <- prometheus.MustNewConstMetric(c.inserts, prometheus.CounterValue, float64(sums[StatTCPEstablishedInserts]))
	ch <- prometheus.MustNewConstMetric(c.promoted, prometheus.CounterValue, float64(sums[StatTCPL7Promoted]))
	ch <- prometheus.MustNewConstMetric(c.noEst, prometheus.CounterValue, float64(sums[StatTCPL7MatchNoEst]))
	ch <- prometheus.MustNewConstMetric(c.postSeen, prometheus.CounterValue, float64(sums[StatTCPPostClientSeen]))
	ch <- prometheus.MustNewConstMetric(c.getinfoSeen, prometheus.CounterValue, float64(sums[StatTCPGetinfoSeen]))

	mapEntry := func(name string, v int64) {
		if v < 0 {
			return
		}
		ch <- prometheus.MustNewConstMetric(c.mapEntries, prometheus.GaugeValue, float64(v), name)
	}
	mapEntry("tcp_whitelist", c.sizes.whitelist.Load())
	mapEntry("tcp_established", c.sizes.established.Load())
	mapEntry("tcp_syn_seen", c.sizes.synSeen.Load())
	mapEntry("tcp_open_count", c.sizes.openCount.Load())
	mapEntry("udp_ratelimit", c.sizes.udpRL.Load())
	mapEntry("initconnect_ratelimit", c.sizes.initcRL.Load())
	mapEntry("getinfo_ratelimit", c.sizes.getinfoRL.Load())
	mapEntry("udp_health", c.sizes.health.Load())
	mapEntry("fivem_drop_history", c.sizes.dropHistory.Load())

	ch <- prometheus.MustNewConstMetric(c.blacklisted, prometheus.GaugeValue, float64(c.sizes.blacklisted.Load()))
}
