package metrics

import (
	"context"
	"fmt"
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

const (
	StatPassTCP                      = 0
	StatPassUDPWhitelisted           = 1
	StatDropUDPNotWhitelisted        = 2
	StatDropUDPExpired               = 3
	StatDropMalformed                = 4
	StatTCPEstablishedInserts        = 5
	StatTCPL7Promoted                = 6
	StatTCPL7MatchNoEst              = 7
	StatDropUDPRatelimit             = 8
	StatDropTCPInitconnectRatelimit  = 9
	StatDropUDPEnetMalformed         = 10
	StatDropUDPUnhealthy             = 11
	StatTCPPostClientSeen            = 12
	StatTCPGetinfoSeen               = 13
	StatDropTCPGetinfoRatelimit      = 14
	StatDropTCPBadUserAgent          = 15
	StatDropTCPNoSyn                 = 16
	StatDropTCPGlobalRatelimit       = 17
	StatDropTCPTooManyOpen           = 18
	StatMax                          = 19
)

// MapSizes is a snapshot of IP-keyed map populations, refreshed by a
// background ticker. Scraping these directly in Collect would iterate
// 100k-entry LRU maps on every /metrics hit — unacceptable.
type MapSizes struct {
	whitelist   atomic.Int64
	established atomic.Int64
	synSeen     atomic.Int64
	openCount   atomic.Int64
	udpRL       atomic.Int64
	initcRL     atomic.Int64
	getinfoRL   atomic.Int64
	health      atomic.Int64
	blacklisted atomic.Int64 // IPs with blacklist_until_ns > now
}

type Collector struct {
	stats            *ebpf.Map
	whitelistMap     *ebpf.Map
	establishedMap   *ebpf.Map
	synSeenMap       *ebpf.Map
	openCountMap     *ebpf.Map
	udpRLMap         *ebpf.Map
	initcRLMap       *ebpf.Map
	getinfoRLMap     *ebpf.Map
	healthMap        *ebpf.Map

	sizes MapSizes

	packets     *prometheus.Desc
	inserts     *prometheus.Desc
	promoted    *prometheus.Desc
	noEst       *prometheus.Desc
	postSeen    *prometheus.Desc
	getinfoSeen *prometheus.Desc
	mapSize     *prometheus.Desc
	blacklisted *prometheus.Desc
	buildInfo   *prometheus.Desc
	attached    *prometheus.Desc

	iface           string
	port            uint16
	version         string
	xdpAttached     func() bool
	sockopsAttached func() bool
}

type Maps struct {
	Stats        *ebpf.Map
	Whitelist    *ebpf.Map
	Established  *ebpf.Map
	SynSeen      *ebpf.Map
	OpenCount    *ebpf.Map
	UDPRatelimit *ebpf.Map
	InitcRL      *ebpf.Map
	GetinfoRL    *ebpf.Map
	Health       *ebpf.Map
}

func NewCollector(
	maps Maps,
	iface string, port uint16, version string,
	xdpAttached, sockopsAttached func() bool,
) *Collector {
	return &Collector{
		stats:          maps.Stats,
		whitelistMap:   maps.Whitelist,
		establishedMap: maps.Established,
		synSeenMap:     maps.SynSeen,
		openCountMap:   maps.OpenCount,
		udpRLMap:       maps.UDPRatelimit,
		initcRLMap:     maps.InitcRL,
		getinfoRLMap:   maps.GetinfoRL,
		healthMap:      maps.Health,
		packets: prometheus.NewDesc(
			"fivem_xdp_packets_total",
			"Packets observed by the FiveM XDP filter.",
			[]string{"verdict", "proto", "reason"}, nil,
		),
		inserts: prometheus.NewDesc(
			"fivem_tcp_established_inserts_total",
			"TCP connections promoted to tcp_established by sockops (3WHS completed on port).",
			nil, nil,
		),
		promoted: prometheus.NewDesc(
			"fivem_tcp_l7_promoted_total",
			"IPs promoted to tcp_whitelist after L7 match + TCP established confirmation.",
			nil, nil,
		),
		noEst: prometheus.NewDesc(
			"fivem_tcp_l7_match_no_established_total",
			"L7 pattern matched on a TCP segment but tcp_established missing (spoofed or racy).",
			nil, nil,
		),
		postSeen: prometheus.NewDesc(
			"fivem_tcp_post_client_seen_total",
			"TCP data segments matching POST /client at offset 0 (regardless of verdict).",
			nil, nil,
		),
		getinfoSeen: prometheus.NewDesc(
			"fivem_tcp_getinfo_seen_total",
			"TCP data segments matching GET /info.json, /dynamic.json, or /players.json (regardless of verdict).",
			nil, nil,
		),
		mapSize: prometheus.NewDesc(
			"fivem_map_entries",
			"Number of entries in each pinned IP-keyed map (refreshed by background ticker, default every 30s).",
			[]string{"map"}, nil,
		),
		blacklisted: prometheus.NewDesc(
			"fivem_health_blacklisted_ips",
			"IPs currently in the udp_health blacklist (blacklist_until_ns > now).",
			nil, nil,
		),
		buildInfo: prometheus.NewDesc(
			"fivem_build_info",
			"Build and runtime configuration.",
			[]string{"version", "iface", "port"}, nil,
		),
		attached: prometheus.NewDesc(
			"fivem_attached",
			"Program attachment state (1=attached, 0=not).",
			[]string{"program"}, nil,
		),
		iface:           iface,
		port:            port,
		version:         version,
		xdpAttached:     xdpAttached,
		sockopsAttached: sockopsAttached,
	}
}

// StartSizeTicker refreshes the map-size gauges at the given interval.
// Cancel via the context. Safe to call multiple times; each call starts
// a new goroutine.
func (c *Collector) StartSizeTicker(ctx context.Context, interval time.Duration) {
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

func (c *Collector) refreshSizes() {
	c.sizes.whitelist.Store(countKeys(c.whitelistMap))
	c.sizes.established.Store(countKeys(c.establishedMap))
	c.sizes.synSeen.Store(countKeys(c.synSeenMap))
	c.sizes.openCount.Store(countKeys(c.openCountMap))
	c.sizes.udpRL.Store(countKeys(c.udpRLMap))
	c.sizes.initcRL.Store(countKeys(c.initcRLMap))
	c.sizes.getinfoRL.Store(countKeys(c.getinfoRLMap))
	total, blacklisted := countHealth(c.healthMap)
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

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packets
	ch <- c.inserts
	ch <- c.promoted
	ch <- c.noEst
	ch <- c.postSeen
	ch <- c.getinfoSeen
	ch <- c.mapSize
	ch <- c.blacklisted
	ch <- c.buildInfo
	ch <- c.attached
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ncpu, err := ebpf.PossibleCPU()
	if err != nil || ncpu <= 0 {
		ncpu = 1
	}
	perCPU := make([]uint64, ncpu)
	sums := make([]uint64, StatMax)
	for slot := uint32(0); slot < StatMax; slot++ {
		if err := c.stats.Lookup(&slot, &perCPU); err != nil {
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

	mapSize := func(name string, v int64) {
		if v < 0 {
			return
		}
		ch <- prometheus.MustNewConstMetric(c.mapSize, prometheus.GaugeValue, float64(v), name)
	}
	mapSize("tcp_whitelist", c.sizes.whitelist.Load())
	mapSize("tcp_established", c.sizes.established.Load())
	mapSize("tcp_syn_seen", c.sizes.synSeen.Load())
	mapSize("tcp_open_count", c.sizes.openCount.Load())
	mapSize("udp_ratelimit", c.sizes.udpRL.Load())
	mapSize("initconnect_ratelimit", c.sizes.initcRL.Load())
	mapSize("getinfo_ratelimit", c.sizes.getinfoRL.Load())
	mapSize("udp_health", c.sizes.health.Load())

	ch <- prometheus.MustNewConstMetric(c.blacklisted, prometheus.GaugeValue, float64(c.sizes.blacklisted.Load()))
	ch <- prometheus.MustNewConstMetric(
		c.buildInfo, prometheus.GaugeValue, 1,
		c.version, c.iface, fmt.Sprintf("%d", c.port),
	)
	ch <- prometheus.MustNewConstMetric(c.attached, prometheus.GaugeValue, boolToF(c.xdpAttached()), "xdp")
	ch <- prometheus.MustNewConstMetric(c.attached, prometheus.GaugeValue, boolToF(c.sockopsAttached()), "sockops")
}

func boolToF(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
