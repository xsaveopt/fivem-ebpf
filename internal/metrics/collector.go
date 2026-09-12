package metrics

import (
	"context"
	"log"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

type MapSizes struct {
	whitelist   atomic.Int64
	established atomic.Int64
	synSeen     atomic.Int64
	openCount   atomic.Int64
	udpRL       atomic.Int64
	initcRL     atomic.Int64
	getinfoRL   atomic.Int64
	health      atomic.Int64
	dropHistory atomic.Int64
	blacklisted atomic.Int64
}

type Collector struct {
	stats          *ebpf.Map
	whitelistMap   *ebpf.Map
	establishedMap *ebpf.Map
	synSeenMap     *ebpf.Map
	openCountMap   *ebpf.Map
	udpRLMap       *ebpf.Map
	initcRLMap     *ebpf.Map
	getinfoRLMap   *ebpf.Map
	healthMap      *ebpf.Map
	dropHistoryMap *ebpf.Map

	sizes MapSizes

	packets     *prometheus.Desc
	inserts     *prometheus.Desc
	promoted    *prometheus.Desc
	noEst       *prometheus.Desc
	postSeen    *prometheus.Desc
	postUnknown *prometheus.Desc
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
	DropHistory  *ebpf.Map
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
		dropHistoryMap: maps.DropHistory,
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
		postUnknown: prometheus.NewDesc(
			"fivem_tcp_post_client_ua_unknown_total",
			"POST /client segments carrying no recognisable User-Agent, so no promotion happened.",
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

func (c *Collector) StartSizeTicker(ctx context.Context, interval time.Duration) func() {
	if interval <= 0 {
		log.Printf("map-size gauges disabled (map-size-interval %s)", interval)
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
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
	return func() { <-done }
}

func (c *Collector) refreshSizes() {
	store := func(dst *atomic.Int64, name string, m *ebpf.Map) {
		n, err := bpfmaps.CountKeys(m)
		if err != nil {
			log.Printf("map-size %s: %v (keeping previous value)", name, err)
			return
		}
		dst.Store(n)
	}
	store(&c.sizes.whitelist, bpfmaps.Whitelist, c.whitelistMap)
	store(&c.sizes.established, bpfmaps.Established, c.establishedMap)
	store(&c.sizes.synSeen, bpfmaps.SynSeen, c.synSeenMap)
	store(&c.sizes.openCount, bpfmaps.OpenCount, c.openCountMap)
	store(&c.sizes.udpRL, bpfmaps.UDPRatelimit, c.udpRLMap)
	store(&c.sizes.initcRL, bpfmaps.InitConnectRatelimit, c.initcRLMap)
	store(&c.sizes.getinfoRL, bpfmaps.GetInfoRatelimit, c.getinfoRLMap)
	store(&c.sizes.dropHistory, bpfmaps.DropHistoryMap, c.dropHistoryMap)

	total, blacklisted, err := countHealth(c.healthMap)
	if err != nil {
		log.Printf("map-size %s: %v (keeping previous value)", bpfmaps.Health, err)
		return
	}
	c.sizes.health.Store(total)
	c.sizes.blacklisted.Store(blacklisted)
}

func countHealth(m *ebpf.Map) (total, blacklisted int64, err error) {
	if m == nil {
		return -1, -1, nil
	}
	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		return 0, 0, err
	}
	var key [4]byte
	var val bpfmaps.UDPHealth
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		total++
		if val.BlacklistUntilNS > now {
			blacklisted++
		}
	}
	return total, blacklisted, iter.Err()
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packets
	ch <- c.inserts
	ch <- c.promoted
	ch <- c.noEst
	ch <- c.postSeen
	ch <- c.postUnknown
	ch <- c.getinfoSeen
	ch <- c.mapSize
	ch <- c.blacklisted
	ch <- c.buildInfo
	ch <- c.attached
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	sums, err := bpfmaps.ReadStats(c.stats)
	if err != nil {
		log.Printf("metrics: read stats: %v", err)
	} else {
		emit := func(slot int, verdict, proto, reason string) {
			ch <- prometheus.MustNewConstMetric(
				c.packets, prometheus.CounterValue, float64(sums[slot]),
				verdict, proto, reason,
			)
		}
		emit(bpfmaps.StatPassTCP, "pass", "tcp", "")
		emit(bpfmaps.StatPassUDPWhitelisted, "pass", "udp", "whitelisted")
		emit(bpfmaps.StatDropUDPNotWhitelisted, "drop", "udp", "not_whitelisted")
		emit(bpfmaps.StatDropUDPExpired, "drop", "udp", "expired")
		emit(bpfmaps.StatDropUDPRatelimit, "drop", "udp", "ratelimit")
		emit(bpfmaps.StatDropUDPEnetMalformed, "drop", "udp", "enet_malformed")
		emit(bpfmaps.StatDropUDPUnhealthy, "drop", "udp", "unhealthy")
		emit(bpfmaps.StatDropMalformed, "drop", "tcp", "malformed")
		emit(bpfmaps.StatDropTCPInitconnectRatelimit, "drop", "tcp", "initconnect_ratelimit")
		emit(bpfmaps.StatDropTCPGetinfoRatelimit, "drop", "tcp", "getinfo_ratelimit")
		emit(bpfmaps.StatDropTCPBadUserAgent, "drop", "tcp", "bad_user_agent")
		emit(bpfmaps.StatDropTCPNoSyn, "drop", "tcp", "no_syn")
		emit(bpfmaps.StatDropTCPGlobalRatelimit, "drop", "tcp", "global_ratelimit")
		emit(bpfmaps.StatDropTCPTooManyOpen, "drop", "tcp", "too_many_open")
		emit(bpfmaps.StatDropIPFragment, "drop", "ip", "fragment")

		ch <- prometheus.MustNewConstMetric(c.inserts, prometheus.CounterValue, float64(sums[bpfmaps.StatTCPEstablishedInserts]))
		ch <- prometheus.MustNewConstMetric(c.promoted, prometheus.CounterValue, float64(sums[bpfmaps.StatTCPL7Promoted]))
		ch <- prometheus.MustNewConstMetric(c.noEst, prometheus.CounterValue, float64(sums[bpfmaps.StatTCPL7MatchNoEst]))
		ch <- prometheus.MustNewConstMetric(c.postSeen, prometheus.CounterValue, float64(sums[bpfmaps.StatTCPPostClientSeen]))
		ch <- prometheus.MustNewConstMetric(c.postUnknown, prometheus.CounterValue, float64(sums[bpfmaps.StatTCPPostUAUnknown]))
		ch <- prometheus.MustNewConstMetric(c.getinfoSeen, prometheus.CounterValue, float64(sums[bpfmaps.StatTCPGetinfoSeen]))
	}

	mapSize := func(name string, v int64) {
		if v < 0 {
			return
		}
		ch <- prometheus.MustNewConstMetric(c.mapSize, prometheus.GaugeValue, float64(v), name)
	}
	mapSize(bpfmaps.Whitelist, c.sizes.whitelist.Load())
	mapSize(bpfmaps.Established, c.sizes.established.Load())
	mapSize(bpfmaps.SynSeen, c.sizes.synSeen.Load())
	mapSize(bpfmaps.OpenCount, c.sizes.openCount.Load())
	mapSize(bpfmaps.UDPRatelimit, c.sizes.udpRL.Load())
	mapSize(bpfmaps.InitConnectRatelimit, c.sizes.initcRL.Load())
	mapSize(bpfmaps.GetInfoRatelimit, c.sizes.getinfoRL.Load())
	mapSize(bpfmaps.Health, c.sizes.health.Load())
	mapSize(bpfmaps.DropHistoryMap, c.sizes.dropHistory.Load())

	ch <- prometheus.MustNewConstMetric(c.blacklisted, prometheus.GaugeValue, float64(c.sizes.blacklisted.Load()))
	ch <- prometheus.MustNewConstMetric(
		c.buildInfo, prometheus.GaugeValue, 1,
		c.version, c.iface, strconv.Itoa(int(c.port)),
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
