package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sratabix/fivem-ebpf/internal/loader"
	"github.com/sratabix/fivem-ebpf/internal/metrics"
)

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	iface := fs.String("iface", "eth0", "network interface to attach XDP to")
	port := fs.Uint("port", 30120, "FiveM server port (TCP+UDP)")
	ttl := fs.Duration("ttl", 10*time.Minute, "whitelist TTL")
	metricsAddr := fs.String("metrics-addr", ":9464", "prometheus metrics listen address")
	cgroup := fs.String("cgroup", "/sys/fs/cgroup", "cgroup v2 path for sockops attach")
	pinPath := fs.String("pin-path", "/sys/fs/bpf/fivem", "bpf map pin directory")
	udpRate := fs.Uint64("udp-rate", 1500, "per-IP UDP refill rate (packets/sec)")
	udpBurst := fs.Uint64("udp-burst", 4500, "per-IP UDP burst capacity (packets)")
	initRate := fs.Uint64("tcp-initconnect-per-min", 6, "per-IP POST /client refill rate (per minute)")
	initBurst := fs.Uint64("tcp-initconnect-burst", 3, "per-IP POST /client burst capacity")
	getRate := fs.Uint64("tcp-getinfo-per-min", 6, "per-IP GET /info.json|/dynamic.json|/players.json refill rate (per minute)")
	getBurst := fs.Uint64("tcp-getinfo-burst", 5, "per-IP GET /info.json etc. burst capacity")
	tcpGlobalRate := fs.Uint64("tcp-global-rate", 5000, "global circuit-breaker on aggregate TCP packets/sec to target port (0 disables)")
	tcpGlobalBurst := fs.Uint64("tcp-global-burst", 15000, "global circuit-breaker burst capacity (packets)")
	tcpMaxOpenPerIP := fs.Uint64("tcp-max-open-per-ip", 8, "drop new SYNs from any IP that already holds this many open TCP sockets to the target port (0 disables)")
	healthWindow := fs.Duration("health-window", 10*time.Second, "anomaly counting window per IP")
	healthThreshold := fs.Uint("health-threshold", 20, "anomalies per window before blacklisting an IP")
	healthBlacklist := fs.Duration("health-blacklist", 5*time.Minute, "how long an unhealthy IP stays blacklisted")
	sizeInterval := fs.Duration("map-size-interval", 30*time.Second, "how often to refresh map-size Prometheus gauges")
	_ = fs.Parse(args)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	l, err := loader.Load(loader.Options{
		Iface:             *iface,
		Port:              uint16(*port),
		TTL:               *ttl,
		CgroupPath:        *cgroup,
		PinPath:           *pinPath,
		UDPRatePerSec:     *udpRate,
		UDPBurst:          *udpBurst,
		InitConnectPerMin: *initRate,
		InitConnectBurst:  *initBurst,
		GetInfoPerMin:     *getRate,
		GetInfoBurst:      *getBurst,
		TCPGlobalPerSec:   *tcpGlobalRate,
		TCPGlobalBurst:    *tcpGlobalBurst,
		TCPMaxOpenPerIP:   *tcpMaxOpenPerIP,
		HealthWindow:      *healthWindow,
		HealthThreshold:   uint32(*healthThreshold),
		HealthBlacklist:   *healthBlacklist,
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("load: verifier rejected program:\n%+v", verr)
		}
		log.Fatalf("load: %v", err)
	}
	defer l.Close()

	log.Printf("xdp: %s mode on %s", l.XDPMode, *iface)
	log.Printf("sockops: attached to %s", *cgroup)
	log.Printf("pin path: %s", *pinPath)
	log.Printf("port: %d, ttl: %s", *port, *ttl)
	log.Printf("udp ratelimit: %d/s burst %d", *udpRate, *udpBurst)
	log.Printf("initConnect ratelimit: %d/min burst %d", *initRate, *initBurst)
	log.Printf("getinfo ratelimit: %d/min burst %d", *getRate, *getBurst)
	if *tcpGlobalRate > 0 {
		log.Printf("tcp global circuit-breaker: %d pps aggregate, burst %d (split per-CPU internally)", *tcpGlobalRate, *tcpGlobalBurst)
	} else {
		log.Printf("tcp global circuit-breaker: DISABLED")
	}
	if *tcpMaxOpenPerIP > 0 {
		log.Printf("tcp per-IP open-conn cap: %d sockets/IP", *tcpMaxOpenPerIP)
	} else {
		log.Printf("tcp per-IP open-conn cap: DISABLED")
	}
	log.Printf("health: %d anomalies / %s → blacklist for %s", *healthThreshold, *healthWindow, *healthBlacklist)
	log.Printf("NOTE: drops TCP segments with User-Agent: CitizenFX (bare, no /1); see README Limitations")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := prometheus.NewRegistry()
	collector := metrics.NewCollector(
		metrics.Maps{
			Stats:        l.Stats,
			Whitelist:    l.TCPWhitelist,
			Established:  l.TCPEstablished,
			SynSeen:      l.TCPSynSeen,
			OpenCount:    l.TCPOpenCount,
			UDPRatelimit: l.UDPRatelimit,
			InitcRL:      l.InitConnectRatelimit,
			GetinfoRL:    l.GetInfoRatelimit,
			Health:       l.UDPHealth,
		},
		*iface, uint16(*port), version,
		func() bool { return l.XDPLink != nil },
		func() bool { return l.SockopsLink != nil },
	)
	collector.StartSizeTicker(ctx, *sizeInterval)
	reg.MustRegister(collector)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	registerAPI(mux, apiCfg{
		Loaded:  l,
		Version: version,
		Iface:   *iface,
		Port:    uint16(*port),
		PinPath: *pinPath,
		Limits: apiLimits{
			UDPRatePerSec:     *udpRate,
			UDPBurst:          *udpBurst,
			InitConnectPerMin: *initRate,
			InitConnectBurst:  *initBurst,
			GetInfoPerMin:     *getRate,
			GetInfoBurst:      *getBurst,
			TCPGlobalPerSec:   *tcpGlobalRate,
			TCPGlobalBurst:    *tcpGlobalBurst,
			TCPMaxOpenPerIP:   *tcpMaxOpenPerIP,
			WhitelistTTL:      *ttl,
			HealthWindow:      *healthWindow,
			HealthThreshold:   uint32(*healthThreshold),
			HealthBlacklist:   *healthBlacklist,
		},
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fivem-ebpf " + version + "\n" +
			"  /metrics                     prometheus counters\n" +
			"  /api/info                    daemon overview (limits + maps + counters)\n" +
			"  /api/stats                   counter values (JSON)\n" +
			"  /api/top?map=...&n=...       hottest IPs in a per-IP map\n" +
			"  /api/health[?all=1]          blacklisted IPs (with ?all=1: all anomaly entries)\n" +
			"  /api/whitelist               IPs in tcp_whitelist\n" +
			"  /api/blacklist               IPs currently UDP-blacklisted\n" +
			"  /api/established             IPs in tcp_established\n" +
			"  /api/syn-seen                IPs in tcp_syn_seen\n" +
			"  /api/open-count              open TCP socket count per IP\n" +
			"  /api/ip/<addr>               aggregate state for one IPv4 across all maps\n" +
			"  /api/state                   index of the above\n"))
	})

	srv := &http.Server{Addr: *metricsAddr, Handler: mux}
	go func() {
		log.Printf("metrics: http://%s/metrics (map-size refresh every %s)", *metricsAddr, *sizeInterval)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
}
