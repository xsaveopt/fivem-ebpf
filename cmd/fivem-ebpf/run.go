package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/xsaveopt/fivem-ebpf/internal/loader"
	"github.com/xsaveopt/fivem-ebpf/internal/metrics"
)

func cmdRun(args []string) {
	if err := runDaemon(args); err != nil {
		log.Fatal(err)
	}
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	iface := fs.String("iface", "eth0", "network interface to attach XDP to")
	port := fs.Uint("port", 30120, "FiveM server port (TCP+UDP)")
	ttl := fs.Duration("ttl", 10*time.Minute, "whitelist TTL")
	metricsAddr := fs.String("metrics-addr", "127.0.0.1:9464", "listen address for /metrics and /api (serves every tracked IP, so bind it to a trusted interface)")
	cgroup := fs.String("cgroup", "/sys/fs/cgroup", "cgroup v2 path for sockops attach")
	pinPath := fs.String("pin-path", defaultPinPath, "bpf map pin directory")
	udpRate := fs.Uint64("udp-rate", 1500, "per-IP UDP refill rate (packets/sec, 0 disables)")
	udpBurst := fs.Uint64("udp-burst", 4500, "per-IP UDP burst capacity (packets, 0 disables)")
	initRate := fs.Uint64("tcp-initconnect-per-min", 6, "per-IP POST /client refill rate (per minute, 0 disables)")
	initBurst := fs.Uint64("tcp-initconnect-burst", 3, "per-IP POST /client burst capacity (0 disables)")
	getRate := fs.Uint64("tcp-getinfo-per-min", 6, "per-IP GET /info.json|/dynamic.json|/players.json refill rate (per minute, 0 disables)")
	getBurst := fs.Uint64("tcp-getinfo-burst", 5, "per-IP GET /info.json etc. burst capacity (0 disables)")
	tcpGlobalRate := fs.Uint64("tcp-global-rate", 5000, "global circuit-breaker on new SYNs/sec to the target port (0 disables)")
	tcpGlobalBurst := fs.Uint64("tcp-global-burst", 15000, "global circuit-breaker burst capacity (SYNs)")
	tcpMaxOpenPerIP := fs.Uint64("tcp-max-open-per-ip", 16, "drop new SYNs from any IP that already holds this many open TCP sockets to the target port (0 disables)")
	healthWindow := fs.Duration("health-window", 60*time.Second, "anomaly counting window per IP")
	healthThreshold := fs.Uint("health-threshold", 100, "anomalies per window before blacklisting an IP")
	healthBlacklist := fs.Duration("health-blacklist", 5*time.Minute, "how long an unhealthy IP stays blacklisted")
	sizeInterval := fs.Duration("map-size-interval", 30*time.Second, "how often to refresh map-size Prometheus gauges (0 disables them)")
	dropHistory := fs.Bool("drop-history", true, "record per-IP drop counts by reason (the data behind inspect and /api/ip)")
	_ = fs.Parse(args)

	if *port == 0 || *port > 65535 {
		return fmt.Errorf("--port %d out of range: must be 1-65535", *port)
	}
	if uint64(*healthThreshold) > math.MaxUint32 {
		return fmt.Errorf("--health-threshold %d out of range: must be <= %d", *healthThreshold, uint32(math.MaxUint32))
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("rlimit: %w", err)
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
		DropHistory:       *dropHistory,
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return fmt.Errorf("load: verifier rejected program:\n%+w", verr)
		}
		return fmt.Errorf("load: %w", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			log.Printf("detach: %v", err)
		}
	}()

	log.Printf("xdp: %s mode on %s", l.XDPMode, *iface)
	log.Printf("sockops: attached to %s", *cgroup)
	log.Printf("pin path: %s", *pinPath)
	log.Printf("port: %d, ttl: %s", *port, *ttl)
	log.Printf("udp ratelimit: %s", limitDesc(*udpRate, "/s", *udpBurst))
	log.Printf("initConnect ratelimit: %s", limitDesc(*initRate, "/min", *initBurst))
	log.Printf("getinfo ratelimit: %s", limitDesc(*getRate, "/min", *getBurst))
	if *tcpGlobalRate > 0 {
		log.Printf("tcp global circuit-breaker: %d new SYNs/s, burst %d (split per-CPU internally)", *tcpGlobalRate, *tcpGlobalBurst)
	} else {
		log.Printf("tcp global circuit-breaker: DISABLED")
	}
	if *tcpMaxOpenPerIP > 0 {
		log.Printf("tcp per-IP open-conn cap: %d sockets/IP", *tcpMaxOpenPerIP)
	} else {
		log.Printf("tcp per-IP open-conn cap: DISABLED")
	}
	log.Printf("health: %d anomalies / %s then blacklist for %s", *healthThreshold, *healthWindow, *healthBlacklist)
	log.Printf("drop history: %s", enabledDesc(*dropHistory))
	log.Printf("NOTE: drops TCP segments with User-Agent: CitizenFX (bare, no /1); see README Limitations")
	if !isLoopback(*metricsAddr) {
		log.Printf("WARNING: %s is reachable off-host and /api exposes every tracked player IP, unauthenticated", *metricsAddr)
	}

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
			DropHistory:  l.IPDropHistory,
		},
		*iface, uint16(*port), version,
		func() bool { return l.XDPLink != nil },
		func() bool { return l.SockopsLink != nil },
	)
	waitTicker := collector.StartSizeTicker(ctx, *sizeInterval)
	reg.MustRegister(collector)

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
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
			DropHistory:       *dropHistory,
		},
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("fivem-ebpf " + version + "\n  /metrics\n  " +
			strings.Join(apiRoutes, "\n  ") + "\n"))
	})

	srv := &http.Server{
		Addr:              *metricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		log.Printf("metrics: http://%s/metrics (map-size refresh every %s)", *metricsAddr, *sizeInterval)
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	var fatal error
	select {
	case s := <-sig:
		log.Printf("shutting down (%s)", s)
	case err := <-serveErr:
		if err != nil {
			fatal = fmt.Errorf("metrics server: %w", err)
		}
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("http shutdown: %v", err)
	}
	cancel()
	waitTicker()
	return fatal
}

func limitDesc(rate uint64, unit string, burst uint64) string {
	if rate == 0 || burst == 0 {
		return "DISABLED"
	}
	return fmt.Sprintf("%d%s burst %d", rate, unit, burst)
}

func enabledDesc(on bool) string {
	if on {
		return "enabled"
	}
	return "disabled"
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
