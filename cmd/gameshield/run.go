package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sratabix/gameshield-ebpf/internal/config"
	"github.com/sratabix/gameshield-ebpf/internal/core"
	"github.com/sratabix/gameshield-ebpf/internal/metrics"
	"github.com/sratabix/gameshield-ebpf/internal/module"
	"github.com/sratabix/gameshield-ebpf/internal/pinpath"
)

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gameshield/config.yaml", "path to YAML config")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	loaded, err := core.Load(core.Options{
		Iface:      cfg.Daemon.Iface,
		CgroupPath: cfg.Daemon.CgroupPath,
		PinRoot:    cfg.Daemon.PinRoot,
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("core load: verifier:\n%+v", verr)
		}
		log.Fatalf("core load: %v", err)
	}
	defer loaded.Close()
	log.Printf("core: xdp %s on %s, sockops on %s", loaded.XDPMode, cfg.Daemon.Iface, cfg.Daemon.CgroupPath)
	log.Printf("core: pin root %s", cfg.Daemon.PinRoot)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := prometheus.NewRegistry()

	var attachMu sync.RWMutex
	moduleState := map[string]bool{}
	moduleStateSnapshot := func() map[string]bool {
		attachMu.RLock()
		defer attachMu.RUnlock()
		out := make(map[string]bool, len(moduleState))
		for k, v := range moduleState {
			out[k] = v
		}
		return out
	}

	core_ := metrics.NewCore(
		version, cfg.Daemon.Iface, cfg.Daemon.PinRoot, loaded.XDPMode,
		func() bool { return loaded.XDPLink != nil },
		func() bool { return loaded.SockopsLink != nil },
		moduleStateSnapshot,
	)
	reg.MustRegister(core_)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))

	enabled := cfg.EnabledModules()
	sort.Strings(enabled)

	loadedModules := []module.Module{}
	for slot, name := range enabled {
		m, err := module.New(name)
		if err != nil {
			log.Fatalf("module %s: %v", name, err)
		}
		raw := cfg.Modules[name]
		if err := m.Configure(raw); err != nil {
			log.Fatalf("module %s configure: %v", name, err)
		}
		modPin := pinpath.Module(cfg.Daemon.PinRoot, name)
		if err := m.Load(loaded, modPin); err != nil {
			log.Fatalf("module %s load: %v", name, err)
		}
		if err := loaded.RegisterXDP(uint32(slot), m.XDP()); err != nil {
			log.Fatalf("module %s register xdp: %v", name, err)
		}
		if so := m.Sockops(); so != nil {
			if err := loaded.RegisterSockops(uint32(slot), so); err != nil {
				log.Fatalf("module %s register sockops: %v", name, err)
			}
		}
		if err := loaded.BindPorts(uint32(slot), m.Ports()); err != nil {
			log.Fatalf("module %s bind ports: %v", name, err)
		}
		for _, c := range m.Collectors() {
			reg.MustRegister(c)
		}
		m.APIRoutes(mux, "/api/"+name+"/")
		m.Start(ctx, cfg.Daemon.MapSizeInterval)

		attachMu.Lock()
		moduleState[name] = true
		attachMu.Unlock()
		loadedModules = append(loadedModules, m)
		ports := m.Ports()
		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = p.Proto.String() + "/" + uint16ToStr(p.Port)
		}
		log.Printf("module %s: id=%d ports=[%s]", name, slot, joinComma(portStrs))
	}
	defer func() {
		for slot, m := range loadedModules {
			loaded.UnbindPorts(uint32(slot), m.Ports())
			_ = m.Close()
		}
	}()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("gameshield-ebpf " + version + "\n" +
			"  /metrics                  prometheus counters\n" +
			"  /api/<module>/...         module-specific endpoints\n"))
	})

	srv := &http.Server{Addr: cfg.Daemon.MetricsAddr, Handler: mux}
	go func() {
		log.Printf("metrics: http://%s/metrics (map-size refresh %s)", cfg.Daemon.MetricsAddr, cfg.Daemon.MapSizeInterval)
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

func uint16ToStr(p uint16) string {
	const digits = "0123456789"
	if p == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for p > 0 {
		i--
		buf[i] = digits[p%10]
		p /= 10
	}
	return string(buf[i:])
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
