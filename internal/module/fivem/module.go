package fivem

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sratabix/gameshield-ebpf/internal/core"
	"github.com/sratabix/gameshield-ebpf/internal/module"
)

const Name = "fivem"

// Module is the FiveM implementation of module.Module.
type Module struct {
	cfg       Config
	xdpObj    *fivemXDPObjects
	soObj     *fivemSockopsObjects
	collector *collector
}

// New returns an unconfigured FiveM module. Configure must be called before Load.
func New() *Module {
	return &Module{cfg: defaults()}
}

func (m *Module) Name() string { return Name }

func (m *Module) Configure(raw module.Config) error {
	cfg := defaults()
	if err := decodeConfig(raw, &cfg); err != nil {
		return fmt.Errorf("fivem config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("fivem config: %w", err)
	}
	m.cfg = cfg
	return nil
}

func (m *Module) Ports() []core.PortBinding {
	return []core.PortBinding{
		{Proto: core.ProtoTCP, Port: m.cfg.Port},
		{Proto: core.ProtoUDP, Port: m.cfg.Port},
	}
}

func (m *Module) Load(loaded *core.Loaded, pinPath string) error {
	if err := os.MkdirAll(pinPath, 0o755); err != nil {
		return fmt.Errorf("create pin path %s: %w", pinPath, err)
	}

	xspec, err := loadFivemXDP()
	if err != nil {
		return fmt.Errorf("load xdp spec: %w", err)
	}
	if err := m.applyRodata(xspec); err != nil {
		return err
	}

	xobj := &fivemXDPObjects{}
	if err := xspec.LoadAndAssign(xobj, &ebpf.CollectionOptions{
		MapReplacements: loaded.SharedMapReplacements(),
		Maps:            ebpf.MapOptions{PinPath: pinPath},
	}); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return fmt.Errorf("load xdp: verifier:\n%+v", verr)
		}
		return fmt.Errorf("load xdp: %w", err)
	}
	m.xdpObj = xobj

	sspec, err := loadFivemSockops()
	if err != nil {
		m.closeXDP()
		return fmt.Errorf("load sockops spec: %w", err)
	}

	// Sockops references whatever subset of shared + private maps its
	// included headers pull in. Build a candidate set, then filter to maps
	// actually present in the spec — cilium/ebpf rejects replacements for
	// undeclared maps.
	candidates := loaded.SharedMapReplacements()
	candidates["fivem_stats"] = xobj.FivemStats
	candidates["fivem_drop_history"] = xobj.FivemDropHistory
	candidates["initconnect_ratelimit"] = xobj.InitconnectRatelimit
	candidates["getinfo_ratelimit"] = xobj.GetinfoRatelimit
	sockopsReplacements := map[string]*ebpf.Map{}
	for name, m := range candidates {
		if _, ok := sspec.Maps[name]; ok {
			sockopsReplacements[name] = m
		}
	}

	sobj := &fivemSockopsObjects{}
	if err := sspec.LoadAndAssign(sobj, &ebpf.CollectionOptions{
		MapReplacements: sockopsReplacements,
	}); err != nil {
		m.closeXDP()
		return fmt.Errorf("load sockops: %w", err)
	}
	m.soObj = sobj
	return nil
}

func (m *Module) applyRodata(spec *ebpf.CollectionSpec) error {
	cfg := m.cfg

	udpPeriodNs := uint64(0)
	if cfg.UDPRatePerSec > 0 {
		udpPeriodNs = 1_000_000_000 / cfg.UDPRatePerSec
	}
	initPeriodNs := uint64(0)
	if cfg.InitConnectPerMin > 0 {
		initPeriodNs = (60 * 1_000_000_000) / cfg.InitConnectPerMin
	}
	getInfoPeriodNs := uint64(0)
	if cfg.GetInfoPerMin > 0 {
		getInfoPeriodNs = (60 * 1_000_000_000) / cfg.GetInfoPerMin
	}

	ncpu, _ := ebpf.PossibleCPU()
	if ncpu <= 0 {
		ncpu = 1
	}
	tcpGlobalPeriodNs := uint64(0)
	if cfg.TCPGlobalRatePerS > 0 {
		perCPU := cfg.TCPGlobalRatePerS / uint64(ncpu)
		if perCPU == 0 {
			perCPU = 1
		}
		tcpGlobalPeriodNs = 1_000_000_000 / perCPU
	}
	tcpGlobalBurstPerCPU := cfg.TCPGlobalBurst / uint64(ncpu)
	if cfg.TCPGlobalBurst > 0 && tcpGlobalBurstPerCPU == 0 {
		tcpGlobalBurstPerCPU = 1
	}

	vars := []struct {
		name string
		val  any
	}{
		{"whitelist_ttl_ns", uint64(cfg.WhitelistTTL.Nanoseconds())},
		{"udp_refill_period_ns", udpPeriodNs},
		{"udp_burst", cfg.UDPBurst},
		{"initconnect_period_ns", initPeriodNs},
		{"initconnect_burst", cfg.InitConnectBurst},
		{"getinfo_period_ns", getInfoPeriodNs},
		{"getinfo_burst", cfg.GetInfoBurst},
		{"tcp_global_period_ns", tcpGlobalPeriodNs},
		{"tcp_global_burst", tcpGlobalBurstPerCPU},
		{"tcp_max_open_per_ip", cfg.TCPMaxOpenPerIP},
		{"health_window_ns", uint64(cfg.HealthWindow.Nanoseconds())},
		{"health_threshold", cfg.HealthThreshold},
		{"health_blacklist_ns", uint64(cfg.HealthBlacklist.Nanoseconds())},
	}
	for _, v := range vars {
		if err := core.SetVar(spec, v.name, v.val); err != nil {
			return err
		}
	}
	return nil
}

func (m *Module) XDP() *ebpf.Program {
	if m.xdpObj == nil {
		return nil
	}
	return m.xdpObj.GameshieldFivemXdp
}

func (m *Module) Sockops() *ebpf.Program {
	if m.soObj == nil {
		return nil
	}
	return m.soObj.GameshieldFivemSockops
}

// Maps returns the module-private maps as a Maps struct (used by collectors,
// CLI subcommands, HTTP handlers).
func (m *Module) Maps() Maps {
	if m.xdpObj == nil {
		return Maps{}
	}
	return Maps{
		Stats:       m.xdpObj.FivemStats,
		DropHistory: m.xdpObj.FivemDropHistory,
		InitcRL:     m.xdpObj.InitconnectRatelimit,
		GetinfoRL:   m.xdpObj.GetinfoRatelimit,
	}
}

// SharedMaps returns the shared maps as the FiveM module sees them (same
// FDs as core.Loaded). Convenience for module-scoped CLI subcommands and
// /api routes that need to read these.
func (m *Module) SharedMaps() SharedMaps {
	if m.xdpObj == nil {
		return SharedMaps{}
	}
	return SharedMaps{
		TCPEstablished: m.xdpObj.TcpEstablished,
		TCPSynSeen:     m.xdpObj.TcpSynSeen,
		TCPWhitelist:   m.xdpObj.TcpWhitelist,
		TCPOpenCount:   m.xdpObj.TcpOpenCount,
		UDPRatelimit:   m.xdpObj.UdpRatelimit,
		UDPHealth:      m.xdpObj.UdpHealth,
	}
}

func (m *Module) Collectors() []prometheus.Collector {
	if m.collector == nil {
		m.collector = newCollector(m)
	}
	return []prometheus.Collector{m.collector}
}

func (m *Module) Start(ctx context.Context, sizeInterval time.Duration) {
	if m.collector == nil {
		m.collector = newCollector(m)
	}
	m.collector.StartSizeTicker(ctx, sizeInterval)
}

func (m *Module) Subcommands() []module.Subcommand { return subcommands() }

func (m *Module) APIRoutes(mux *http.ServeMux, prefix string) {
	registerAPI(mux, prefix, m)
}

func (m *Module) Close() error {
	var errs []error
	if m.soObj != nil {
		if m.soObj.GameshieldFivemSockops != nil {
			if err := m.soObj.GameshieldFivemSockops.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	m.closeXDP()
	return errors.Join(errs...)
}

func (m *Module) closeXDP() {
	if m.xdpObj == nil {
		return
	}
	if m.xdpObj.GameshieldFivemXdp != nil {
		m.xdpObj.GameshieldFivemXdp.Close()
	}
	for _, mp := range []*ebpf.Map{
		m.xdpObj.FivemStats, m.xdpObj.FivemDropHistory,
		m.xdpObj.InitconnectRatelimit, m.xdpObj.GetinfoRatelimit,
	} {
		if mp != nil {
			mp.Close()
		}
	}
}

// Maps is the module-private map set.
type Maps struct {
	Stats       *ebpf.Map
	DropHistory *ebpf.Map
	InitcRL     *ebpf.Map
	GetinfoRL   *ebpf.Map
}

// SharedMaps is the shared core map set as visible from this module.
type SharedMaps struct {
	TCPEstablished *ebpf.Map
	TCPSynSeen     *ebpf.Map
	TCPWhitelist   *ebpf.Map
	TCPOpenCount   *ebpf.Map
	UDPRatelimit   *ebpf.Map
	UDPHealth      *ebpf.Map
}

func init() {
	module.Register(Name, func() module.Module { return New() })
}
