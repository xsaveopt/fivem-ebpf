package loader

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

type Options struct {
	Iface             string
	Port              uint16
	TTL               time.Duration
	CgroupPath        string
	PinPath           string
	UDPRatePerSec     uint64
	UDPBurst          uint64
	InitConnectPerMin uint64
	InitConnectBurst  uint64
	GetInfoPerMin     uint64
	GetInfoBurst      uint64
	TCPGlobalPerSec   uint64
	TCPGlobalBurst    uint64
	TCPMaxOpenPerIP   uint64
	HealthWindow      time.Duration
	HealthThreshold   uint32
	HealthBlacklist   time.Duration
	DropHistory       bool
}

type Loaded struct {
	XDPLink              link.Link
	SockopsLink          link.Link
	TCPEstablished       *ebpf.Map
	TCPSynSeen           *ebpf.Map
	TCPWhitelist         *ebpf.Map
	UDPRatelimit         *ebpf.Map
	InitConnectRatelimit *ebpf.Map
	GetInfoRatelimit     *ebpf.Map
	TCPGlobalRatelimit   *ebpf.Map
	TCPOpenCount         *ebpf.Map
	UDPHealth            *ebpf.Map
	IPDropHistory        *ebpf.Map
	Stats                *ebpf.Map
	XDPMode              string
}

func (l *Loaded) ByPinnedName(name string) *ebpf.Map {
	switch name {
	case bpfmaps.Whitelist:
		return l.TCPWhitelist
	case bpfmaps.Established:
		return l.TCPEstablished
	case bpfmaps.SynSeen:
		return l.TCPSynSeen
	case bpfmaps.OpenCount:
		return l.TCPOpenCount
	case bpfmaps.UDPRatelimit:
		return l.UDPRatelimit
	case bpfmaps.InitConnectRatelimit:
		return l.InitConnectRatelimit
	case bpfmaps.GetInfoRatelimit:
		return l.GetInfoRatelimit
	case bpfmaps.Health:
		return l.UDPHealth
	case bpfmaps.DropHistoryMap:
		return l.IPDropHistory
	case bpfmaps.Stats:
		return l.Stats
	}
	return nil
}

func (l *Loaded) Close() error {
	var errs []error
	if l.SockopsLink != nil {
		if err := l.SockopsLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if l.XDPLink != nil {
		if err := l.XDPLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, m := range []*ebpf.Map{
		l.TCPEstablished, l.TCPSynSeen, l.TCPWhitelist,
		l.UDPRatelimit, l.InitConnectRatelimit,
		l.GetInfoRatelimit, l.TCPGlobalRatelimit,
		l.TCPOpenCount, l.UDPHealth, l.IPDropHistory, l.Stats,
	} {
		if m != nil {
			if err := m.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func Load(opts Options) (*Loaded, error) {
	ifc, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", opts.Iface, err)
	}
	if err := os.MkdirAll(opts.PinPath, 0o755); err != nil {
		return nil, fmt.Errorf("create pin path: %w", err)
	}
	if err := checkBPFFS(opts.PinPath); err != nil {
		return nil, err
	}

	xobj, err := loadXDP(opts)
	if err != nil {
		return nil, err
	}
	xlink, xmode, err := attachXDP(xobj.FivemXdp, ifc.Index)
	if err != nil {
		closeXDPObjs(xobj)
		return nil, fmt.Errorf("attach xdp: %w", err)
	}
	_ = xobj.FivemXdp.Close()

	sobj, err := loadSockops(opts)
	if err != nil {
		_ = xlink.Close()
		closeXDPMaps(xobj)
		return nil, err
	}
	slink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    opts.CgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: sobj.FivemSockops,
	})
	if err != nil {
		closeSockopsObjs(sobj)
		_ = xlink.Close()
		closeXDPMaps(xobj)
		return nil, fmt.Errorf("attach sockops to %s: %w", opts.CgroupPath, err)
	}
	_ = sobj.FivemSockops.Close()
	closeSockopsMaps(sobj)

	if err := clearMap(xobj.TcpOpenCount); err != nil {
		_ = slink.Close()
		_ = xlink.Close()
		closeXDPMaps(xobj)
		return nil, fmt.Errorf("reset %s: %w", "tcp_open_count", err)
	}

	return &Loaded{
		XDPLink:              xlink,
		SockopsLink:          slink,
		TCPEstablished:       xobj.TcpEstablished,
		TCPSynSeen:           xobj.TcpSynSeen,
		TCPWhitelist:         xobj.TcpWhitelist,
		UDPRatelimit:         xobj.UdpRatelimit,
		InitConnectRatelimit: xobj.InitconnectRatelimit,
		GetInfoRatelimit:     xobj.GetinfoRatelimit,
		TCPGlobalRatelimit:   xobj.TcpGlobalRatelimit,
		TCPOpenCount:         xobj.TcpOpenCount,
		UDPHealth:            xobj.UdpHealth,
		IPDropHistory:        xobj.IpDropHistory,
		Stats:                xobj.Stats,
		XDPMode:              xmode,
	}, nil
}

func loadXDP(opts Options) (*fivemXDPObjects, error) {
	spec, err := loadFivemXDP()
	if err != nil {
		return nil, fmt.Errorf("load xdp spec: %w", err)
	}
	if err := setVar(spec, "target_port", opts.Port); err != nil {
		return nil, err
	}
	if err := setVar(spec, "whitelist_ttl_ns", uint64(opts.TTL.Nanoseconds())); err != nil {
		return nil, err
	}
	var udpPeriodNs uint64
	if opts.UDPRatePerSec > 0 {
		udpPeriodNs = 1_000_000_000 / opts.UDPRatePerSec
	}
	if err := setVar(spec, "udp_refill_period_ns", udpPeriodNs); err != nil {
		return nil, err
	}
	if err := setVar(spec, "udp_burst", opts.UDPBurst); err != nil {
		return nil, err
	}
	var initPeriodNs uint64
	if opts.InitConnectPerMin > 0 {
		initPeriodNs = (60 * 1_000_000_000) / opts.InitConnectPerMin
	}
	if err := setVar(spec, "initconnect_period_ns", initPeriodNs); err != nil {
		return nil, err
	}
	if err := setVar(spec, "initconnect_burst", opts.InitConnectBurst); err != nil {
		return nil, err
	}
	var getInfoPeriodNs uint64
	if opts.GetInfoPerMin > 0 {
		getInfoPeriodNs = (60 * 1_000_000_000) / opts.GetInfoPerMin
	}
	if err := setVar(spec, "getinfo_period_ns", getInfoPeriodNs); err != nil {
		return nil, err
	}
	if err := setVar(spec, "getinfo_burst", opts.GetInfoBurst); err != nil {
		return nil, err
	}

	ncpu := runtime.NumCPU()
	if ncpu <= 0 {
		ncpu = 1
	}
	var tcpGlobalPeriodNs uint64
	if opts.TCPGlobalPerSec > 0 {
		perCPURate := opts.TCPGlobalPerSec / uint64(ncpu)
		if perCPURate == 0 {
			perCPURate = 1
		}
		tcpGlobalPeriodNs = 1_000_000_000 / perCPURate
	}
	tcpGlobalBurstPerCPU := opts.TCPGlobalBurst / uint64(ncpu)
	if opts.TCPGlobalBurst > 0 && tcpGlobalBurstPerCPU == 0 {
		tcpGlobalBurstPerCPU = 1
	}
	if err := setVar(spec, "tcp_global_period_ns", tcpGlobalPeriodNs); err != nil {
		return nil, err
	}
	if err := setVar(spec, "tcp_global_burst", tcpGlobalBurstPerCPU); err != nil {
		return nil, err
	}
	if err := setVar(spec, "tcp_max_open_per_ip", opts.TCPMaxOpenPerIP); err != nil {
		return nil, err
	}
	if err := setVar(spec, "health_window_ns", uint64(opts.HealthWindow.Nanoseconds())); err != nil {
		return nil, err
	}
	if err := setVar(spec, "health_threshold", opts.HealthThreshold); err != nil {
		return nil, err
	}
	if err := setVar(spec, "health_blacklist_ns", uint64(opts.HealthBlacklist.Nanoseconds())); err != nil {
		return nil, err
	}
	var dropHistory uint8
	if opts.DropHistory {
		dropHistory = 1
	}
	if err := setVar(spec, "drop_history_enabled", dropHistory); err != nil {
		return nil, err
	}
	obj := &fivemXDPObjects{}
	if err := spec.LoadAndAssign(obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: opts.PinPath},
	}); err != nil {
		return nil, wrapLoadError("xdp", opts.PinPath, err)
	}
	return obj, nil
}

func wrapLoadError(what, pinPath string, err error) error {
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		return fmt.Errorf("load %s objects: the pinned maps in %s were created by an "+
			"incompatible build; remove them with: rm -rf %s (this drops every active "+
			"session and forces players to reconnect): %w", what, pinPath, pinPath, err)
	}
	return fmt.Errorf("load %s objects: %w", what, err)
}

func loadSockops(opts Options) (*fivemSockopsObjects, error) {
	spec, err := loadFivemSockops()
	if err != nil {
		return nil, fmt.Errorf("load sockops spec: %w", err)
	}
	if err := setVar(spec, "target_port", opts.Port); err != nil {
		return nil, err
	}
	obj := &fivemSockopsObjects{}
	if err := spec.LoadAndAssign(obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: opts.PinPath},
	}); err != nil {
		return nil, wrapLoadError("sockops", opts.PinPath, err)
	}
	return obj, nil
}

func setVar(spec *ebpf.CollectionSpec, name string, value any) error {
	v, ok := spec.Variables[name]
	if !ok {
		return fmt.Errorf("bpf program has no variable %q: rebuild the BPF objects (make generate)", name)
	}
	if err := v.Set(value); err != nil {
		return fmt.Errorf("set %s: %w", name, err)
	}
	return nil
}

func clearMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	var keys [][4]byte
	var key [4]byte
	valBuf := make([]byte, m.ValueSize())
	iter := m.Iterate()
	for iter.Next(&key, &valBuf) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := m.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func attachXDP(prog *ebpf.Program, ifindex int) (link.Link, string, error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
		Flags:     link.XDPDriverMode,
	})
	if err == nil {
		return l, "native", nil
	}
	l, err2 := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
		Flags:     link.XDPGenericMode,
	})
	if err2 != nil {
		return nil, "", fmt.Errorf("native: %w; generic: %w", err, err2)
	}
	return l, "generic", nil
}

func closeXDPObjs(o *fivemXDPObjects) {
	_ = o.FivemXdp.Close()
	closeXDPMaps(o)
}

func closeXDPMaps(o *fivemXDPObjects) {
	for _, m := range []*ebpf.Map{
		o.TcpEstablished, o.TcpSynSeen, o.TcpWhitelist,
		o.UdpRatelimit, o.InitconnectRatelimit,
		o.GetinfoRatelimit, o.TcpGlobalRatelimit,
		o.TcpOpenCount, o.UdpHealth, o.IpDropHistory, o.Stats,
	} {
		if m != nil {
			_ = m.Close()
		}
	}
}

func closeSockopsObjs(o *fivemSockopsObjects) {
	_ = o.FivemSockops.Close()
	closeSockopsMaps(o)
}

func closeSockopsMaps(o *fivemSockopsObjects) {
	for _, m := range []*ebpf.Map{
		o.TcpEstablished, o.TcpSynSeen, o.TcpWhitelist,
		o.UdpRatelimit, o.InitconnectRatelimit,
		o.GetinfoRatelimit, o.TcpGlobalRatelimit,
		o.TcpOpenCount, o.UdpHealth, o.IpDropHistory, o.Stats,
	} {
		if m != nil {
			_ = m.Close()
		}
	}
}
