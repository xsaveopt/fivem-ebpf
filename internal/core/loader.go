package core

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func PinPath(root, sub string) string {
	return filepath.Join(root, sub)
}

type Options struct {
	Iface      string
	CgroupPath string
	PinRoot    string
}

type Loaded struct {
	XDPLink     link.Link
	SockopsLink link.Link
	XDPMode     string

	TCPEstablished     *ebpf.Map
	TCPSynSeen         *ebpf.Map
	TCPWhitelist       *ebpf.Map
	TCPOpenCount       *ebpf.Map
	TCPGlobalRatelimit *ebpf.Map
	UDPRatelimit       *ebpf.Map
	UDPHealth          *ebpf.Map

	XDPModules     *ebpf.Map
	SockopsModules *ebpf.Map
	PortRouter     *ebpf.Map
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
		l.TCPEstablished, l.TCPSynSeen, l.TCPWhitelist, l.TCPOpenCount,
		l.TCPGlobalRatelimit, l.UDPRatelimit, l.UDPHealth,
		l.XDPModules, l.SockopsModules, l.PortRouter,
	} {
		if m != nil {
			m.Close()
		}
	}
	return errors.Join(errs...)
}

func Load(opts Options) (*Loaded, error) {
	ifc, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", opts.Iface, err)
	}
	corePin := PinPath(opts.PinRoot, "core")
	if err := os.MkdirAll(corePin, 0o755); err != nil {
		return nil, fmt.Errorf("create pin path %s: %w", corePin, err)
	}

	xspec, err := loadDispatcherXDP()
	if err != nil {
		return nil, fmt.Errorf("load xdp dispatcher spec: %w", err)
	}
	xobj := &dispatcherXDPObjects{}
	if err := xspec.LoadAndAssign(xobj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: corePin},
	}); err != nil {
		return nil, fmt.Errorf("load xdp dispatcher: %w", err)
	}

	xlink, xmode, err := attachXDP(xobj.GameshieldDispatchXdp, ifc.Index)
	if err != nil {
		closeAllMaps(xobj)
		xobj.GameshieldDispatchXdp.Close()
		return nil, fmt.Errorf("attach xdp: %w", err)
	}
	xobj.GameshieldDispatchXdp.Close()

	sspec, err := loadDispatcherSockops()
	if err != nil {
		xlink.Close()
		closeAllMaps(xobj)
		return nil, fmt.Errorf("load sockops dispatcher spec: %w", err)
	}
	sobj := &dispatcherSockopsObjects{}
	if err := sspec.LoadAndAssign(sobj, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"xdp_modules":     xobj.XdpModules,
			"sockops_modules": xobj.SockopsModules,
			"port_router":     xobj.PortRouter,
		},
	}); err != nil {
		xlink.Close()
		closeAllMaps(xobj)
		return nil, fmt.Errorf("load sockops dispatcher: %w", err)
	}
	slink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    opts.CgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: sobj.GameshieldDispatchSockops,
	})
	if err != nil {
		sobj.GameshieldDispatchSockops.Close()
		xlink.Close()
		closeAllMaps(xobj)
		return nil, fmt.Errorf("attach sockops to %s: %w", opts.CgroupPath, err)
	}
	sobj.GameshieldDispatchSockops.Close()

	return &Loaded{
		XDPLink:            xlink,
		SockopsLink:        slink,
		XDPMode:            xmode,
		TCPEstablished:     xobj.TcpEstablished,
		TCPSynSeen:         xobj.TcpSynSeen,
		TCPWhitelist:       xobj.TcpWhitelist,
		TCPOpenCount:       xobj.TcpOpenCount,
		TCPGlobalRatelimit: xobj.TcpGlobalRatelimit,
		UDPRatelimit:       xobj.UdpRatelimit,
		UDPHealth:          xobj.UdpHealth,
		XDPModules:         xobj.XdpModules,
		SockopsModules:     xobj.SockopsModules,
		PortRouter:         xobj.PortRouter,
	}, nil
}

func (l *Loaded) SharedMapReplacements() map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		"tcp_established":      l.TCPEstablished,
		"tcp_syn_seen":         l.TCPSynSeen,
		"tcp_whitelist":        l.TCPWhitelist,
		"tcp_open_count":       l.TCPOpenCount,
		"tcp_global_ratelimit": l.TCPGlobalRatelimit,
		"udp_ratelimit":        l.UDPRatelimit,
		"udp_health":           l.UDPHealth,
	}
}

type Proto uint8

const (
	ProtoTCP Proto = 6
	ProtoUDP Proto = 17
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	default:
		return fmt.Sprintf("proto-%d", uint8(p))
	}
}

type PortBinding struct {
	Proto Proto
	Port  uint16
}

func (b PortBinding) routerKey() uint32 {
	return (uint32(b.Proto) << 16) | uint32(b.Port)
}

func (l *Loaded) RegisterXDP(slot uint32, prog *ebpf.Program) error {
	fd := uint32(prog.FD())
	return l.XDPModules.Update(slot, fd, ebpf.UpdateAny)
}

func (l *Loaded) RegisterSockops(slot uint32, prog *ebpf.Program) error {
	if prog == nil {
		return nil
	}
	fd := uint32(prog.FD())
	return l.SockopsModules.Update(slot, fd, ebpf.UpdateAny)
}

func (l *Loaded) BindPorts(slot uint32, ports []PortBinding) error {
	for _, b := range ports {
		key := b.routerKey()
		if err := l.PortRouter.Update(key, slot, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("bind %s/%d: %w", b.Proto, b.Port, err)
		}
	}
	return nil
}

func (l *Loaded) UnbindPorts(slot uint32, ports []PortBinding) {
	for _, b := range ports {
		key := b.routerKey()
		_ = l.PortRouter.Delete(key)
	}
	_ = l.XDPModules.Delete(slot)
	_ = l.SockopsModules.Delete(slot)
}

func SetVar(spec *ebpf.CollectionSpec, name string, value any) error {
	v, ok := spec.Variables[name]
	if !ok {
		return nil
	}
	if err := v.Set(value); err != nil {
		return fmt.Errorf("set %s: %w", name, err)
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
		return nil, "", fmt.Errorf("native: %v; generic: %w", err, err2)
	}
	return l, "generic", nil
}

func closeAllMaps(o *dispatcherXDPObjects) {
	for _, m := range []*ebpf.Map{
		o.TcpEstablished, o.TcpSynSeen, o.TcpWhitelist, o.TcpOpenCount,
		o.TcpGlobalRatelimit, o.UdpRatelimit, o.UdpHealth,
		o.XdpModules, o.SockopsModules, o.PortRouter,
	} {
		if m != nil {
			m.Close()
		}
	}
}
