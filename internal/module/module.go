package module

import (
	"context"
	"net/http"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sratabix/gameshield-ebpf/internal/core"
)

// Config is the module-specific subtree from the YAML config. Modules type-
// assert / unmarshal it into their concrete config struct.
type Config = map[string]any

// Subcommand describes a module-scoped CLI verb registered as
// `gameshield <module-name> <verb>`. Args are everything after the verb.
type Subcommand struct {
	Name        string
	Description string
	Run         func(args []string)
}

// Module is the contract a per-game module implements. Lifecycle:
//
//	m := fivem.New()
//	m.Configure(cfg.Subtree)
//	m.Load(coreLoaded, pinPath)               → loads BPF, populates state
//	core.RegisterXDP(slot, m.XDP())
//	core.RegisterSockops(slot, m.Sockops())   // may be nil
//	core.BindPorts(slot, m.Ports())
//	reg.MustRegister(m.Collectors()...)
//	... runtime ...
//	core.UnbindPorts(slot, m.Ports())
//	m.Close()
type Module interface {
	// Name returns a stable identifier ("fivem", "minecraft"). Used for
	// pin-path namespacing, metric labels, CLI subcommand grouping.
	Name() string

	// Configure parses the per-module YAML subtree. Called once before Load.
	Configure(raw Config) error

	// Ports lists the (proto, port) bindings this module owns. The
	// dispatcher routes matching packets to this module's XDP program.
	Ports() []core.PortBinding

	// Load creates the module's BPF objects. Shared maps come from
	// `loaded.SharedMapReplacements()`; module-private maps pin under
	// pinPath.
	Load(loaded *core.Loaded, pinPath string) error

	// XDP returns the module's tail-callable XDP program. Non-nil after Load.
	XDP() *ebpf.Program

	// Sockops returns the module's tail-callable sock_ops program, or nil
	// if the module doesn't use cgroup sockops (UDP-only modules).
	Sockops() *ebpf.Program

	// Collectors returns Prometheus collectors specific to this module.
	// Names are namespaced gameshield_<name>_*.
	Collectors() []prometheus.Collector

	// Start runs background tasks (e.g. map-size ticker for the collector's
	// gauges). Called once after Load + register, before serving traffic.
	// May be a no-op for modules with no background work.
	Start(ctx context.Context, sizeInterval time.Duration)

	// Subcommands returns module-scoped CLI verbs.
	Subcommands() []Subcommand

	// APIRoutes registers module-specific HTTP handlers under prefix
	// (typically "/api/<name>/"). May be a no-op.
	APIRoutes(mux *http.ServeMux, prefix string)

	// Close releases module resources. Map FDs are closed; pinned maps
	// stay on disk.
	Close() error
}
