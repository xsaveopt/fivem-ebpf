// Package metrics holds the gameshield-level Prometheus collectors. Module-
// specific metrics live in each module's package and are registered via
// Module.Collectors().
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Core exposes attach state, build info, and per-module attach gauges.
type Core struct {
	version string
	iface   string
	pinRoot string
	xdpMode string

	xdpAttached     func() bool
	sockopsAttached func() bool
	moduleAttached  func() map[string]bool

	buildInfo *prometheus.Desc
	attached  *prometheus.Desc
	moduleGa  *prometheus.Desc
}

// NewCore builds the core collector. xdpAttached/sockopsAttached return the
// dispatcher attach state; moduleAttached returns module-name → attached.
func NewCore(version, iface, pinRoot, xdpMode string,
	xdpAttached, sockopsAttached func() bool,
	moduleAttached func() map[string]bool,
) *Core {
	return &Core{
		version:         version,
		iface:           iface,
		pinRoot:         pinRoot,
		xdpMode:         xdpMode,
		xdpAttached:     xdpAttached,
		sockopsAttached: sockopsAttached,
		moduleAttached:  moduleAttached,
		buildInfo: prometheus.NewDesc(
			"gameshield_build_info",
			"Build and runtime configuration.",
			[]string{"version", "iface", "pin_root", "xdp_mode"}, nil,
		),
		attached: prometheus.NewDesc(
			"gameshield_attached",
			"Dispatcher attach state (1=attached, 0=not).",
			[]string{"program"}, nil,
		),
		moduleGa: prometheus.NewDesc(
			"gameshield_module_attached",
			"Per-module attach state (1=registered with the dispatcher).",
			[]string{"module"}, nil,
		),
	}
}

func (c *Core) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.buildInfo
	ch <- c.attached
	ch <- c.moduleGa
}

func (c *Core) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		c.buildInfo, prometheus.GaugeValue, 1,
		c.version, c.iface, c.pinRoot, c.xdpMode,
	)
	ch <- prometheus.MustNewConstMetric(c.attached, prometheus.GaugeValue, b2f(c.xdpAttached()), "xdp")
	ch <- prometheus.MustNewConstMetric(c.attached, prometheus.GaugeValue, b2f(c.sockopsAttached()), "sockops")
	for name, ok := range c.moduleAttached() {
		ch <- prometheus.MustNewConstMetric(c.moduleGa, prometheus.GaugeValue, b2f(ok), name)
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
