package module

import (
	"context"
	"net/http"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sratabix/gameshield-ebpf/internal/core"
)

type Config = map[string]any

type Subcommand struct {
	Name        string
	Description string
	Run         func(args []string)
}

type Module interface {
	Name() string
	Configure(raw Config) error
	Ports() []core.PortBinding
	Load(loaded *core.Loaded, pinPath string) error
	XDP() *ebpf.Program
	Sockops() *ebpf.Program
	Collectors() []prometheus.Collector
	Start(ctx context.Context, sizeInterval time.Duration)
	Subcommands() []Subcommand
	APIRoutes(mux *http.ServeMux, prefix string)
	Close() error
}
