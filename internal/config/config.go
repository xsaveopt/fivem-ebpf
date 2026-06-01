package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Daemon struct {
	Iface           string        `yaml:"iface"`
	CgroupPath      string        `yaml:"cgroup_path"`
	PinRoot         string        `yaml:"pin_root"`
	MetricsAddr     string        `yaml:"metrics_addr"`
	MapSizeInterval time.Duration `yaml:"map_size_interval"`
}

type Config struct {
	Daemon  Daemon                    `yaml:",inline"`
	Modules map[string]map[string]any `yaml:"modules"`
}

func defaults() Config {
	return Config{
		Daemon: Daemon{
			Iface:           "eth0",
			CgroupPath:      "/sys/fs/cgroup",
			PinRoot:         "/sys/fs/bpf/gameshield",
			MetricsAddr:     ":9464",
			MapSizeInterval: 30 * time.Second,
		},
		Modules: map[string]map[string]any{},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	cfg := defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Daemon.Iface == "" {
		return nil, fmt.Errorf("iface is required")
	}
	if cfg.Daemon.PinRoot == "" {
		cfg.Daemon.PinRoot = "/sys/fs/bpf/gameshield"
	}
	if cfg.Daemon.CgroupPath == "" {
		cfg.Daemon.CgroupPath = "/sys/fs/cgroup"
	}
	if cfg.Daemon.MetricsAddr == "" {
		cfg.Daemon.MetricsAddr = ":9464"
	}
	if cfg.Daemon.MapSizeInterval == 0 {
		cfg.Daemon.MapSizeInterval = 30 * time.Second
	}
	return &cfg, nil
}

func (c *Config) ModuleEnabled(name string) bool {
	sec, ok := c.Modules[name]
	if !ok {
		return false
	}
	enabled, _ := sec["enabled"].(bool)
	return enabled
}

func (c *Config) EnabledModules() []string {
	out := make([]string, 0, len(c.Modules))
	for name := range c.Modules {
		if c.ModuleEnabled(name) {
			out = append(out, name)
		}
	}
	return out
}
