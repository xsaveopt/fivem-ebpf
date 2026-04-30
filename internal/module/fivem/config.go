package fivem

import (
	"fmt"
	"time"
)

// Config is the parsed `modules.fivem` subtree. Defaults match the values
// the standalone fivem-ebpf binary used historically.
type Config struct {
	Port               uint16        `yaml:"port"`
	WhitelistTTL       time.Duration `yaml:"whitelist_ttl"`
	UDPRatePerSec      uint64        `yaml:"udp_rate_per_sec"`
	UDPBurst           uint64        `yaml:"udp_burst"`
	InitConnectPerMin  uint64        `yaml:"initconnect_per_min"`
	InitConnectBurst   uint64        `yaml:"initconnect_burst"`
	GetInfoPerMin      uint64        `yaml:"getinfo_per_min"`
	GetInfoBurst       uint64        `yaml:"getinfo_burst"`
	TCPGlobalRatePerS  uint64        `yaml:"tcp_global_rate_per_sec"` // 0 disables
	TCPGlobalBurst     uint64        `yaml:"tcp_global_burst"`
	TCPMaxOpenPerIP    uint64        `yaml:"tcp_max_open_per_ip"` // 0 disables
	HealthWindow       time.Duration `yaml:"health_window"`
	HealthThreshold    uint32        `yaml:"health_threshold"`
	HealthBlacklist    time.Duration `yaml:"health_blacklist"`
}

// defaults returns the historical fivem-ebpf settings.
func defaults() Config {
	return Config{
		Port:              30120,
		WhitelistTTL:      10 * time.Minute,
		UDPRatePerSec:     1500,
		UDPBurst:          4500,
		InitConnectPerMin: 6,
		InitConnectBurst:  3,
		GetInfoPerMin:     6,
		GetInfoBurst:      5,
		TCPGlobalRatePerS: 5000,
		TCPGlobalBurst:    15000,
		TCPMaxOpenPerIP:   16,
		HealthWindow:      60 * time.Second,
		HealthThreshold:   100,
		HealthBlacklist:   5 * time.Minute,
	}
}

// validate enforces the few invariants that aren't expressible at the
// type level (e.g. burst > 0 if rate > 0).
func (c *Config) validate() error {
	if c.Port == 0 {
		return fmt.Errorf("port must be > 0")
	}
	if c.UDPRatePerSec > 0 && c.UDPBurst == 0 {
		return fmt.Errorf("udp_burst must be > 0 when udp_rate_per_sec > 0")
	}
	if c.InitConnectPerMin > 0 && c.InitConnectBurst == 0 {
		return fmt.Errorf("initconnect_burst must be > 0 when initconnect_per_min > 0")
	}
	if c.GetInfoPerMin > 0 && c.GetInfoBurst == 0 {
		return fmt.Errorf("getinfo_burst must be > 0 when getinfo_per_min > 0")
	}
	if c.TCPGlobalRatePerS > 0 && c.TCPGlobalBurst == 0 {
		return fmt.Errorf("tcp_global_burst must be > 0 when tcp_global_rate_per_sec > 0")
	}
	return nil
}
