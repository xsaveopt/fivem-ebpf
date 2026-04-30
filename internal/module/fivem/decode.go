package fivem

import (
	"fmt"
	"time"
)

// decodeConfig copies values from the YAML-decoded raw map into a typed
// Config. We don't use yaml.Unmarshal directly because the daemon receives
// the full config and hands each module its already-decoded subtree as a
// generic map[string]any.
func decodeConfig(raw map[string]any, out *Config) error {
	for k, v := range raw {
		switch k {
		case "port":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.Port = uint16(n)
		case "whitelist_ttl":
			d, err := asDuration(v, k)
			if err != nil {
				return err
			}
			out.WhitelistTTL = d
		case "udp_rate_per_sec":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.UDPRatePerSec = n
		case "udp_burst":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.UDPBurst = n
		case "initconnect_per_min":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.InitConnectPerMin = n
		case "initconnect_burst":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.InitConnectBurst = n
		case "getinfo_per_min":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.GetInfoPerMin = n
		case "getinfo_burst":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.GetInfoBurst = n
		case "tcp_global_rate_per_sec":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.TCPGlobalRatePerS = n
		case "tcp_global_burst":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.TCPGlobalBurst = n
		case "tcp_max_open_per_ip":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.TCPMaxOpenPerIP = n
		case "health_window":
			d, err := asDuration(v, k)
			if err != nil {
				return err
			}
			out.HealthWindow = d
		case "health_threshold":
			n, err := asUint(v, k)
			if err != nil {
				return err
			}
			out.HealthThreshold = uint32(n)
		case "health_blacklist":
			d, err := asDuration(v, k)
			if err != nil {
				return err
			}
			out.HealthBlacklist = d
		case "enabled":
			// handled at the daemon level, ignored here
		default:
			return fmt.Errorf("unknown key: %s", k)
		}
	}
	return nil
}

func asUint(v any, name string) (uint64, error) {
	switch n := v.(type) {
	case int:
		if n < 0 {
			return 0, fmt.Errorf("%s: negative value %d", name, n)
		}
		return uint64(n), nil
	case int64:
		if n < 0 {
			return 0, fmt.Errorf("%s: negative value %d", name, n)
		}
		return uint64(n), nil
	case uint:
		return uint64(n), nil
	case uint64:
		return n, nil
	case float64:
		if n < 0 {
			return 0, fmt.Errorf("%s: negative value %v", name, n)
		}
		return uint64(n), nil
	default:
		return 0, fmt.Errorf("%s: expected number, got %T", name, v)
	}
}

func asDuration(v any, name string) (time.Duration, error) {
	switch n := v.(type) {
	case string:
		d, err := time.ParseDuration(n)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", name, err)
		}
		return d, nil
	case time.Duration:
		return n, nil
	default:
		return 0, fmt.Errorf("%s: expected duration string, got %T", name, v)
	}
}
