package bpfmaps

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
)

const NumDropReasons = 13

var DropReasonNames = [NumDropReasons]string{
	"tcp_no_syn",
	"tcp_too_many_open",
	"tcp_global_ratelimit",
	"tcp_bad_user_agent",
	"tcp_initconnect_ratelimit",
	"tcp_getinfo_ratelimit",
	"malformed",
	"udp_not_whitelisted",
	"udp_expired",
	"udp_unhealthy",
	"udp_enet_malformed",
	"udp_ratelimit",
	"ip_fragment",
}

const (
	StatPassTCP = iota
	StatPassUDPWhitelisted
	StatDropUDPNotWhitelisted
	StatDropUDPExpired
	StatDropMalformed
	StatTCPEstablishedInserts
	StatTCPL7Promoted
	StatTCPL7MatchNoEst
	StatDropUDPRatelimit
	StatDropTCPInitconnectRatelimit
	StatDropUDPEnetMalformed
	StatDropUDPUnhealthy
	StatTCPPostClientSeen
	StatTCPGetinfoSeen
	StatDropTCPGetinfoRatelimit
	StatDropTCPBadUserAgent
	StatDropTCPNoSyn
	StatDropTCPGlobalRatelimit
	StatDropTCPTooManyOpen
	StatTCPPostUAUnknown
	StatDropIPFragment
	StatMax
)

var StatLabels = [StatMax]string{
	StatPassTCP:                     "pass_tcp",
	StatPassUDPWhitelisted:          "pass_udp_whitelisted",
	StatDropUDPNotWhitelisted:       "drop_udp_not_whitelisted",
	StatDropUDPExpired:              "drop_udp_expired",
	StatDropMalformed:               "drop_malformed",
	StatTCPEstablishedInserts:       "tcp_established_inserts",
	StatTCPL7Promoted:               "tcp_l7_promoted",
	StatTCPL7MatchNoEst:             "tcp_l7_match_no_est",
	StatDropUDPRatelimit:            "drop_udp_ratelimit",
	StatDropTCPInitconnectRatelimit: "drop_tcp_initconnect_ratelimit",
	StatDropUDPEnetMalformed:        "drop_udp_enet_malformed",
	StatDropUDPUnhealthy:            "drop_udp_unhealthy",
	StatTCPPostClientSeen:           "tcp_post_client_seen",
	StatTCPGetinfoSeen:              "tcp_getinfo_seen",
	StatDropTCPGetinfoRatelimit:     "drop_tcp_getinfo_ratelimit",
	StatDropTCPBadUserAgent:         "drop_tcp_bad_user_agent",
	StatDropTCPNoSyn:                "drop_tcp_no_syn",
	StatDropTCPGlobalRatelimit:      "drop_tcp_global_ratelimit",
	StatDropTCPTooManyOpen:          "drop_tcp_too_many_open",
	StatTCPPostUAUnknown:            "tcp_post_ua_unknown",
	StatDropIPFragment:              "drop_ip_fragment",
}

type Ratelimit struct {
	Tokens       uint64
	LastRefillNS uint64
}

type UDPHealth struct {
	Anomalies        uint32
	_                uint32
	WindowStartNS    uint64
	BlacklistUntilNS uint64
}

type DropHistory struct {
	FirstDropNS uint64
	LastDropNS  uint64
	Counts      [NumDropReasons]uint64
}

const (
	Whitelist            = "tcp_whitelist"
	Established          = "tcp_established"
	SynSeen              = "tcp_syn_seen"
	OpenCount            = "tcp_open_count"
	UDPRatelimit         = "udp_ratelimit"
	InitConnectRatelimit = "initconnect_ratelimit"
	GetInfoRatelimit     = "getinfo_ratelimit"
	Health               = "udp_health"
	DropHistoryMap       = "ip_drop_history"
	Stats                = "stats"
)

var PerIP = []string{
	Whitelist,
	Established,
	SynSeen,
	OpenCount,
	UDPRatelimit,
	InitConnectRatelimit,
	GetInfoRatelimit,
	Health,
	DropHistoryMap,
}

var CLIName = map[string]string{
	"whitelist":             Whitelist,
	"established":           Established,
	"syn-seen":              SynSeen,
	"open-count":            OpenCount,
	"udp-ratelimit":         UDPRatelimit,
	"initconnect-ratelimit": InitConnectRatelimit,
	"getinfo-ratelimit":     GetInfoRatelimit,
	"health":                Health,
	"drop-history":          DropHistoryMap,
}

const CLINamesHelp = "whitelist | established | syn-seen | open-count | " +
	"udp-ratelimit | initconnect-ratelimit | getinfo-ratelimit | health | drop-history"

type Iterator interface {
	Next(keyOut, valueOut any) bool
	Err() error
}

type Reader interface {
	Iterate() Iterator
	Lookup(key, valueOut any) error
}

type Map struct{ M *ebpf.Map }

func (m Map) Iterate() Iterator { return m.M.Iterate() }

func (m Map) Lookup(key, valueOut any) error { return m.M.Lookup(key, valueOut) }

func NewReader(m *ebpf.Map) Reader {
	if m == nil {
		return nil
	}
	return Map{M: m}
}

func Open(pinPath, name string) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	return m, nil
}

func CountKeys(m *ebpf.Map) (int64, error) {
	if m == nil {
		return -1, nil
	}
	var n int64
	var cur, next [4]byte
	var prev any
	for {
		if err := m.NextKey(prev, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return n, nil
			}
			return n, err
		}
		n++
		cur = next
		prev = &cur
	}
}

func ReadStats(m *ebpf.Map) ([]uint64, error) {
	if m == nil {
		return nil, fmt.Errorf("stats map not available")
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("possible cpus: %w", err)
	}
	if ncpu <= 0 {
		return nil, fmt.Errorf("possible cpus: %d", ncpu)
	}
	perCPU := make([]uint64, ncpu)
	out := make([]uint64, StatMax)
	for i := range out {
		k := uint32(i)
		if err := m.Lookup(&k, &perCPU); err != nil {
			return nil, fmt.Errorf("stat slot %d (%s): %w", i, StatLabels[i], err)
		}
		var s uint64
		for _, v := range perCPU {
			s += v
		}
		out[i] = s
	}
	return out, nil
}
