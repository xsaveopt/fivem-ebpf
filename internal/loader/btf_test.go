package loader

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func xdpSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	spec, err := loadFivemXDP()
	if err != nil {
		t.Fatalf("load xdp spec: %v", err)
	}
	return spec
}

func structByName(t *testing.T, spec *ebpf.CollectionSpec, name string) *btf.Struct {
	t.Helper()
	var s *btf.Struct
	if err := spec.Types.TypeByName(name, &s); err != nil {
		t.Fatalf("BTF has no struct %s: %v", name, err)
	}
	return s
}

func assertLayout(t *testing.T, s *btf.Struct, goType reflect.Type, fields map[string]string) {
	t.Helper()
	if uint32(goType.Size()) != s.Size {
		t.Errorf("%s: C size %d, Go %s size %d", s.Name, s.Size, goType, goType.Size())
	}
	byName := map[string]btf.Member{}
	for _, m := range s.Members {
		byName[m.Name] = m
	}
	for cName, goName := range fields {
		m, ok := byName[cName]
		if !ok {
			t.Errorf("%s: C struct has no member %s", s.Name, cName)
			continue
		}
		f, ok := goType.FieldByName(goName)
		if !ok {
			t.Errorf("%s: Go type %s has no field %s", s.Name, goType, goName)
			continue
		}
		if want := uint64(m.Offset.Bytes()); f.Offset != uintptr(want) {
			t.Errorf("%s.%s: C offset %d, Go %s.%s offset %d",
				s.Name, cName, want, goType, goName, f.Offset)
		}
	}
	if len(byName) != len(fields) {
		t.Errorf("%s: C struct has %d members, test covers %d", s.Name, len(byName), len(fields))
	}
}

func TestRatelimitLayout(t *testing.T) {
	spec := xdpSpec(t)
	assertLayout(t, structByName(t, spec, "ratelimit"),
		reflect.TypeOf(bpfmaps.Ratelimit{}),
		map[string]string{
			"tokens":         "Tokens",
			"last_refill_ns": "LastRefillNS",
		})
}

func TestUDPHealthLayout(t *testing.T) {
	spec := xdpSpec(t)
	assertLayout(t, structByName(t, spec, "udp_health"),
		reflect.TypeOf(bpfmaps.UDPHealth{}),
		map[string]string{
			"anomalies":          "Anomalies",
			"window_start_ns":    "WindowStartNS",
			"blacklist_until_ns": "BlacklistUntilNS",
		})
}

func TestDropHistoryLayout(t *testing.T) {
	spec := xdpSpec(t)
	s := structByName(t, spec, "ip_drop_history")
	assertLayout(t, s, reflect.TypeOf(bpfmaps.DropHistory{}),
		map[string]string{
			"first_drop_ns": "FirstDropNS",
			"last_drop_ns":  "LastDropNS",
			"counts":        "Counts",
		})

	for _, m := range s.Members {
		if m.Name != "counts" {
			continue
		}
		arr, ok := m.Type.(*btf.Array)
		if !ok {
			t.Fatalf("counts is %T, want an array", m.Type)
		}
		if arr.Nelems != bpfmaps.NumDropReasons {
			t.Errorf("NUM_DROP_REASONS is %d in C, NumDropReasons is %d in Go",
				arr.Nelems, bpfmaps.NumDropReasons)
		}
	}
}

func TestEveryTunableExists(t *testing.T) {
	spec := xdpSpec(t)
	for _, name := range []string{
		"target_port",
		"whitelist_ttl_ns",
		"udp_refill_period_ns",
		"udp_burst",
		"initconnect_period_ns",
		"initconnect_burst",
		"getinfo_period_ns",
		"getinfo_burst",
		"tcp_global_period_ns",
		"tcp_global_burst",
		"tcp_max_open_per_ip",
		"health_window_ns",
		"health_threshold",
		"health_blacklist_ns",
		"drop_history_enabled",
	} {
		if _, ok := spec.Variables[name]; !ok {
			t.Errorf("xdp program has no variable %q, so setVar would reject it", name)
		}
	}

	sockops, err := loadFivemSockops()
	if err != nil {
		t.Fatalf("load sockops spec: %v", err)
	}
	if _, ok := sockops.Variables["target_port"]; !ok {
		t.Error("sockops program has no variable \"target_port\"")
	}
}
