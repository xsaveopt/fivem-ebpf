package loader

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func TestByPinnedNameResolvesEveryPinnedMap(t *testing.T) {
	l := &Loaded{
		TCPWhitelist:         &ebpf.Map{},
		TCPEstablished:       &ebpf.Map{},
		TCPSynSeen:           &ebpf.Map{},
		TCPOpenCount:         &ebpf.Map{},
		UDPRatelimit:         &ebpf.Map{},
		InitConnectRatelimit: &ebpf.Map{},
		GetInfoRatelimit:     &ebpf.Map{},
		UDPHealth:            &ebpf.Map{},
		IPDropHistory:        &ebpf.Map{},
		Stats:                &ebpf.Map{},
	}
	want := map[string]*ebpf.Map{
		bpfmaps.Whitelist:            l.TCPWhitelist,
		bpfmaps.Established:          l.TCPEstablished,
		bpfmaps.SynSeen:              l.TCPSynSeen,
		bpfmaps.OpenCount:            l.TCPOpenCount,
		bpfmaps.UDPRatelimit:         l.UDPRatelimit,
		bpfmaps.InitConnectRatelimit: l.InitConnectRatelimit,
		bpfmaps.GetInfoRatelimit:     l.GetInfoRatelimit,
		bpfmaps.Health:               l.UDPHealth,
		bpfmaps.DropHistoryMap:       l.IPDropHistory,
		bpfmaps.Stats:                l.Stats,
	}
	seen := map[*ebpf.Map]string{}
	for name, m := range want {
		got := l.ByPinnedName(name)
		if got != m {
			t.Errorf("ByPinnedName(%q) returned the wrong map", name)
			continue
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%q and %q resolve to the same map", prev, name)
		}
		seen[got] = name
	}
	for _, name := range bpfmaps.PerIP {
		if l.ByPinnedName(name) == nil {
			t.Errorf("%s is in PerIP but ByPinnedName does not resolve it", name)
		}
	}
}

func TestByPinnedNameRejectsUnknownName(t *testing.T) {
	l := &Loaded{TCPWhitelist: &ebpf.Map{}}
	for _, name := range []string{"", "whitelist", "tcp_global_ratelimit", "nope"} {
		if got := l.ByPinnedName(name); got != nil {
			t.Errorf("ByPinnedName(%q) resolved to a map, want nil", name)
		}
	}
}

func TestCloseIsSafeWithNothingLoaded(t *testing.T) {
	if err := (&Loaded{}).Close(); err != nil {
		t.Errorf("Close on an empty Loaded: %v", err)
	}
}

func TestWrapLoadErrorExplainsIncompatiblePins(t *testing.T) {
	err := wrapLoadError("xdp", "/sys/fs/bpf/fivem", fmt.Errorf("pinned: %w", ebpf.ErrMapIncompatible))
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		t.Error("wrapLoadError dropped the ErrMapIncompatible cause")
	}
	msg := err.Error()
	if !strings.Contains(msg, "rm -rf /sys/fs/bpf/fivem") {
		t.Errorf("the incompatible-pin error does not say how to recover: %s", msg)
	}
}

func TestWrapLoadErrorPassesOtherCausesThrough(t *testing.T) {
	cause := errors.New("permission denied")
	err := wrapLoadError("sockops", "/sys/fs/bpf/fivem", cause)
	if !errors.Is(err, cause) {
		t.Error("wrapLoadError dropped the cause")
	}
	if msg := err.Error(); msg != "load sockops objects: permission denied" {
		t.Errorf("error = %q", msg)
	}
	if strings.Contains(err.Error(), "rm -rf") {
		t.Error("an unrelated load failure suggests deleting the pin directory")
	}
}

func TestPeriodNS(t *testing.T) {
	for _, tc := range []struct {
		unit, rate, want uint64
	}{
		{nsPerSec, 0, 0},
		{nsPerSec, 1, nsPerSec},
		{nsPerSec, 1500, 666_666},
		{nsPerMin, 0, 0},
		{nsPerMin, 6, 10 * nsPerSec},
		{nsPerMin, 60, nsPerSec},
		{nsPerMin, 120_000_000_000, 0},
	} {
		if got := periodNS(tc.unit, tc.rate); got != tc.want {
			t.Errorf("periodNS(%d, %d) = %d, want %d", tc.unit, tc.rate, got, tc.want)
		}
	}
}

func TestPerCPUKeepsADisabledLimitDisabled(t *testing.T) {
	for _, tc := range []struct {
		v    uint64
		ncpu int
		want uint64
	}{
		{0, 8, 0},
		{5000, 8, 625},
		{15000, 8, 1875},
		{3, 8, 1},
		{1, 64, 1},
		{5000, 1, 5000},
		{5000, 0, 5000},
		{5000, -1, 5000},
	} {
		if got := perCPU(tc.v, tc.ncpu); got != tc.want {
			t.Errorf("perCPU(%d, %d) = %d, want %d", tc.v, tc.ncpu, got, tc.want)
		}
	}
}

func TestSetVarRejectsUnknownAndMistypedVariables(t *testing.T) {
	spec := xdpSpec(t)

	if err := setVar(spec, "target_port", uint16(30120)); err != nil {
		t.Errorf("setVar on a known variable: %v", err)
	}
	err := setVar(spec, "no_such_variable", uint64(1))
	if err == nil {
		t.Fatal("setVar accepted a variable the program does not declare")
	}
	if !strings.Contains(err.Error(), "make generate") {
		t.Errorf("the missing-variable error does not point at the fix: %v", err)
	}
	if err := setVar(spec, "target_port", uint64(30120)); err == nil {
		t.Error("setVar accepted a value of the wrong width for target_port")
	}
}

func TestClearMapIgnoresAnAbsentMap(t *testing.T) {
	if err := clearMap(nil); err != nil {
		t.Errorf("clearMap(nil): %v", err)
	}
}

func TestCheckBPFFSRejectsAnOrdinaryDirectory(t *testing.T) {
	if err := checkBPFFS("."); err == nil {
		t.Error("checkBPFFS accepted a directory that is not a bpf filesystem")
	}
}
