package loader

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func fullOptions(pin string) Options {
	return Options{
		Iface:             "lo",
		Port:              30125,
		TTL:               7 * time.Minute,
		PinPath:           pin,
		UDPRatePerSec:     2000,
		UDPBurst:          6000,
		InitConnectPerMin: 12,
		InitConnectBurst:  4,
		GetInfoPerMin:     30,
		GetInfoBurst:      7,
		TCPGlobalPerSec:   8000,
		TCPGlobalBurst:    16000,
		TCPMaxOpenPerIP:   9,
		HealthWindow:      45 * time.Second,
		HealthThreshold:   77,
		HealthBlacklist:   11 * time.Minute,
		DropHistory:       true,
	}
}

func readVar[T any](t *testing.T, name string, v *ebpf.Variable) T {
	t.Helper()
	var out T
	if err := v.Get(&out); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return out
}

func loadXDPForTest(t *testing.T, opts Options) *fivemXDPObjects {
	t.Helper()
	requireBPF(t)
	obj, err := loadXDP(opts)
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("loadXDP: %v", err)
	}
	t.Cleanup(func() { closeXDPObjs(obj) })
	return obj
}

func TestLoadXDPMapsEveryOptionOntoTheProgram(t *testing.T) {
	requireBPF(t)
	opts := fullOptions(testPinPath(t))
	obj := loadXDPForTest(t, opts)
	ncpu := runtime.NumCPU()

	checks := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"target_port", uint64(readVar[uint16](t, "target_port", obj.TargetPort)), 30125},
		{"whitelist_ttl_ns", readVar[uint64](t, "whitelist_ttl_ns", obj.WhitelistTtlNs), uint64(7 * time.Minute)},
		{"udp_refill_period_ns", readVar[uint64](t, "udp_refill_period_ns", obj.UdpRefillPeriodNs), nsPerSec / 2000},
		{"udp_burst", readVar[uint64](t, "udp_burst", obj.UdpBurst), 6000},
		{"initconnect_period_ns", readVar[uint64](t, "initconnect_period_ns", obj.InitconnectPeriodNs), 5 * nsPerSec},
		{"initconnect_burst", readVar[uint64](t, "initconnect_burst", obj.InitconnectBurst), 4},
		{"getinfo_period_ns", readVar[uint64](t, "getinfo_period_ns", obj.GetinfoPeriodNs), 2 * nsPerSec},
		{"getinfo_burst", readVar[uint64](t, "getinfo_burst", obj.GetinfoBurst), 7},
		{"tcp_global_period_ns", readVar[uint64](t, "tcp_global_period_ns", obj.TcpGlobalPeriodNs), nsPerSec / perCPU(8000, ncpu)},
		{"tcp_global_burst", readVar[uint64](t, "tcp_global_burst", obj.TcpGlobalBurst), perCPU(16000, ncpu)},
		{"tcp_max_open_per_ip", readVar[uint64](t, "tcp_max_open_per_ip", obj.TcpMaxOpenPerIp), 9},
		{"health_window_ns", readVar[uint64](t, "health_window_ns", obj.HealthWindowNs), uint64(45 * time.Second)},
		{"health_threshold", uint64(readVar[uint32](t, "health_threshold", obj.HealthThreshold)), 77},
		{"health_blacklist_ns", readVar[uint64](t, "health_blacklist_ns", obj.HealthBlacklistNs), uint64(11 * time.Minute)},
		{"drop_history_enabled", uint64(readVar[uint8](t, "drop_history_enabled", obj.DropHistoryEnabled)), 1},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestLoadXDPWritesZeroForDisabledLimits(t *testing.T) {
	requireBPF(t)
	opts := fullOptions(testPinPath(t))
	opts.UDPRatePerSec = 0
	opts.InitConnectPerMin = 0
	opts.GetInfoPerMin = 0
	opts.TCPGlobalPerSec = 0
	opts.TCPGlobalBurst = 0
	opts.DropHistory = false
	obj := loadXDPForTest(t, opts)

	for name, v := range map[string]*ebpf.Variable{
		"udp_refill_period_ns":  obj.UdpRefillPeriodNs,
		"initconnect_period_ns": obj.InitconnectPeriodNs,
		"getinfo_period_ns":     obj.GetinfoPeriodNs,
		"tcp_global_period_ns":  obj.TcpGlobalPeriodNs,
		"tcp_global_burst":      obj.TcpGlobalBurst,
	} {
		if got := readVar[uint64](t, name, v); got != 0 {
			t.Errorf("%s = %d, want 0 for a disabled limit", name, got)
		}
	}
	if got := readVar[uint8](t, "drop_history_enabled", obj.DropHistoryEnabled); got != 0 {
		t.Errorf("drop_history_enabled = %d with DropHistory off", got)
	}
}

func TestLoadXDPPinsEveryMapAndReusesThePins(t *testing.T) {
	requireBPF(t)
	pin := testPinPath(t)
	first := loadXDPForTest(t, fullOptions(pin))

	for _, name := range append([]string{"tcp_global_ratelimit"}, append(bpfmaps.PerIP, bpfmaps.Stats)...) {
		if _, err := os.Stat(filepath.Join(pin, name)); err != nil {
			t.Errorf("%s is not pinned: %v", name, err)
		}
	}

	key := [4]byte{192, 0, 2, 10}
	if err := first.TcpWhitelist.Put(&key, uint64(42)); err != nil {
		t.Fatalf("put: %v", err)
	}
	closeXDPObjs(first)

	second := loadXDPForTest(t, fullOptions(pin))
	got, ok := lookup[uint64](t, second.TcpWhitelist, key)
	if !ok || got != 42 {
		t.Errorf("reloaded whitelist entry = %d (present %v), want the pinned 42", got, ok)
	}
}

func pinIncompatibleWhitelist(t *testing.T, pin string) {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "tcp_whitelist",
		Type:       ebpf.LRUHash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 16,
	})
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("create map: %v", err)
	}
	defer m.Close()
	if err := m.Pin(filepath.Join(pin, "tcp_whitelist")); err != nil {
		t.Fatalf("pin: %v", err)
	}
}

func TestLoadXDPExplainsAnIncompatiblePin(t *testing.T) {
	requireBPF(t)
	pin := testPinPath(t)
	pinIncompatibleWhitelist(t, pin)

	obj, err := loadXDP(fullOptions(pin))
	if err == nil {
		closeXDPObjs(obj)
		t.Fatal("loadXDP accepted a pinned map with a different value size")
	}
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		t.Errorf("error does not wrap ErrMapIncompatible: %v", err)
	}
	if !strings.Contains(err.Error(), "rm -rf "+pin) {
		t.Errorf("error does not say how to recover: %v", err)
	}
}

func loadForTest(t *testing.T, opts Options) *Loaded {
	t.Helper()
	l, err := Load(opts)
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("Load: %v", err)
	}
	return l
}

func xdpAttachable(t *testing.T) bool {
	t.Helper()
	spec := xdpSpec(t)
	unpinned(spec)
	obj := &fivemXDPObjects{}
	if err := spec.LoadAndAssign(obj, nil); err != nil {
		t.Fatalf("load xdp: %v", err)
	}
	defer obj.Close()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lo: %v", err)
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: obj.FivemXdp, Interface: lo.Index, Flags: link.XDPGenericMode})
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

func TestLoadAttachesBothProgramsAndCloseReleasesThem(t *testing.T) {
	requireBPF(t)
	opts := fullOptions(testPinPath(t))
	opts.CgroupPath = ownCgroup(t)

	warm := loadForTest(t, opts)
	if err := warm.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	baseline := openFDs(t)

	l := loadForTest(t, opts)
	if l.XDPLink == nil || l.SockopsLink == nil {
		t.Errorf("links xdp=%v sockops=%v, want both attached", l.XDPLink, l.SockopsLink)
	}
	if l.XDPMode != "generic" {
		t.Errorf("XDPMode = %q on lo, want the generic fallback", l.XDPMode)
	}
	for _, name := range bpfmaps.PerIP {
		if l.ByPinnedName(name) == nil {
			t.Errorf("%s is not loaded", name)
		}
	}
	if l.TCPGlobalRatelimit == nil || l.Stats == nil {
		t.Error("the global ratelimit or stats map is not loaded")
	}
	if xdpAttachable(t) {
		t.Error("another XDP program could attach to lo while Load held it")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := openFDs(t); got != baseline {
		t.Errorf("%d fds open after Close, want the %d from before Load", got, baseline)
	}
	if !xdpAttachable(t) {
		t.Error("the XDP program stayed attached to lo after Close")
	}
}

func TestLoadClearsOpenCountsButKeepsOtherState(t *testing.T) {
	requireBPF(t)
	opts := fullOptions(testPinPath(t))
	opts.CgroupPath = ownCgroup(t)
	key := [4]byte{192, 0, 2, 10}

	first := loadForTest(t, opts)
	if err := first.TCPOpenCount.Put(&key, uint64(5)); err != nil {
		t.Fatalf("put open count: %v", err)
	}
	if err := first.TCPWhitelist.Put(&key, uint64(42)); err != nil {
		t.Fatalf("put whitelist: %v", err)
	}
	_ = first.Close()

	second := loadForTest(t, opts)
	defer second.Close()
	if n, err := bpfmaps.CountKeys(second.TCPOpenCount); err != nil || n != 0 {
		t.Errorf("open count holds %d entries after reload (err %v), want 0", n, err)
	}
	if got, ok := lookup[uint64](t, second.TCPWhitelist, key); !ok || got != 42 {
		t.Errorf("whitelist entry = %d (present %v), want it kept across the reload", got, ok)
	}
}

func TestLoadCleansUpWhenTheSockopsAttachFails(t *testing.T) {
	requireBPF(t)
	opts := fullOptions(testPinPath(t))
	opts.CgroupPath = ownCgroup(t)
	warm := loadForTest(t, opts)
	_ = warm.Close()
	baseline := openFDs(t)

	opts.CgroupPath = filepath.Join(t.TempDir(), "no-such-cgroup")
	l, err := Load(opts)
	if err == nil {
		_ = l.Close()
		t.Fatal("Load succeeded with a cgroup path that does not exist")
	}
	if !strings.Contains(err.Error(), "attach sockops") {
		t.Errorf("error = %v", err)
	}
	if got := openFDs(t); got != baseline {
		t.Errorf("%d fds open after the failed Load, want %d", got, baseline)
	}
	if !xdpAttachable(t) {
		t.Error("the XDP program stayed attached after Load failed")
	}
}

func TestLoadCleansUpWhenThePinnedMapsAreIncompatible(t *testing.T) {
	requireBPF(t)
	opts := fullOptions(testPinPath(t))
	opts.CgroupPath = ownCgroup(t)
	pinIncompatibleWhitelist(t, opts.PinPath)
	baseline := openFDs(t)

	l, err := Load(opts)
	if err == nil {
		_ = l.Close()
		t.Fatal("Load succeeded over an incompatible pin")
	}
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		t.Errorf("error = %v", err)
	}
	if got := openFDs(t); got != baseline {
		t.Errorf("%d fds open after the failed Load, want %d", got, baseline)
	}
	if !xdpAttachable(t) {
		t.Error("an XDP program was attached although Load failed")
	}
}

func TestLoadRejectsAnUnknownInterface(t *testing.T) {
	_, err := Load(Options{Iface: "fivemtest0", PinPath: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "interface fivemtest0") {
		t.Errorf("error = %v, want it to name the missing interface", err)
	}
}

func TestLoadRejectsAPinPathOffBPFFS(t *testing.T) {
	_, err := Load(Options{Iface: "lo", PinPath: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "not on a bpf filesystem") {
		t.Errorf("error = %v, want the bpffs hint", err)
	}
}

func TestAttachXDPFallsBackToGenericMode(t *testing.T) {
	h := newXDP(t, nil)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lo: %v", err)
	}
	l, mode, err := attachXDP(h.obj.FivemXdp, lo.Index)
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("attachXDP: %v", err)
	}
	defer l.Close()
	if mode != "generic" {
		t.Errorf("mode = %q on lo, which has no native XDP support", mode)
	}
}

func TestAttachXDPReportsBothModesWhenNeitherWorks(t *testing.T) {
	h := newXDP(t, nil)
	l, mode, err := attachXDP(h.obj.FivemXdp, 1<<30)
	if err == nil {
		_ = l.Close()
		t.Fatalf("attachXDP succeeded on a missing interface in %s mode", mode)
	}
	msg := err.Error()
	if !strings.Contains(msg, "native:") || !strings.Contains(msg, "generic:") {
		t.Errorf("error = %q, want both attach attempts reported", msg)
	}
}

func TestClearMapEmptiesARealMap(t *testing.T) {
	requireBPF(t)
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 4, ValueSize: 8, MaxEntries: 4096})
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("create map: %v", err)
	}
	defer m.Close()

	if err := clearMap(m); err != nil {
		t.Errorf("clearMap on an empty map: %v", err)
	}
	for _, prefix := range [][3]byte{{192, 0, 2}, {198, 51, 100}, {203, 0, 113}} {
		for i := range 256 {
			key := [4]byte{prefix[0], prefix[1], prefix[2], byte(i)}
			if err := m.Put(&key, uint64(i)); err != nil {
				t.Fatalf("put: %v", err)
			}
		}
	}
	if n, err := bpfmaps.CountKeys(m); err != nil || n != 768 {
		t.Fatalf("seeded %d keys (err %v), want 768", n, err)
	}
	if err := clearMap(m); err != nil {
		t.Fatalf("clearMap: %v", err)
	}
	if n, err := bpfmaps.CountKeys(m); err != nil || n != 0 {
		t.Errorf("%d keys left after clearMap (err %v)", n, err)
	}
}
