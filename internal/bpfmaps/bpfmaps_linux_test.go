package bpfmaps

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func newTestMap(t *testing.T, spec *ebpf.MapSpec) *ebpf.Map {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("needs BPF privileges: %v", err)
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("needs BPF privileges: %v", err)
		}
		t.Fatalf("create map: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func statsMap(t *testing.T, entries uint32) *ebpf.Map {
	t.Helper()
	return newTestMap(t, &ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: entries,
	})
}

func TestReadStatsSumsEveryCPU(t *testing.T) {
	m := statsMap(t, StatMax)
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible cpus: %v", err)
	}
	want := make([]uint64, StatMax)
	for slot := range StatMax {
		perCPU := make([]uint64, ncpu)
		for cpu := range perCPU {
			perCPU[cpu] = uint64(slot*100 + cpu + 1)
			want[slot] += perCPU[cpu]
		}
		if err := m.Put(uint32(slot), perCPU); err != nil {
			t.Fatalf("put slot %d: %v", slot, err)
		}
	}

	got, err := ReadStats(m)
	if err != nil {
		t.Fatalf("ReadStats: %v", err)
	}
	if len(got) != StatMax {
		t.Fatalf("got %d slots, want %d", len(got), StatMax)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("slot %s = %d, want %d", StatLabels[i], got[i], want[i])
		}
	}
}

func TestReadStatsOnAFreshMapIsAllZero(t *testing.T) {
	got, err := ReadStats(statsMap(t, StatMax))
	if err != nil {
		t.Fatalf("ReadStats: %v", err)
	}
	for i, v := range got {
		if v != 0 {
			t.Errorf("slot %s = %d on a fresh map", StatLabels[i], v)
		}
	}
}

func TestReadStatsNamesTheSlotAMapIsTooShortFor(t *testing.T) {
	_, err := ReadStats(statsMap(t, StatMax-1))
	if err == nil {
		t.Fatal("ReadStats succeeded on a map with too few slots")
	}
	if !strings.Contains(err.Error(), StatLabels[StatMax-1]) {
		t.Errorf("error = %v, want it to name %s", err, StatLabels[StatMax-1])
	}
}

func TestReadStatsWithoutAMapIsAnError(t *testing.T) {
	if _, err := ReadStats(nil); err == nil {
		t.Error("ReadStats(nil) succeeded")
	}
}

func TestCountKeysOnRealMaps(t *testing.T) {
	for _, n := range []int{0, 1, 2, 256} {
		m := newTestMap(t, &ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 4, ValueSize: 8, MaxEntries: 1024})
		for i := range n {
			key := [4]byte{198, 51, 100, byte(i)}
			if err := m.Put(&key, uint64(i)); err != nil {
				t.Fatalf("put: %v", err)
			}
		}
		got, err := CountKeys(m)
		if err != nil {
			t.Errorf("CountKeys with %d entries: %v", n, err)
			continue
		}
		if got != int64(n) {
			t.Errorf("CountKeys = %d, want %d", got, n)
		}
	}
}

func TestCountKeysOnAWideValueMap(t *testing.T) {
	m := newTestMap(t, &ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 4, ValueSize: 120, MaxEntries: 64})
	for i := range 3 {
		key := [4]byte{203, 0, 113, byte(i)}
		if err := m.Put(&key, DropHistory{FirstDropNS: 1}); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	if got, err := CountKeys(m); err != nil || got != 3 {
		t.Errorf("CountKeys = %d (err %v), want 3", got, err)
	}
}

func TestCountKeysWithoutAMapIsMinusOne(t *testing.T) {
	got, err := CountKeys(nil)
	if err != nil || got != -1 {
		t.Errorf("CountKeys(nil) = %d, %v, want -1 and no error", got, err)
	}
}

func TestOpenReadsAPinnedMap(t *testing.T) {
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &st); err != nil || uint32(st.Type) != 0xcafe4a11 {
		t.Skip("no bpf filesystem at /sys/fs/bpf")
	}
	m := newTestMap(t, &ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 4, ValueSize: 8, MaxEntries: 16})
	dir, err := os.MkdirTemp("/sys/fs/bpf", "fivem-test-")
	if err != nil {
		t.Skipf("cannot write to the bpf filesystem: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := m.Pin(dir + "/" + Whitelist); err != nil {
		t.Fatalf("pin: %v", err)
	}
	key := [4]byte{192, 0, 2, 10}
	if err := m.Put(&key, uint64(7)); err != nil {
		t.Fatalf("put: %v", err)
	}

	opened, err := Open(dir, Whitelist)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer opened.Close()
	var v uint64
	if err := NewReader(opened).Lookup(&key, &v); err != nil || v != 7 {
		t.Errorf("lookup through the reopened pin = %d, %v", v, err)
	}

	if _, err := Open(dir, Established); err == nil || !strings.Contains(err.Error(), Established) {
		t.Errorf("Open of a missing pin = %v, want an error naming %s", err, Established)
	}
}
