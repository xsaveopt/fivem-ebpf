package main

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

var _ mapMutator = (*ebpf.Map)(nil)

type fakeMutator struct {
	keys      [][4]byte
	deleted   [][4]byte
	nextErr   error
	deleteErr error
	missing   map[[4]byte]bool
}

func (f *fakeMutator) NextKey(key, nextKeyOut any) error {
	if f.nextErr != nil {
		return f.nextErr
	}
	i := 0
	if key != nil {
		prev := *key.(*[4]byte)
		i = len(f.keys)
		for j, k := range f.keys {
			if k == prev {
				i = j + 1
				break
			}
		}
	}
	if i >= len(f.keys) {
		return ebpf.ErrKeyNotExist
	}
	*nextKeyOut.(*[4]byte) = f.keys[i]
	return nil
}

func (f *fakeMutator) Delete(key any) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	k := *key.(*[4]byte)
	if f.missing[k] {
		return ebpf.ErrKeyNotExist
	}
	f.deleted = append(f.deleted, k)
	return nil
}

func TestCollectKeysWalksTheWholeMap(t *testing.T) {
	want := [][4]byte{{10, 0, 0, 1}, {10, 0, 0, 2}, {10, 0, 0, 3}}
	got, err := collectKeys(&fakeMutator{keys: want})
	if err != nil {
		t.Fatalf("collectKeys: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d keys, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestCollectKeysOnAnEmptyMap(t *testing.T) {
	got, err := collectKeys(&fakeMutator{})
	if err != nil {
		t.Fatalf("collectKeys: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d keys from an empty map", len(got))
	}
}

func TestCollectKeysPropagatesARealError(t *testing.T) {
	_, err := collectKeys(&fakeMutator{nextErr: errors.New("operation not permitted")})
	if err == nil {
		t.Error("collectKeys treated a permission failure as the end of the map")
	}
}

func TestDeleteAllKeysRemovesEveryKey(t *testing.T) {
	m := &fakeMutator{keys: [][4]byte{{10, 0, 0, 1}, {10, 0, 0, 2}}}
	n, err := deleteAllKeys(m)
	if err != nil {
		t.Fatalf("deleteAllKeys: %v", err)
	}
	if n != 2 {
		t.Errorf("cleared %d entries, want 2", n)
	}
	if len(m.deleted) != 2 {
		t.Errorf("deleted %d keys, want 2", len(m.deleted))
	}
}

func TestDeleteAllKeysToleratesAKeyThatExpiredMidSweep(t *testing.T) {
	m := &fakeMutator{
		keys:    [][4]byte{{10, 0, 0, 1}, {10, 0, 0, 2}},
		missing: map[[4]byte]bool{{10, 0, 0, 1}: true},
	}
	n, err := deleteAllKeys(m)
	if err != nil {
		t.Fatalf("deleteAllKeys: %v", err)
	}
	if n != 2 {
		t.Errorf("cleared %d entries, want the 2 that were listed", n)
	}
}

func TestDeleteAllKeysPropagatesARealDeleteError(t *testing.T) {
	m := &fakeMutator{
		keys:      [][4]byte{{10, 0, 0, 1}},
		deleteErr: errors.New("operation not permitted"),
	}
	if _, err := deleteAllKeys(m); err == nil {
		t.Error("deleteAllKeys reported success after a failed delete")
	}
}

func TestDeleteKey(t *testing.T) {
	m := &fakeMutator{keys: [][4]byte{{10, 0, 0, 1}}}
	n, err := deleteKey(m, [4]byte{10, 0, 0, 1})
	if err != nil {
		t.Fatalf("deleteKey: %v", err)
	}
	if n != 1 {
		t.Errorf("deleteKey removed %d entries, want 1", n)
	}
}

func TestDeleteKeyReportsAnAbsentIP(t *testing.T) {
	m := &fakeMutator{missing: map[[4]byte]bool{{10, 0, 0, 9}: true}}
	n, err := deleteKey(m, [4]byte{10, 0, 0, 9})
	if err != nil {
		t.Fatalf("deleteKey: %v", err)
	}
	if n != 0 {
		t.Errorf("deleteKey reported %d removals for an IP that was not there", n)
	}
}

func TestDeleteKeyPropagatesARealError(t *testing.T) {
	m := &fakeMutator{deleteErr: errors.New("operation not permitted")}
	if _, err := deleteKey(m, [4]byte{10, 0, 0, 1}); err == nil {
		t.Error("deleteKey swallowed a permission failure")
	}
}

func TestClearFailsWithoutPinnedMaps(t *testing.T) {
	if _, err := clearWholeMap("/nonexistent-pin-path", "tcp_whitelist"); err == nil {
		t.Error("clearWholeMap succeeded with no pinned maps")
	}
	if _, err := clearMapKey("/nonexistent-pin-path", "tcp_whitelist", [4]byte{10, 0, 0, 1}); err == nil {
		t.Error("clearMapKey succeeded with no pinned maps")
	}
}
