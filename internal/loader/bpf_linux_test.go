package loader

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func unprivileged(err error) bool {
	return errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, os.ErrPermission) ||
		errors.Is(err, ebpf.ErrNotSupported)
}

func skipIfUnprivileged(t *testing.T, err error) {
	t.Helper()
	if unprivileged(err) {
		t.Skipf("needs BPF privileges: %v", err)
	}
}

func requireBPF(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("needs BPF privileges: %v", err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("create probe map: %v", err)
	}
	_ = m.Close()
}

func unpinned(spec *ebpf.CollectionSpec) {
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
		if m.Type == ebpf.LRUHash {
			m.MaxEntries = 1024
		}
	}
}

func testPinPath(t *testing.T) string {
	t.Helper()
	if err := checkBPFFS("/sys/fs/bpf"); err != nil {
		t.Skipf("no bpf filesystem: %v", err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	dir := filepath.Join("/sys/fs/bpf", "fivem-test-"+hex.EncodeToString(b[:]))
	if err := os.Mkdir(dir, 0o700); err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("create pin dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func ownCgroup(t *testing.T) string {
	t.Helper()
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		t.Skipf("no cgroup information: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			path := filepath.Join("/sys/fs/cgroup", rest)
			if _, err := os.Stat(filepath.Join(path, "cgroup.procs")); err != nil {
				t.Skipf("cgroup v2 path %s not usable: %v", path, err)
			}
			return path
		}
	}
	t.Skip("not in a cgroup v2 hierarchy")
	return ""
}

func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("list fds: %v", err)
	}
	return len(ents)
}

func bootNow(t *testing.T) uint64 {
	t.Helper()
	now, err := bpfmaps.BootTimeNS()
	if err != nil {
		t.Fatalf("BootTimeNS: %v", err)
	}
	if now < 1000*nsPerSec {
		t.Skip("boot clock too young to place timestamps in the past")
	}
	return now
}
