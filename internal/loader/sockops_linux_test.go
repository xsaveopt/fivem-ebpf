package loader

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

var loopback = [4]byte{127, 0, 0, 1}

type sockopsHarness struct {
	t      *testing.T
	obj    *fivemSockopsObjects
	ln     net.Listener
	target string
}

func newSockops(t *testing.T) *sockopsHarness {
	t.Helper()
	requireBPF(t)
	cgroup := ownCgroup(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	spec, err := loadFivemSockops()
	if err != nil {
		t.Fatalf("load sockops spec: %v", err)
	}
	unpinned(spec)
	if err := setVar(spec, "target_port", port); err != nil {
		t.Fatalf("setVar: %v", err)
	}
	obj := &fivemSockopsObjects{}
	if err := spec.LoadAndAssign(obj, nil); err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("load sockops: %v", err)
	}
	t.Cleanup(func() { _ = obj.Close() })

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: obj.FivemSockops,
	})
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("attach sockops: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &sockopsHarness{t: t, obj: obj, ln: ln, target: ln.Addr().String()}
}

type connPair struct {
	client net.Conn
	server *net.TCPConn
}

func (h *sockopsHarness) connect() connPair {
	h.t.Helper()
	return connectTo(h.t, h.ln, h.target)
}

func connectTo(t *testing.T, ln net.Listener, addr string) connPair {
	t.Helper()
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})
	return connPair{client: c, server: s.(*net.TCPConn)}
}

func (p connPair) closeGracefully(t *testing.T) {
	t.Helper()
	_ = p.client.Close()
	buf := make([]byte, 1)
	_ = p.server.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = p.server.Read(buf)
	_ = p.server.Close()
}

func (p connPair) reset() {
	_ = p.server.SetLinger(0)
	_ = p.server.Close()
	_ = p.client.Close()
}

func (h *sockopsHarness) openCount() (uint64, bool) {
	h.t.Helper()
	return lookup[uint64](h.t, h.obj.TcpOpenCount, loopback)
}

func (h *sockopsHarness) waitOpenCount(want uint64) {
	h.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got, _ := h.openCount()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("open count = %d, want %d", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSockopsCountsOpenConnectionsPerSource(t *testing.T) {
	h := newSockops(t)
	before := bootNow(t)

	conns := []connPair{h.connect(), h.connect(), h.connect()}
	h.waitOpenCount(3)

	est, ok := lookup[uint64](t, h.obj.TcpEstablished, loopback)
	if !ok {
		t.Fatal("an accepted connection did not record the source in tcp_established")
	}
	if est < before {
		t.Errorf("established timestamp %d predates the connections at %d", est, before)
	}
	stats, err := bpfmaps.ReadStats(h.obj.Stats)
	if err != nil {
		t.Fatalf("read stats: %v", err)
	}
	if stats[bpfmaps.StatTCPEstablishedInserts] != 3 {
		t.Errorf("established inserts = %d, want 3", stats[bpfmaps.StatTCPEstablishedInserts])
	}

	conns[0].closeGracefully(t)
	h.waitOpenCount(2)
	conns[1].closeGracefully(t)
	conns[2].closeGracefully(t)
	h.waitOpenCount(0)
}

func TestSockopsCountsAServerSideCloseAsClosed(t *testing.T) {
	h := newSockops(t)
	p := h.connect()
	h.waitOpenCount(1)

	_ = p.server.Close()
	buf := make([]byte, 1)
	_ = p.client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = p.client.Read(buf)
	_ = p.client.Close()
	h.waitOpenCount(0)
}

func TestSockopsCountsAResetAsClosed(t *testing.T) {
	h := newSockops(t)
	p := h.connect()
	h.waitOpenCount(1)
	p.reset()
	h.waitOpenCount(0)
}

func TestSockopsIgnoresOtherPorts(t *testing.T) {
	h := newSockops(t)
	other, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer other.Close()

	connectTo(t, other, other.Addr().String())
	if n, ok := h.openCount(); ok {
		t.Errorf("a connection to another port was counted: %d", n)
	}
	if _, ok := lookup[uint64](t, h.obj.TcpEstablished, loopback); ok {
		t.Error("a connection to another port was recorded as established")
	}
}

func TestSockopsDoesNotDecrementBelowZero(t *testing.T) {
	h := newSockops(t)
	p := h.connect()
	h.waitOpenCount(1)

	if err := h.obj.TcpOpenCount.Put(&loopback, uint64(0)); err != nil {
		t.Fatalf("reset count: %v", err)
	}
	p.reset()
	time.Sleep(100 * time.Millisecond)
	if got, _ := h.openCount(); got != 0 {
		t.Errorf("open count = %d after closing with the counter at zero, want 0", got)
	}
}
