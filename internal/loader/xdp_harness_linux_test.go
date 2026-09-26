package loader

import (
	"encoding/binary"
	"errors"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

const (
	xdpDrop = 1
	xdpPass = 2

	testPort  = 30120
	otherPort = 30121

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10

	ipMF = 0x2000
)

var (
	srcA    = [4]byte{192, 0, 2, 10}
	srcB    = [4]byte{198, 51, 100, 20}
	srcC    = [4]byte{203, 0, 113, 30}
	dstAddr = [4]byte{192, 0, 2, 1}

	enetPayload = []byte{0x00, 0x01, 0x06, 0x00, 0x00, 0x01}
)

type xdpHarness struct {
	t   *testing.T
	obj *fivemXDPObjects
}

func newXDP(t *testing.T, vars map[string]any) *xdpHarness {
	t.Helper()
	requireBPF(t)
	spec := xdpSpec(t)
	unpinned(spec)
	for name, v := range vars {
		if err := setVar(spec, name, v); err != nil {
			t.Fatalf("setVar %s: %v", name, err)
		}
	}
	obj := &fivemXDPObjects{}
	if err := spec.LoadAndAssign(obj, nil); err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("load xdp: %v", err)
	}
	t.Cleanup(func() { _ = obj.Close() })
	return &xdpHarness{t: t, obj: obj}
}

func (h *xdpHarness) run(frame []byte) uint32 {
	h.t.Helper()
	ret, err := h.obj.FivemXdp.Run(&ebpf.RunOptions{Data: frame})
	if err != nil {
		h.t.Fatalf("run xdp: %v", err)
	}
	return ret
}

func (h *xdpHarness) expect(name string, frame []byte, want uint32) {
	h.t.Helper()
	if got := h.run(frame); got != want {
		h.t.Errorf("%s: verdict %s, want %s", name, verdict(got), verdict(want))
	}
}

func verdict(v uint32) string {
	switch v {
	case xdpDrop:
		return "XDP_DROP"
	case xdpPass:
		return "XDP_PASS"
	}
	return "unexpected verdict"
}

func (h *xdpHarness) stats() []uint64 {
	h.t.Helper()
	vals, err := bpfmaps.ReadStats(h.obj.Stats)
	if err != nil {
		h.t.Fatalf("read stats: %v", err)
	}
	return vals
}

func (h *xdpHarness) expectStats(want map[int]uint64) {
	h.t.Helper()
	got := h.stats()
	for slot, v := range got {
		if v != want[slot] {
			h.t.Errorf("stat %s = %d, want %d", bpfmaps.StatLabels[slot], v, want[slot])
		}
	}
}

func (h *xdpHarness) put(m *ebpf.Map, ip [4]byte, v any) {
	h.t.Helper()
	if err := m.Put(&ip, v); err != nil {
		h.t.Fatalf("put: %v", err)
	}
}

func lookup[T any](t *testing.T, m *ebpf.Map, ip [4]byte) (T, bool) {
	t.Helper()
	var v T
	err := m.Lookup(&ip, &v)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return v, false
	}
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	return v, true
}

func seedGlobalBuckets(t *testing.T, h *xdpHarness, b bpfmaps.Ratelimit) {
	t.Helper()
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible cpus: %v", err)
	}
	buckets := make([]bpfmaps.Ratelimit, ncpu)
	for i := range buckets {
		buckets[i] = b
	}
	if err := h.obj.TcpGlobalRatelimit.Put(uint32(0), buckets); err != nil {
		t.Fatalf("seed global buckets: %v", err)
	}
}

func pinToOneCPU(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	var prev unix.CPUSet
	if err := unix.SchedGetaffinity(0, &prev); err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("get affinity: %v", err)
	}
	cpu := -1
	for i := range 1024 {
		if prev.IsSet(i) {
			cpu = i
			break
		}
	}
	var one unix.CPUSet
	one.Set(cpu)
	if err := unix.SchedSetaffinity(0, &one); err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("set affinity: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.SchedSetaffinity(0, &prev)
		runtime.UnlockOSThread()
	})
}

type ipOpts struct {
	tags  []uint16
	src   [4]byte
	frag  uint16
	ihl   uint8
	proto uint8
}

func frame(o ipOpts, l4 []byte) []byte {
	b := []byte{0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02}
	for _, tpid := range o.tags {
		b = binary.BigEndian.AppendUint16(b, tpid)
		b = binary.BigEndian.AppendUint16(b, 100)
	}
	b = binary.BigEndian.AppendUint16(b, 0x0800)
	ihl := o.ihl
	if ihl == 0 {
		ihl = 5
	}
	hdrLen := max(int(ihl)*4, 20)
	ip := make([]byte, hdrLen)
	ip[0] = 0x40 | ihl
	binary.BigEndian.PutUint16(ip[2:], uint16(hdrLen+len(l4)))
	binary.BigEndian.PutUint16(ip[6:], o.frag)
	ip[8] = 64
	ip[9] = o.proto
	copy(ip[12:], o.src[:])
	copy(ip[16:], dstAddr[:])
	for i := 20; i < hdrLen; i++ {
		ip[i] = 1
	}
	b = append(b, ip...)
	return append(b, l4...)
}

func udpSeg(dport uint16, payload []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, 40000)
	b = binary.BigEndian.AppendUint16(b, dport)
	b = binary.BigEndian.AppendUint16(b, uint16(8+len(payload)))
	b = binary.BigEndian.AppendUint16(b, 0)
	return append(b, payload...)
}

func tcpHeader(dport uint16, flags, doff uint8) []byte {
	b := binary.BigEndian.AppendUint16(nil, 40000)
	b = binary.BigEndian.AppendUint16(b, dport)
	b = binary.BigEndian.AppendUint32(b, 1000)
	b = binary.BigEndian.AppendUint32(b, 2000)
	b = append(b, doff<<4, flags)
	b = binary.BigEndian.AppendUint16(b, 65535)
	b = binary.BigEndian.AppendUint16(b, 0)
	return binary.BigEndian.AppendUint16(b, 0)
}

func tcpSeg(dport uint16, flags uint8, payload []byte) []byte {
	return append(tcpHeader(dport, flags, 5), payload...)
}

func udpFrame(src [4]byte, dport uint16, payload []byte) []byte {
	return frame(ipOpts{src: src, proto: 17}, udpSeg(dport, payload))
}

func tcpFrame(src [4]byte, dport uint16, flags uint8, payload string) []byte {
	return frame(ipOpts{src: src, proto: 6}, tcpSeg(dport, flags, []byte(payload)))
}

func synFrame(src [4]byte) []byte {
	return tcpFrame(src, testPort, tcpSYN, "")
}

func dataFrame(src [4]byte, payload string) []byte {
	return tcpFrame(src, testPort, tcpPSH|tcpACK, payload)
}

const (
	postValidUA   = "POST /client HTTP/1.1\r\nHost: game.example\r\nUser-Agent: CitizenFX/1\r\nContent-Length: 0\r\n\r\n"
	postBareUA    = "POST /client HTTP/1.1\r\nHost: game.example\r\nUser-Agent: CitizenFX\r\nContent-Length: 0\r\n\r\n"
	postUnknownUA = "POST /client HTTP/1.1\r\nHost: game.example\r\nUser-Agent: curl/8.0\r\nContent-Length: 0\r\n\r\n"
	getInfo       = "GET /info.json HTTP/1.1\r\nHost: game.example\r\n\r\n"
	getDynamic    = "GET /dynamic.json HTTP/1.1\r\nHost: game.example\r\n\r\n"
	getPlayers    = "GET /players.json HTTP/1.1\r\nHost: game.example\r\n\r\n"
)
