package loader

import (
	"strings"
	"testing"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

const (
	reasonNoSyn           = 0
	reasonTooManyOpen     = 1
	reasonGlobalRatelimit = 2
	reasonBadUA           = 3
	reasonInitconnect     = 4
	reasonGetinfo         = 5
	reasonMalformed       = 6
	reasonNotWhitelisted  = 7
	reasonExpired         = 8
	reasonUnhealthy       = 9
	reasonEnetMalformed   = 10
	reasonUDPRatelimit    = 11
	reasonFragment        = 12
)

func TestXDPPassesTrafficItDoesNotFilter(t *testing.T) {
	h := newXDP(t, nil)

	arp := frame(ipOpts{src: srcA, proto: 17}, udpSeg(testPort, enetPayload))
	arp[12], arp[13] = 0x08, 0x06
	ipv6 := frame(ipOpts{src: srcA, proto: 17}, udpSeg(testPort, enetPayload))
	ipv6[12], ipv6[13] = 0x86, 0xdd

	h.expect("arp", arp, xdpPass)
	h.expect("ipv6", ipv6, xdpPass)
	h.expect("bare ethernet header", make([]byte, 14), xdpPass)
	h.expect("truncated ipv4 header", frame(ipOpts{src: srcA, proto: 17}, nil)[:30], xdpPass)
	h.expect("udp to another port", udpFrame(srcA, otherPort, enetPayload), xdpPass)
	h.expect("tcp to another port", tcpFrame(srcA, otherPort, tcpACK, ""), xdpPass)
	h.expect("truncated udp header", frame(ipOpts{src: srcA, proto: 17}, udpSeg(testPort, nil)[:6]), xdpPass)
	h.expect("truncated tcp header", frame(ipOpts{src: srcA, proto: 6}, tcpHeader(testPort, tcpACK, 5)[:12]), xdpPass)
	h.expect("icmp", frame(ipOpts{src: srcA, proto: 1}, make([]byte, 16)), xdpPass)
	h.expect("ihl below five", frame(ipOpts{src: srcA, proto: 17, ihl: 4}, udpSeg(testPort, enetPayload)), xdpPass)

	h.expectStats(nil)
	if _, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA); ok {
		t.Error("passed traffic left a drop history entry")
	}
}

func TestXDPHonoursTheConfiguredPort(t *testing.T) {
	h := newXDP(t, map[string]any{"target_port": uint16(otherPort)})
	h.expect("udp to the configured port", udpFrame(srcA, otherPort, enetPayload), xdpDrop)
	h.expect("udp to the default port", udpFrame(srcA, testPort, enetPayload), xdpPass)
}

func TestXDPDropsUDPFromAnUnwhitelistedSource(t *testing.T) {
	h := newXDP(t, nil)
	h.expect("unwhitelisted udp", udpFrame(srcA, testPort, enetPayload), xdpDrop)
	h.expectStats(map[int]uint64{bpfmaps.StatDropUDPNotWhitelisted: 1})
	if _, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA); ok {
		t.Error("a drop from an unknown source created a drop history entry")
	}
}

func TestXDPPassesUDPFromAWhitelistedSourceAndRefreshesIt(t *testing.T) {
	h := newXDP(t, nil)
	now := bootNow(t)
	h.put(h.obj.TcpWhitelist, srcA, now-30*nsPerSec)

	h.expect("whitelisted udp", udpFrame(srcA, testPort, enetPayload), xdpPass)
	h.expectStats(map[int]uint64{bpfmaps.StatPassUDPWhitelisted: 1})

	last, ok := lookup[uint64](t, h.obj.TcpWhitelist, srcA)
	if !ok {
		t.Fatal("the whitelist entry disappeared")
	}
	if last < now {
		t.Errorf("whitelist timestamp %d was not refreshed past %d", last, now)
	}
}

func TestXDPDropsUDPOnceTheWhitelistEntryExpires(t *testing.T) {
	h := newXDP(t, map[string]any{"whitelist_ttl_ns": uint64(60 * nsPerSec)})
	now := bootNow(t)
	h.put(h.obj.TcpWhitelist, srcA, now-50*nsPerSec)
	h.put(h.obj.TcpWhitelist, srcB, now-70*nsPerSec)

	h.expect("inside the ttl", udpFrame(srcA, testPort, enetPayload), xdpPass)
	h.expect("past the ttl", udpFrame(srcB, testPort, enetPayload), xdpDrop)
	h.expectStats(map[int]uint64{
		bpfmaps.StatPassUDPWhitelisted: 1,
		bpfmaps.StatDropUDPExpired:     1,
	})

	hist, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcB)
	if !ok {
		t.Fatal("an expired whitelist drop was not recorded")
	}
	if hist.Counts[reasonExpired] != 1 {
		t.Errorf("counts = %v, want one udp_expired", hist.Counts)
	}
	if last, _ := lookup[uint64](t, h.obj.TcpWhitelist, srcB); last != now-70*nsPerSec {
		t.Error("a dropped packet refreshed an expired whitelist entry")
	}
}

func TestXDPParsesVLANTags(t *testing.T) {
	h := newXDP(t, nil)
	for name, tags := range map[string][]uint16{
		"802.1Q":            {0x8100},
		"802.1ad":           {0x88a8},
		"QinQ":              {0x88a8, 0x8100},
		"double 802.1Q tag": {0x8100, 0x8100},
	} {
		f := frame(ipOpts{tags: tags, src: srcA, proto: 17}, udpSeg(testPort, enetPayload))
		h.expect(name, f, xdpDrop)
	}
	h.expectStats(map[int]uint64{bpfmaps.StatDropUDPNotWhitelisted: 4})

	truncated := frame(ipOpts{tags: []uint16{0x8100}, src: srcA, proto: 17}, nil)[:16]
	h.expect("truncated vlan header", truncated, xdpPass)
}

func TestXDPSkipsIPOptionsToFindTheTransportHeader(t *testing.T) {
	h := newXDP(t, nil)
	h.put(h.obj.TcpWhitelist, srcA, bootNow(t))

	h.expect("options before a valid enet packet", frame(ipOpts{src: srcA, proto: 17, ihl: 7}, udpSeg(testPort, enetPayload)), xdpPass)
	h.expect("options before udp to another port", frame(ipOpts{src: srcB, proto: 17, ihl: 7}, udpSeg(otherPort, enetPayload)), xdpPass)
	h.expect("options before unwhitelisted udp", frame(ipOpts{src: srcB, proto: 17, ihl: 7}, udpSeg(testPort, enetPayload)), xdpDrop)
	h.expectStats(map[int]uint64{
		bpfmaps.StatPassUDPWhitelisted:    1,
		bpfmaps.StatDropUDPNotWhitelisted: 1,
	})
}

func TestXDPDropsFirstFragmentsToThePort(t *testing.T) {
	h := newXDP(t, nil)
	h.put(h.obj.TcpWhitelist, srcA, bootNow(t))
	h.put(h.obj.IpDropHistory, srcA, bpfmaps.DropHistory{})

	h.expect("udp first fragment", frame(ipOpts{src: srcA, proto: 17, frag: ipMF}, udpSeg(testPort, enetPayload)), xdpDrop)
	h.expect("tcp first fragment", frame(ipOpts{src: srcB, proto: 6, frag: ipMF}, tcpSeg(testPort, tcpSYN, nil)), xdpDrop)
	h.expect("udp first fragment to another port", frame(ipOpts{src: srcA, proto: 17, frag: ipMF}, udpSeg(otherPort, enetPayload)), xdpPass)
	h.expect("later fragment", frame(ipOpts{src: srcC, proto: 17, frag: 185}, udpSeg(testPort, enetPayload)), xdpPass)
	h.expect("last fragment", frame(ipOpts{src: srcC, proto: 17, frag: ipMF | 185}, udpSeg(testPort, enetPayload)), xdpPass)
	h.expectStats(map[int]uint64{bpfmaps.StatDropIPFragment: 2})

	if _, ok := lookup[uint64](t, h.obj.TcpSynSeen, srcB); ok {
		t.Error("a fragmented SYN was recorded as seen")
	}
	if hist, _ := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA); hist.Counts[reasonFragment] != 1 {
		t.Errorf("known source counts = %v, want one ip_fragment", hist.Counts)
	}
	if _, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcB); ok {
		t.Error("a fragment from an unknown source created a drop history entry")
	}
}

func TestXDPDropsTCPWithoutAPriorHandshake(t *testing.T) {
	h := newXDP(t, nil)
	now := bootNow(t)

	h.expect("ack from nowhere", tcpFrame(srcA, testPort, tcpACK, ""), xdpDrop)
	h.expect("rst from nowhere", tcpFrame(srcA, testPort, tcpRST, ""), xdpDrop)
	h.expect("fin from nowhere", tcpFrame(srcA, testPort, tcpFIN|tcpACK, ""), xdpDrop)
	h.expectStats(map[int]uint64{bpfmaps.StatDropTCPNoSyn: 3})

	h.put(h.obj.TcpSynSeen, srcA, now)
	h.put(h.obj.TcpEstablished, srcB, now)
	h.put(h.obj.TcpWhitelist, srcC, now)
	h.expect("ack after a syn", tcpFrame(srcA, testPort, tcpACK, ""), xdpPass)
	h.expect("ack on an established source", tcpFrame(srcB, testPort, tcpACK, ""), xdpPass)
	h.expect("ack on a whitelisted source", tcpFrame(srcC, testPort, tcpACK, ""), xdpPass)
}

func TestXDPRecordsASYNAndPassesIt(t *testing.T) {
	h := newXDP(t, nil)
	before := bootNow(t)
	h.expect("syn", synFrame(srcA), xdpPass)
	seen, ok := lookup[uint64](t, h.obj.TcpSynSeen, srcA)
	if !ok {
		t.Fatal("the SYN was not recorded in tcp_syn_seen")
	}
	if seen < before {
		t.Errorf("syn_seen = %d, earlier than the send at %d", seen, before)
	}
	h.expect("follow-up ack", tcpFrame(srcA, testPort, tcpACK, ""), xdpPass)
	h.expectStats(map[int]uint64{bpfmaps.StatPassTCP: 2})
}

func TestXDPDropsMalformedTCPHeaders(t *testing.T) {
	h := newXDP(t, nil)
	h.put(h.obj.TcpWhitelist, srcA, bootNow(t))

	short := frame(ipOpts{src: srcA, proto: 6}, tcpHeader(testPort, tcpACK, 4))
	past := frame(ipOpts{src: srcA, proto: 6}, tcpHeader(testPort, tcpACK, 15))
	h.expect("data offset below five", short, xdpDrop)
	h.expect("data offset past the packet", past, xdpDrop)
	h.expectStats(map[int]uint64{bpfmaps.StatDropMalformed: 2})

	hist, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA)
	if ok && hist.Counts[reasonMalformed] != 0 {
		t.Errorf("malformed drops were recorded for a source with no history: %v", hist.Counts)
	}
}

func TestXDPCapsOpenConnectionsPerIP(t *testing.T) {
	h := newXDP(t, map[string]any{"tcp_max_open_per_ip": uint64(2)})
	h.put(h.obj.TcpOpenCount, srcA, uint64(2))
	h.put(h.obj.TcpOpenCount, srcB, uint64(1))

	h.expect("syn at the cap", synFrame(srcA), xdpDrop)
	h.expect("syn under the cap", synFrame(srcB), xdpPass)
	h.expect("syn with no open sockets", synFrame(srcC), xdpPass)
	h.expect("data at the cap", tcpFrame(srcB, testPort, tcpACK, ""), xdpPass)
	h.expectStats(map[int]uint64{
		bpfmaps.StatDropTCPTooManyOpen: 1,
		bpfmaps.StatPassTCP:            3,
	})

	hist, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA)
	if !ok || hist.Counts[reasonTooManyOpen] != 1 {
		t.Errorf("drop history = %+v (present %v), want one tcp_too_many_open", hist, ok)
	}
	if _, ok := lookup[uint64](t, h.obj.TcpSynSeen, srcA); ok {
		t.Error("a SYN dropped at the cap was still recorded as seen")
	}
}

func TestXDPOpenConnectionCapIsOffAtZero(t *testing.T) {
	h := newXDP(t, map[string]any{"tcp_max_open_per_ip": uint64(0)})
	h.put(h.obj.TcpOpenCount, srcA, uint64(1000))
	h.expect("syn with many open sockets", synFrame(srcA), xdpPass)
}

func TestXDPGlobalSYNBreaker(t *testing.T) {
	pinToOneCPU(t)
	h := newXDP(t, map[string]any{
		"tcp_global_period_ns": uint64(3600 * nsPerSec),
		"tcp_global_burst":     uint64(2),
	})
	now := bootNow(t)
	h.put(h.obj.TcpWhitelist, srcC, now)
	seedGlobalBuckets(t, h, bpfmaps.Ratelimit{Tokens: 2, LastRefillNS: now})

	h.expect("first syn", synFrame(srcA), xdpPass)
	h.expect("second syn", synFrame(srcB), xdpPass)
	h.expect("third syn", synFrame(srcA), xdpDrop)
	h.expect("syn from a whitelisted source", synFrame(srcC), xdpDrop)
	h.expect("data is not rate limited", tcpFrame(srcA, testPort, tcpACK, ""), xdpPass)
	h.expectStats(map[int]uint64{
		bpfmaps.StatDropTCPGlobalRatelimit: 2,
		bpfmaps.StatPassTCP:                3,
	})

	if _, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA); ok {
		t.Error("a breaker drop for a source that was never whitelisted created a drop history entry")
	}
	hist, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcC)
	if !ok || hist.Counts[reasonGlobalRatelimit] != 1 {
		t.Errorf("whitelisted source history = %+v (present %v), want one tcp_global_ratelimit", hist, ok)
	}
}

func TestXDPGlobalSYNBreakerRefills(t *testing.T) {
	pinToOneCPU(t)
	h := newXDP(t, map[string]any{
		"tcp_global_period_ns": uint64(10 * nsPerSec),
		"tcp_global_burst":     uint64(5),
	})
	now := bootNow(t)
	seedGlobalBuckets(t, h, bpfmaps.Ratelimit{Tokens: 0, LastRefillNS: now - 25*nsPerSec})

	h.expect("syn after two refills", synFrame(srcA), xdpPass)
	h.expect("syn on the second refilled token", synFrame(srcB), xdpPass)
	h.expect("syn with the bucket empty again", synFrame(srcC), xdpDrop)
}

func TestXDPGlobalSYNBreakerIsOffAtZero(t *testing.T) {
	for name, vars := range map[string]map[string]any{
		"zero burst":  {"tcp_global_period_ns": uint64(3600 * nsPerSec), "tcp_global_burst": uint64(0)},
		"zero period": {"tcp_global_period_ns": uint64(0), "tcp_global_burst": uint64(1)},
	} {
		t.Run(name, func(t *testing.T) {
			h := newXDP(t, vars)
			for range 20 {
				h.expect("syn", synFrame(srcA), xdpPass)
			}
		})
	}
}

func TestXDPPromotesAValidClientOnAnEstablishedConnection(t *testing.T) {
	h := newXDP(t, nil)
	now := bootNow(t)
	h.put(h.obj.TcpEstablished, srcA, now)

	h.expect("POST /client", dataFrame(srcA, postValidUA), xdpPass)
	h.expectStats(map[int]uint64{
		bpfmaps.StatTCPPostClientSeen: 1,
		bpfmaps.StatTCPL7Promoted:     1,
		bpfmaps.StatPassTCP:           1,
	})
	wl, ok := lookup[uint64](t, h.obj.TcpWhitelist, srcA)
	if !ok {
		t.Fatal("a valid POST /client on an established connection was not whitelisted")
	}
	if wl < now {
		t.Errorf("whitelist timestamp %d predates the request at %d", wl, now)
	}
	h.expect("udp after promotion", udpFrame(srcA, testPort, enetPayload), xdpPass)
}

func TestXDPDoesNotPromoteWithoutAnEstablishedConnection(t *testing.T) {
	h := newXDP(t, nil)
	h.put(h.obj.TcpSynSeen, srcA, bootNow(t))

	h.expect("POST /client", dataFrame(srcA, postValidUA), xdpPass)
	h.expectStats(map[int]uint64{
		bpfmaps.StatTCPPostClientSeen: 1,
		bpfmaps.StatTCPL7MatchNoEst:   1,
		bpfmaps.StatPassTCP:           1,
	})
	if _, ok := lookup[uint64](t, h.obj.TcpWhitelist, srcA); ok {
		t.Error("a POST /client without an established socket was whitelisted")
	}
}

func TestXDPDropsTheBareCitizenFXUserAgent(t *testing.T) {
	h := newXDP(t, nil)
	now := bootNow(t)
	h.put(h.obj.TcpEstablished, srcA, now)
	h.put(h.obj.TcpEstablished, srcB, now)

	h.expect("POST with a bare user agent", dataFrame(srcA, postBareUA), xdpDrop)
	h.expect("GET with a bare user agent", dataFrame(srcB, "GET /info.json HTTP/1.1\r\nUser-Agent: CitizenFX\r\n\r\n"), xdpDrop)
	h.expectStats(map[int]uint64{bpfmaps.StatDropTCPBadUserAgent: 2})

	hist, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA)
	if !ok || hist.Counts[reasonBadUA] != 1 {
		t.Errorf("drop history = %+v (present %v), want one tcp_bad_user_agent", hist, ok)
	}
	if _, ok := lookup[uint64](t, h.obj.TcpWhitelist, srcA); ok {
		t.Error("a bot user agent was whitelisted")
	}
	if _, ok := lookup[bpfmaps.Ratelimit](t, h.obj.InitconnectRatelimit, srcA); ok {
		t.Error("a bot request spent an initConnect token")
	}
}

func TestXDPCountsAPOSTWithAnUnknownUserAgent(t *testing.T) {
	h := newXDP(t, nil)
	h.put(h.obj.TcpEstablished, srcA, bootNow(t))

	h.expect("POST with another user agent", dataFrame(srcA, postUnknownUA), xdpPass)
	h.expect("POST with no headers", dataFrame(srcA, "POST /client HTTP/1.1\r\n\r\n"), xdpPass)
	h.expectStats(map[int]uint64{
		bpfmaps.StatTCPPostClientSeen: 2,
		bpfmaps.StatTCPPostUAUnknown:  2,
		bpfmaps.StatPassTCP:           2,
	})
	if _, ok := lookup[uint64](t, h.obj.TcpWhitelist, srcA); ok {
		t.Error("a POST without the CitizenFX user agent was whitelisted")
	}
}

func TestXDPScansTheFirst512BytesForTheUserAgent(t *testing.T) {
	const needle = "CitizenFX/1\r\n"
	build := func(at int) string {
		head := "POST /client HTTP/1.1\r\nX-Pad: "
		pad := at - len(head)
		return head + strings.Repeat("a", pad) + needle + strings.Repeat("b", 64) + "\r\n\r\n"
	}
	for _, tc := range []struct {
		at       int
		promoted bool
	}{
		{100, true},
		{502, true},
		{503, false},
		{800, false},
	} {
		h := newXDP(t, nil)
		h.put(h.obj.TcpEstablished, srcA, bootNow(t))
		payload := build(tc.at)
		if got := strings.Index(payload, "CitizenFX"); got != tc.at {
			t.Fatalf("needle at %d, want %d", got, tc.at)
		}
		h.expect("POST /client", dataFrame(srcA, payload), xdpPass)
		_, ok := lookup[uint64](t, h.obj.TcpWhitelist, srcA)
		if ok != tc.promoted {
			t.Errorf("user agent at byte %d: promoted %v, want %v", tc.at, ok, tc.promoted)
		}
	}
}

func TestXDPUserAgentNeedsRoomForTheVersionSlash(t *testing.T) {
	h := newXDP(t, nil)
	h.put(h.obj.TcpEstablished, srcA, bootNow(t))
	h.put(h.obj.TcpEstablished, srcB, bootNow(t))

	h.expect("needle cut off at the end", dataFrame(srcA, "POST /client HTTP/1.1\r\nUser-Agent: CitizenFX"), xdpPass)
	h.expect("needle with another suffix", dataFrame(srcB, "POST /client HTTP/1.1\r\nUser-Agent: CitizenFXv2\r\n\r\n"), xdpPass)
	h.expectStats(map[int]uint64{
		bpfmaps.StatTCPPostClientSeen: 2,
		bpfmaps.StatTCPPostUAUnknown:  2,
		bpfmaps.StatPassTCP:           2,
	})
}

func TestXDPMatchesOnlyTheExactRequestLines(t *testing.T) {
	h := newXDP(t, nil)
	h.put(h.obj.TcpEstablished, srcA, bootNow(t))
	for _, payload := range []string{
		"post /client HTTP/1.1\r\n\r\n",
		"POST /clien",
		"POST /files HTTP/1.1\r\n\r\n",
		"PUT /client HTTP/1.1\r\n\r\n",
		"GET /info.jso",
		"GET /info.html HTTP/1.1\r\n\r\n",
		"GET /dynamic.jsn HTTP/1.1\r\n\r\n",
		"GET /players.xml HTTP/1.1\r\n\r\n",
		"GET / HTTP/1.1\r\n\r\n",
		"HEAD /info.json HTTP/1.1\r\n\r\n",
	} {
		h.expect(payload, dataFrame(srcA, payload), xdpPass)
	}
	h.expectStats(map[int]uint64{bpfmaps.StatPassTCP: 10})
}

func TestXDPRatelimitsPOSTClientPerIP(t *testing.T) {
	h := newXDP(t, map[string]any{
		"initconnect_period_ns": uint64(3600 * nsPerSec),
		"initconnect_burst":     uint64(2),
	})
	now := bootNow(t)
	h.put(h.obj.TcpEstablished, srcA, now)
	h.put(h.obj.TcpEstablished, srcB, now)

	h.expect("first POST", dataFrame(srcA, postValidUA), xdpPass)
	h.expect("second POST", dataFrame(srcA, postValidUA), xdpPass)
	h.expect("third POST", dataFrame(srcA, postValidUA), xdpDrop)
	h.expect("POST from another source", dataFrame(srcB, postValidUA), xdpPass)
	h.expect("GET is a separate bucket", dataFrame(srcA, getInfo), xdpPass)

	stats := h.stats()
	if stats[bpfmaps.StatDropTCPInitconnectRatelimit] != 1 {
		t.Errorf("initconnect drops = %d, want 1", stats[bpfmaps.StatDropTCPInitconnectRatelimit])
	}
	if stats[bpfmaps.StatTCPPostClientSeen] != 4 {
		t.Errorf("post_client_seen = %d, want 4", stats[bpfmaps.StatTCPPostClientSeen])
	}
	hist, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA)
	if !ok || hist.Counts[reasonInitconnect] != 1 {
		t.Errorf("drop history = %+v (present %v), want one tcp_initconnect_ratelimit", hist, ok)
	}
	b, _ := lookup[bpfmaps.Ratelimit](t, h.obj.InitconnectRatelimit, srcA)
	if b.Tokens != 0 {
		t.Errorf("bucket tokens = %d after spending the burst, want 0", b.Tokens)
	}
}

func TestXDPTokenBucketRefillsByWholePeriods(t *testing.T) {
	h := newXDP(t, map[string]any{
		"initconnect_period_ns": uint64(10 * nsPerSec),
		"initconnect_burst":     uint64(5),
	})
	now := bootNow(t)
	h.put(h.obj.TcpEstablished, srcA, now)
	h.put(h.obj.TcpEstablished, srcB, now)
	h.put(h.obj.TcpEstablished, srcC, now)
	lastA := now - 25*nsPerSec
	h.put(h.obj.InitconnectRatelimit, srcA, bpfmaps.Ratelimit{Tokens: 0, LastRefillNS: lastA})
	h.put(h.obj.InitconnectRatelimit, srcB, bpfmaps.Ratelimit{Tokens: 0, LastRefillNS: now - 500*nsPerSec})
	h.put(h.obj.InitconnectRatelimit, srcC, bpfmaps.Ratelimit{Tokens: 0, LastRefillNS: now - 5*nsPerSec})

	h.expect("two periods elapsed", dataFrame(srcA, postValidUA), xdpPass)
	a, _ := lookup[bpfmaps.Ratelimit](t, h.obj.InitconnectRatelimit, srcA)
	if a.Tokens != 1 {
		t.Errorf("tokens = %d after refilling two and spending one, want 1", a.Tokens)
	}
	if a.LastRefillNS != lastA+20*nsPerSec {
		t.Errorf("last refill moved to %d, want exactly two periods on to %d", a.LastRefillNS, lastA+20*nsPerSec)
	}

	h.expect("long idle", dataFrame(srcB, postValidUA), xdpPass)
	b, _ := lookup[bpfmaps.Ratelimit](t, h.obj.InitconnectRatelimit, srcB)
	if b.Tokens != 4 {
		t.Errorf("tokens = %d after a long idle, want the burst of 5 less one", b.Tokens)
	}

	h.expect("under one period", dataFrame(srcC, postValidUA), xdpDrop)
}

func TestXDPRatelimitIsOffAtZero(t *testing.T) {
	for name, vars := range map[string]map[string]any{
		"zero burst":  {"initconnect_period_ns": uint64(3600 * nsPerSec), "initconnect_burst": uint64(0)},
		"zero period": {"initconnect_period_ns": uint64(0), "initconnect_burst": uint64(1)},
	} {
		t.Run(name, func(t *testing.T) {
			h := newXDP(t, vars)
			h.put(h.obj.TcpEstablished, srcA, bootNow(t))
			for range 10 {
				h.expect("POST", dataFrame(srcA, postValidUA), xdpPass)
			}
			if _, ok := lookup[bpfmaps.Ratelimit](t, h.obj.InitconnectRatelimit, srcA); ok {
				t.Error("a disabled limit still created a bucket")
			}
		})
	}
}

func TestXDPRatelimitsTheInfoEndpointsTogether(t *testing.T) {
	h := newXDP(t, map[string]any{
		"getinfo_period_ns": uint64(3600 * nsPerSec),
		"getinfo_burst":     uint64(3),
	})
	h.put(h.obj.TcpSynSeen, srcA, bootNow(t))

	h.expect("info.json", dataFrame(srcA, getInfo), xdpPass)
	h.expect("dynamic.json", dataFrame(srcA, getDynamic), xdpPass)
	h.expect("players.json", dataFrame(srcA, getPlayers), xdpPass)
	h.expect("fourth request", dataFrame(srcA, getInfo), xdpDrop)
	h.expect("unrelated path", dataFrame(srcA, "GET /files/x HTTP/1.1\r\n\r\n"), xdpPass)
	h.expectStats(map[int]uint64{
		bpfmaps.StatTCPGetinfoSeen:          4,
		bpfmaps.StatDropTCPGetinfoRatelimit: 1,
		bpfmaps.StatPassTCP:                 4,
	})
	hist, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA)
	if !ok || hist.Counts[reasonGetinfo] != 1 {
		t.Errorf("drop history = %+v (present %v), want one tcp_getinfo_ratelimit", hist, ok)
	}
}

func TestXDPRefreshesTheWhitelistOnPassingTCP(t *testing.T) {
	h := newXDP(t, nil)
	now := bootNow(t)
	h.put(h.obj.TcpWhitelist, srcA, now-100*nsPerSec)
	h.expect("ack", tcpFrame(srcA, testPort, tcpACK, ""), xdpPass)
	if wl, _ := lookup[uint64](t, h.obj.TcpWhitelist, srcA); wl < now {
		t.Errorf("whitelist timestamp %d was not refreshed by passing TCP", wl)
	}
}

func TestXDPValidatesTheENetHeader(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		want    uint32
	}{
		{"send reliable", []byte{0x00, 0x01, 0x06, 0x00, 0x00, 0x01}, xdpPass},
		{"connect with ack flag", []byte{0x0f, 0xff, 0x82, 0xff, 0x00, 0x01}, xdpPass},
		{"unsequenced", []byte{0x00, 0x01, 0x49, 0x00, 0x00, 0x01}, xdpPass},
		{"with sent time", []byte{0x80, 0x01, 0x12, 0x34, 0x87, 0x00, 0x00, 0x01}, xdpPass},
		{"highest command", []byte{0x00, 0x01, 0x0c, 0x00, 0x00, 0x00}, xdpPass},
		{"compressed", []byte{0x40, 0x01, 0xde, 0xad}, xdpPass},
		{"out of band", []byte{0xff, 0xff, 0xff, 0xff, 'g', 'e', 't', 'i', 'n', 'f', 'o'}, xdpPass},
		{"command zero", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01}, xdpDrop},
		{"command thirteen", []byte{0x00, 0x01, 0x0d, 0x00, 0x00, 0x01}, xdpDrop},
		{"unknown command flag", []byte{0x00, 0x01, 0x26, 0x00, 0x00, 0x01}, xdpDrop},
		{"sent time pushes the command out", []byte{0x80, 0x01, 0x12, 0x34, 0x06, 0x00, 0x00}, xdpDrop},
		{"command truncated", []byte{0x00, 0x01, 0x06, 0x00, 0x00}, xdpDrop},
		{"header only", []byte{0x00, 0x01}, xdpDrop},
		{"one byte", []byte{0x00}, xdpDrop},
		{"empty", nil, xdpDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newXDP(t, nil)
			h.put(h.obj.TcpWhitelist, srcA, bootNow(t))
			h.expect(tc.name, udpFrame(srcA, testPort, tc.payload), tc.want)

			health, ok := lookup[bpfmaps.UDPHealth](t, h.obj.UdpHealth, srcA)
			if tc.want == xdpPass {
				h.expectStats(map[int]uint64{bpfmaps.StatPassUDPWhitelisted: 1})
				if ok {
					t.Errorf("a valid packet was counted as an anomaly: %+v", health)
				}
				return
			}
			h.expectStats(map[int]uint64{bpfmaps.StatDropUDPEnetMalformed: 1})
			if !ok || health.Anomalies != 1 {
				t.Errorf("health = %+v (present %v), want one anomaly", health, ok)
			}
			hist, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA)
			if !ok || hist.Counts[reasonEnetMalformed] != 1 {
				t.Errorf("drop history = %+v (present %v), want one udp_enet_malformed", hist, ok)
			}
		})
	}
}

func healthVars(threshold uint32) map[string]any {
	return map[string]any{
		"health_window_ns":    uint64(60 * nsPerSec),
		"health_threshold":    threshold,
		"health_blacklist_ns": uint64(300 * nsPerSec),
	}
}

var badENet = []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00}

func TestXDPBlacklistsAfterTheHealthThreshold(t *testing.T) {
	h := newXDP(t, healthVars(3))
	now := bootNow(t)
	h.put(h.obj.TcpWhitelist, srcA, now)

	for range 2 {
		h.expect("malformed", udpFrame(srcA, testPort, badENet), xdpDrop)
	}
	h.expect("valid under the threshold", udpFrame(srcA, testPort, enetPayload), xdpPass)
	h.expect("third malformed", udpFrame(srcA, testPort, badENet), xdpDrop)

	health, _ := lookup[bpfmaps.UDPHealth](t, h.obj.UdpHealth, srcA)
	if health.Anomalies != 3 {
		t.Errorf("anomalies = %d, want 3", health.Anomalies)
	}
	if health.BlacklistUntilNS < now+300*nsPerSec {
		t.Errorf("blacklist until %d, want at least %d", health.BlacklistUntilNS, now+300*nsPerSec)
	}

	h.expect("valid while blacklisted", udpFrame(srcA, testPort, enetPayload), xdpDrop)
	h.expect("malformed while blacklisted", udpFrame(srcA, testPort, badENet), xdpDrop)
	h.expectStats(map[int]uint64{
		bpfmaps.StatDropUDPEnetMalformed: 3,
		bpfmaps.StatPassUDPWhitelisted:   1,
		bpfmaps.StatDropUDPUnhealthy:     2,
	})
	if again, _ := lookup[bpfmaps.UDPHealth](t, h.obj.UdpHealth, srcA); again.Anomalies != 3 {
		t.Errorf("anomalies = %d, a blacklisted source should not keep accruing", again.Anomalies)
	}
	hist, _ := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA)
	if hist.Counts[reasonUnhealthy] != 2 || hist.Counts[reasonEnetMalformed] != 3 {
		t.Errorf("drop history counts = %v", hist.Counts)
	}
}

func TestXDPBlacklistsOnTheFirstAnomalyWhenTheThresholdIsOne(t *testing.T) {
	h := newXDP(t, healthVars(1))
	h.put(h.obj.TcpWhitelist, srcA, bootNow(t))

	h.expect("malformed", udpFrame(srcA, testPort, badENet), xdpDrop)
	h.expect("valid after reaching the threshold", udpFrame(srcA, testPort, enetPayload), xdpDrop)

	health, _ := lookup[bpfmaps.UDPHealth](t, h.obj.UdpHealth, srcA)
	if health.BlacklistUntilNS == 0 {
		t.Errorf("one anomaly with a threshold of one did not blacklist: %+v", health)
	}
}

func TestXDPHealthWindowResetsTheCount(t *testing.T) {
	h := newXDP(t, healthVars(3))
	now := bootNow(t)
	h.put(h.obj.TcpWhitelist, srcA, now)
	h.put(h.obj.UdpHealth, srcA, bpfmaps.UDPHealth{Anomalies: 2, WindowStartNS: now - 120*nsPerSec})

	h.expect("malformed after the window", udpFrame(srcA, testPort, badENet), xdpDrop)
	health, _ := lookup[bpfmaps.UDPHealth](t, h.obj.UdpHealth, srcA)
	if health.Anomalies != 1 {
		t.Errorf("anomalies = %d, want the window to restart at 1", health.Anomalies)
	}
	if health.WindowStartNS < now {
		t.Errorf("window start %d was not moved to now", health.WindowStartNS)
	}
	if health.BlacklistUntilNS != 0 {
		t.Error("a reset window still blacklisted the source")
	}
	h.expect("valid after the reset", udpFrame(srcA, testPort, enetPayload), xdpPass)
}

func TestXDPLetsASourceBackInOnceTheBlacklistExpires(t *testing.T) {
	h := newXDP(t, healthVars(3))
	now := bootNow(t)
	h.put(h.obj.TcpWhitelist, srcA, now)
	h.put(h.obj.UdpHealth, srcA, bpfmaps.UDPHealth{
		Anomalies: 3, WindowStartNS: now - 400*nsPerSec, BlacklistUntilNS: now - nsPerSec,
	})
	h.expect("valid after the blacklist", udpFrame(srcA, testPort, enetPayload), xdpPass)
}

func TestXDPRatelimitsUDPPerIP(t *testing.T) {
	h := newXDP(t, map[string]any{
		"udp_refill_period_ns": uint64(3600 * nsPerSec),
		"udp_burst":            uint64(2),
	})
	now := bootNow(t)
	h.put(h.obj.TcpWhitelist, srcA, now)
	h.put(h.obj.TcpWhitelist, srcB, now)

	h.expect("first", udpFrame(srcA, testPort, enetPayload), xdpPass)
	h.expect("second", udpFrame(srcA, testPort, enetPayload), xdpPass)
	h.expect("third", udpFrame(srcA, testPort, enetPayload), xdpDrop)
	h.expect("another source", udpFrame(srcB, testPort, enetPayload), xdpPass)
	h.expectStats(map[int]uint64{
		bpfmaps.StatPassUDPWhitelisted: 3,
		bpfmaps.StatDropUDPRatelimit:   1,
	})
	hist, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA)
	if !ok || hist.Counts[reasonUDPRatelimit] != 1 {
		t.Errorf("drop history = %+v (present %v), want one udp_ratelimit", hist, ok)
	}
}

func TestXDPDropHistoryCanBeTurnedOff(t *testing.T) {
	h := newXDP(t, map[string]any{
		"drop_history_enabled": uint8(0),
		"tcp_max_open_per_ip":  uint64(1),
	})
	h.put(h.obj.TcpOpenCount, srcA, uint64(1))
	h.expect("syn at the cap", synFrame(srcA), xdpDrop)
	h.expectStats(map[int]uint64{bpfmaps.StatDropTCPTooManyOpen: 1})
	if _, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA); ok {
		t.Error("drop history was recorded with drop_history_enabled = 0")
	}
}

func TestXDPDropHistoryAccumulatesOnAKnownSource(t *testing.T) {
	h := newXDP(t, nil)
	now := bootNow(t)
	first := now - 50*nsPerSec
	var seed bpfmaps.DropHistory
	seed.FirstDropNS = first
	seed.LastDropNS = first
	seed.Counts[reasonExpired] = 4
	h.put(h.obj.IpDropHistory, srcA, seed)

	h.expect("ack from nowhere", tcpFrame(srcA, testPort, tcpACK, ""), xdpDrop)
	h.expect("unwhitelisted udp", udpFrame(srcA, testPort, enetPayload), xdpDrop)

	hist, _ := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA)
	if hist.FirstDropNS != first {
		t.Errorf("first drop moved from %d to %d", first, hist.FirstDropNS)
	}
	if hist.LastDropNS < now {
		t.Errorf("last drop %d was not updated", hist.LastDropNS)
	}
	want := seed.Counts
	want[reasonNoSyn] = 1
	want[reasonNotWhitelisted] = 1
	if hist.Counts != want {
		t.Errorf("counts = %v, want %v", hist.Counts, want)
	}
}

func TestXDPDropHistoryStartsWithOneDrop(t *testing.T) {
	h := newXDP(t, map[string]any{"tcp_max_open_per_ip": uint64(1)})
	before := bootNow(t)
	h.put(h.obj.TcpOpenCount, srcA, uint64(1))
	h.expect("syn at the cap", synFrame(srcA), xdpDrop)

	hist, ok := lookup[bpfmaps.DropHistory](t, h.obj.IpDropHistory, srcA)
	if !ok {
		t.Fatal("no drop history entry")
	}
	if hist.FirstDropNS < before || hist.LastDropNS != hist.FirstDropNS {
		t.Errorf("timestamps first=%d last=%d, want both set to the drop time", hist.FirstDropNS, hist.LastDropNS)
	}
	var want [bpfmaps.NumDropReasons]uint64
	want[reasonTooManyOpen] = 1
	if hist.Counts != want {
		t.Errorf("counts = %v, want %v", hist.Counts, want)
	}
}
