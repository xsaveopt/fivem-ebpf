#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "shared/maps.h"

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

char LICENSE[] SEC("license") = "GPL";

volatile const __u16 target_port              = 30120;
volatile const __u64 whitelist_ttl_ns         = 600ULL * 1000000000ULL;
volatile const __u64 udp_refill_period_ns     = 666666ULL;        /* ~1500 pkt/s */
volatile const __u64 udp_burst                = 4500;
volatile const __u64 initconnect_period_ns    = 10000000000ULL;   /* 6/min */
volatile const __u64 initconnect_burst        = 3;
volatile const __u64 getinfo_period_ns        = 10000000000ULL;   /* 6/min — /info.json etc. */
volatile const __u64 getinfo_burst            = 5;
/* Per-CPU circuit breaker on all TCP to target_port. The userspace daemon
 * divides the user-facing "global" rate by num_cpus before setting these
 * vars, so the per-CPU bucket sums to the configured global cap. burst=0
 * disables the circuit breaker entirely. */
volatile const __u64 tcp_global_period_ns     = 0;
volatile const __u64 tcp_global_burst         = 0;
/* Reject new SYNs from a source IP that already holds this many open TCP
 * sockets to the target port. 0 disables. Catches connection-hold attacks
 * where bots complete 3WHS but never speak L7 (none of our payload matchers
 * fire on idle held connections). */
volatile const __u64 tcp_max_open_per_ip      = 0;
volatile const __u64 health_window_ns         = 10ULL * 1000000000ULL;   /* 10s */
volatile const __u32 health_threshold         = 20;                      /* anomalies per window */
volatile const __u64 health_blacklist_ns      = 300ULL * 1000000000ULL;  /* 5 min */

/* ENet protocol constants (from enet/protocol.h)
 * Header bit layout (first 2 bytes, network order):
 *   bit 15:     SENT_TIME flag
 *   bit 14:     COMPRESSED flag
 *   bits 13-12: SESSION (2-bit session counter, 0-3 — assigned by host on connect)
 *   bits 11-0:  peer_id (0-4095)
 */
#define ENET_HEADER_FLAG_SENT_TIME       0x8000
#define ENET_HEADER_FLAG_COMPRESSED      0x4000
#define ENET_HEADER_FLAG_MASK            0xC000
#define ENET_HEADER_SESSION_MASK         0x3000
#define ENET_HEADER_PEER_ID_MASK         0x0FFF

#define ENET_CMD_TYPE_MASK               0x0F
#define ENET_CMD_FLAG_ACKNOWLEDGE        0x80
#define ENET_CMD_FLAG_UNSEQUENCED        0x40
#define ENET_CMD_FLAGS_MASK              0xF0
#define ENET_CMD_FLAGS_ALLOWED           (ENET_CMD_FLAG_ACKNOWLEDGE | ENET_CMD_FLAG_UNSEQUENCED)

#define ENET_CMD_TYPE_MIN 1
#define ENET_CMD_TYPE_MAX 12

/*
 * Scan for a "CitizenFX" byte sequence in the first UA_SCAN_BYTES of the
 * TCP payload, classifying what follows:
 *   UA_VALID   — "CitizenFX/1", the real FiveM client
 *   UA_BOT     — "CitizenFX\r" (bare, no /1), a bot fingerprint observed
 *                in real attack captures. Impossible for a real client.
 *   UA_UNKNOWN — nothing matched: could be a non-FiveM request (e.g.
 *                browser / legit scraper) or CitizenFX-prefix followed by
 *                something else; pass without promotion or drop.
 *
 * Folding both into one unrolled pass instead of two separate scans is
 * critical — the 1M-instruction verifier limit gets hit fast with two
 * full-width unrolled scans stacked.
 */
#define UA_SCAN_BYTES 128
#define UA_NEEDLE_LEN 10                       /* "CitizenFX" (9) + 1 classify byte */
#define UA_SCAN_POSITIONS (UA_SCAN_BYTES - UA_NEEDLE_LEN + 1)

enum ua_result { UA_UNKNOWN = 0, UA_VALID = 1, UA_BOT = 2 };

static __always_inline enum ua_result scan_user_agent(void *payload, void *data_end) {
    #pragma unroll
    for (int i = 0; i < UA_SCAN_POSITIONS; i++) {
        unsigned char *p = (unsigned char *)payload + i;
        if ((void *)(p + UA_NEEDLE_LEN) > data_end)
            return UA_UNKNOWN;
        if (p[0] == 'C' && p[1] == 'i' && p[2] == 't' && p[3] == 'i' &&
            p[4] == 'z' && p[5] == 'e' && p[6] == 'n' && p[7] == 'F' &&
            p[8] == 'X') {
            if (p[9] == '/')
                return UA_VALID;       /* assume CitizenFX/1 — the only real client form */
            if (p[9] == '\r')
                return UA_BOT;         /* bare CitizenFX — bot fingerprint */
            return UA_UNKNOWN;         /* other suffix — treat as unknown */
        }
    }
    return UA_UNKNOWN;
}

static __always_inline int match_post_client(void *payload, void *data_end) {
    unsigned char *p = payload;
    if ((void *)(p + 12) > data_end)
        return 0;
    return (p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T' &&
            p[4] == ' ' && p[5] == '/' && p[6] == 'c' && p[7] == 'l' &&
            p[8] == 'i' && p[9] == 'e' && p[10] == 'n' && p[11] == 't');
}

/*
 * Match the three amplification GETs: /info.json, /dynamic.json, /players.json.
 * All three return multi-KB JSON responses; attackers spam them to exhaust the
 * server's egress bandwidth (25–50× amplification observed in real captures).
 * Common prefix "GET /" is cheap; then discriminate on the 6th byte ('i', 'd',
 * 'p') and tail.
 */
static __always_inline int match_get_endpoint(void *payload, void *data_end) {
    unsigned char *p = payload;
    if ((void *)(p + 15) > data_end)
        return 0;
    if (p[0] != 'G' || p[1] != 'E' || p[2] != 'T' || p[3] != ' ' || p[4] != '/')
        return 0;
    /* /info.json */
    if (p[5] == 'i' && p[6] == 'n' && p[7] == 'f' && p[8] == 'o' &&
        p[9] == '.' && p[10] == 'j' && p[11] == 's' && p[12] == 'o' && p[13] == 'n')
        return 1;
    /* /dynamic.json */
    if ((void *)(p + 18) > data_end)
        return 0;
    if (p[5] == 'd' && p[6] == 'y' && p[7] == 'n' && p[8] == 'a' &&
        p[9] == 'm' && p[10] == 'i' && p[11] == 'c' && p[12] == '.' &&
        p[13] == 'j' && p[14] == 's' && p[15] == 'o' && p[16] == 'n')
        return 1;
    /* /players.json */
    if (p[5] == 'p' && p[6] == 'l' && p[7] == 'a' && p[8] == 'y' &&
        p[9] == 'e' && p[10] == 'r' && p[11] == 's' && p[12] == '.' &&
        p[13] == 'j' && p[14] == 's' && p[15] == 'o' && p[16] == 'n')
        return 1;
    return 0;
}


static __always_inline bool health_is_blacklisted(__be32 src_ip) {
    struct udp_health *h = bpf_map_lookup_elem(&udp_health, &src_ip);
    if (!h)
        return false;
    __u64 now = bpf_ktime_get_boot_ns();
    return h->blacklist_until_ns > now;
}

static __always_inline void health_record_anomaly(__be32 src_ip) {
    __u64 now = bpf_ktime_get_boot_ns();
    struct udp_health *h = bpf_map_lookup_elem(&udp_health, &src_ip);
    if (!h) {
        struct udp_health init = {
            .anomalies          = 1,
            .window_start_ns    = now,
            .blacklist_until_ns = 0,
        };
        bpf_map_update_elem(&udp_health, &src_ip, &init, BPF_ANY);
        return;
    }
    if (now - h->window_start_ns > health_window_ns) {
        h->anomalies       = 0;
        h->window_start_ns = now;
    }
    h->anomalies++;
    if (h->anomalies >= health_threshold) {
        h->blacklist_until_ns = now + health_blacklist_ns;
    }
}

/*
 * Returns true if the packet looks like structurally valid ENet.
 * Checks only cheap, per-packet invariants:
 *   - packet long enough to hold header + one command header
 *   - first command type is a valid ENet command (1-12)
 *   - first command flag bits are a legal combination (0, ACK, UNSEQ, both)
 * NOTE: bits 12-13 of the header are the session counter (0-3), not reserved —
 * checking them for zero drops every post-handshake packet from any client the
 * server assigned a non-zero session.
 */
static __always_inline bool enet_looks_valid(void *payload, void *data_end) {
    if ((void *)((__u8 *)payload + 2) > data_end)
        return false;

    __u16 header = bpf_ntohs(*(__u16 *)payload);
    __u32 cmd_offset = (header & ENET_HEADER_FLAG_SENT_TIME) ? 4 : 2;

    /* need peer header + at least one command header (4 bytes) */
    if ((void *)((__u8 *)payload + cmd_offset + 4) > data_end)
        return false;

    __u8 cmd_byte  = *((__u8 *)payload + cmd_offset);
    __u8 cmd_type  = cmd_byte & ENET_CMD_TYPE_MASK;
    __u8 cmd_flags = cmd_byte & ENET_CMD_FLAGS_MASK;

    if (cmd_type < ENET_CMD_TYPE_MIN || cmd_type > ENET_CMD_TYPE_MAX)
        return false;
    if (cmd_flags & ~ENET_CMD_FLAGS_ALLOWED)
        return false;

    return true;
}

/*
 * idTech-style out-of-band (connectionless) packets start with four 0xff bytes
 * followed by an ASCII command: "getinfo", "getchallenge", "connect token=...",
 * "rcon", etc. They're not ENet, so the ENet structural check would false-
 * positive on them. Real FiveM clients send "getinfo <challenge>" here as the
 * very first UDP packet in the join flow.
 */
static __always_inline bool is_oob_prefix(void *payload, void *data_end) {
    unsigned char *p = payload;
    if ((void *)(p + 4) > data_end)
        return false;
    return (p[0] == 0xff && p[1] == 0xff && p[2] == 0xff && p[3] == 0xff);
}

/*
 * Global TCP circuit breaker. Backed by a PERCPU_ARRAY so each CPU has its
 * own bucket — a single shared bucket would serialize every TCP packet on
 * one cache line and the contention itself becomes the bottleneck under
 * the load this filter is meant to survive. The userspace daemon divides
 * the configured global rate/burst by NumCPU before passing in here.
 */
static __always_inline bool tcp_global_ratelimit_take(void) {
    /* Either knob being zero means "disabled" — period=0 alone would make
     * the bucket never refill, dropping every packet from a cold start. */
    if (tcp_global_burst == 0 || tcp_global_period_ns == 0)
        return true;
    __u32 zero = 0;
    struct ratelimit *b = bpf_map_lookup_elem(&tcp_global_ratelimit, &zero);
    if (!b)
        return true;

    __u64 now     = bpf_ktime_get_boot_ns();
    __u64 elapsed = now - b->last_refill_ns;
    __u64 refill  = tcp_global_period_ns > 0 ? elapsed / tcp_global_period_ns : 0;
    __u64 t       = b->tokens + refill;
    if (t > tcp_global_burst)
        t = tcp_global_burst;
    if (t == 0)
        return false;

    b->tokens          = t - 1;
    b->last_refill_ns += refill * tcp_global_period_ns;
    return true;
}

static __always_inline bool ratelimit_take(void *map, __be32 src_ip,
                                           __u64 refill_period_ns, __u64 burst) {
    struct ratelimit *b = bpf_map_lookup_elem(map, &src_ip);
    __u64 now = bpf_ktime_get_boot_ns();

    if (!b) {
        struct ratelimit init = {
            .tokens         = burst > 0 ? burst - 1 : 0,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(map, &src_ip, &init, BPF_ANY);
        return true;
    }

    __u64 elapsed = now - b->last_refill_ns;
    __u64 refill  = refill_period_ns > 0 ? elapsed / refill_period_ns : 0;
    __u64 t       = b->tokens + refill;
    if (t > burst)
        t = burst;
    if (t == 0)
        return false;

    b->tokens          = t - 1;
    b->last_refill_ns += refill * refill_period_ns;
    return true;
}

SEC("xdp")
int fivem_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return XDP_PASS;
    void *l4 = (void *)ip + ihl;
    if (l4 > data_end)
        return XDP_PASS;

    __be16 port_be = bpf_htons(target_port);
    __be32 src     = ip->saddr;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        if (tcp->dest != port_be)
            return XDP_PASS;

        /*
         * iptables equivalent:
         *   -A INPUT -p tcp --dport 30120 -m conntrack --ctstate NEW ! --syn -j DROP
         * A non-SYN packet from an IP that has never sent a SYN and isn't
         * established is an ACK/FIN/RST flood — drop before parsing headers
         * deeper.
         */
        if (!tcp->syn) {
            if (!bpf_map_lookup_elem(&tcp_syn_seen, &src) &&
                !bpf_map_lookup_elem(&tcp_established, &src)) {
                stat_bump(STAT_DROP_TCP_NO_SYN);
                return XDP_DROP;
            }
        } else {
            /* Per-IP open-connection cap. Bots that hold many concurrent
             * TCP sockets to FXServer (slow-loris / accept-queue exhaust)
             * get rejected here at SYN time, before kernel allocates state
             * for a new connection. */
            if (tcp_max_open_per_ip > 0) {
                __u64 *open = bpf_map_lookup_elem(&tcp_open_count, &src);
                if (open && *open >= tcp_max_open_per_ip) {
                    stat_bump(STAT_DROP_TCP_TOO_MANY_OPEN);
                    return XDP_DROP;
                }
            }
            __u64 now = bpf_ktime_get_boot_ns();
            bpf_map_update_elem(&tcp_syn_seen, &src, &now, BPF_ANY);
        }

        /* Global circuit breaker on every TCP packet to the target port.
         * Caps aggregate TCP load when many-IP attacks slip through per-IP
         * limits (each IP within budget but the sum saturates the server). */
        if (!tcp_global_ratelimit_take()) {
            stat_bump(STAT_DROP_TCP_GLOBAL_RATELIMIT);
            return XDP_DROP;
        }

        __u32 tcp_hlen = tcp->doff * 4;
        if (tcp_hlen < sizeof(*tcp))
            return XDP_PASS;
        void *payload = (void *)tcp + tcp_hlen;
        if (payload > data_end)
            return XDP_PASS;

        stat_bump(STAT_PASS_TCP);

        int is_post    = match_post_client(payload, data_end);
        int is_getinfo = is_post ? 0 : match_get_endpoint(payload, data_end);

        if (!is_post && !is_getinfo)
            return XDP_PASS;

        /* Single UA scan: classifies as valid CitizenFX/1, bot bare
         * CitizenFX, or unknown (other UA — pass through). Drop bot
         * before consuming rate-limit tokens so the drop can't be
         * used as a probe. */
        enum ua_result ua = scan_user_agent(payload, data_end);
        if (ua == UA_BOT) {
            stat_bump(STAT_DROP_TCP_BAD_USER_AGENT);
            return XDP_DROP;
        }

        if (is_post) {
            stat_bump(STAT_TCP_POST_CLIENT_SEEN);

            if (!ratelimit_take(&initconnect_ratelimit, src,
                                initconnect_period_ns, initconnect_burst)) {
                stat_bump(STAT_DROP_TCP_INITCONNECT_RATELIMIT);
                return XDP_DROP;
            }

            if (ua == UA_VALID) {
                __u64 *est = bpf_map_lookup_elem(&tcp_established, &src);
                if (est) {
                    __u64 now = bpf_ktime_get_boot_ns();
                    bpf_map_update_elem(&tcp_whitelist, &src, &now, BPF_ANY);
                    stat_bump(STAT_TCP_L7_PROMOTED);
                } else {
                    stat_bump(STAT_TCP_L7_MATCH_NO_EST);
                }
            }
            return XDP_PASS;
        }

        /* is_getinfo: GET /info.json, /dynamic.json, /players.json — the
         * amplification vectors. Per-IP rate limit only; no whitelist
         * promotion (these GETs don't authenticate anything). */
        stat_bump(STAT_TCP_GETINFO_SEEN);

        if (!ratelimit_take(&getinfo_ratelimit, src,
                            getinfo_period_ns, getinfo_burst)) {
            stat_bump(STAT_DROP_TCP_GETINFO_RATELIMIT);
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            stat_bump(STAT_DROP_MALFORMED);
            return XDP_DROP;
        }
        if (udp->dest != port_be)
            return XDP_PASS;

        __u64 *last = bpf_map_lookup_elem(&tcp_whitelist, &src);
        if (!last) {
            stat_bump(STAT_DROP_UDP_NOT_WHITELISTED);
            return XDP_DROP;
        }

        __u64 now = bpf_ktime_get_boot_ns();
        if (now - *last > whitelist_ttl_ns) {
            stat_bump(STAT_DROP_UDP_EXPIRED);
            return XDP_DROP;
        }

        if (health_is_blacklisted(src)) {
            stat_bump(STAT_DROP_UDP_UNHEALTHY);
            return XDP_DROP;
        }

        void *udp_payload = (void *)(udp + 1);
        if (!is_oob_prefix(udp_payload, data_end)) {
            if (!enet_looks_valid(udp_payload, data_end)) {
                health_record_anomaly(src);
                stat_bump(STAT_DROP_UDP_ENET_MALFORMED);
                return XDP_DROP;
            }
        }

        if (!ratelimit_take(&udp_ratelimit, src,
                            udp_refill_period_ns, udp_burst)) {
            stat_bump(STAT_DROP_UDP_RATELIMIT);
            return XDP_DROP;
        }

        stat_bump(STAT_PASS_UDP_WHITELISTED);
        return XDP_PASS;
    }

    return XDP_PASS;
}
