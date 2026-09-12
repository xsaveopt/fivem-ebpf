#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "shared/maps.h"

#define ETH_P_IP     0x0800
#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

#define MAX_VLAN_TAGS 2

char LICENSE[] SEC("license") = "GPL";

volatile const __u16 target_port              = 30120;
volatile const __u64 whitelist_ttl_ns         = 600ULL * 1000000000ULL;
volatile const __u64 udp_refill_period_ns     = 666666ULL;
volatile const __u64 udp_burst                = 4500;
volatile const __u64 initconnect_period_ns    = 10000000000ULL;
volatile const __u64 initconnect_burst        = 3;
volatile const __u64 getinfo_period_ns        = 10000000000ULL;
volatile const __u64 getinfo_burst            = 5;

volatile const __u64 tcp_global_period_ns     = 0;
volatile const __u64 tcp_global_burst         = 0;

volatile const __u64 tcp_max_open_per_ip      = 0;
volatile const __u64 health_window_ns         = 10ULL * 1000000000ULL;
volatile const __u32 health_threshold         = 20;
volatile const __u64 health_blacklist_ns      = 300ULL * 1000000000ULL;

volatile const __u8  drop_history_enabled     = 1;

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

#define UA_SCAN_BYTES 512
#define UA_NEEDLE_LEN 10
#define UA_SCAN_POSITIONS (UA_SCAN_BYTES - UA_NEEDLE_LEN + 1)

struct fivem_vlan_hdr {
    __be16 tci;
    __be16 encapsulated_proto;
};

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
                return UA_VALID;
            if (p[9] == '\r')
                return UA_BOT;
            return UA_UNKNOWN;
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

static __always_inline int match_get_endpoint(void *payload, void *data_end) {
    unsigned char *p = payload;
    if ((void *)(p + 15) > data_end)
        return 0;
    if (p[0] != 'G' || p[1] != 'E' || p[2] != 'T' || p[3] != ' ' || p[4] != '/')
        return 0;

    if (p[5] == 'i' && p[6] == 'n' && p[7] == 'f' && p[8] == 'o' &&
        p[9] == '.' && p[10] == 'j' && p[11] == 's' && p[12] == 'o' && p[13] == 'n')
        return 1;

    if ((void *)(p + 18) > data_end)
        return 0;
    if (p[5] == 'd' && p[6] == 'y' && p[7] == 'n' && p[8] == 'a' &&
        p[9] == 'm' && p[10] == 'i' && p[11] == 'c' && p[12] == '.' &&
        p[13] == 'j' && p[14] == 's' && p[15] == 'o' && p[16] == 'n')
        return 1;

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

static __always_inline void record_drop(__be32 src_ip, __u32 reason_idx, bool known_source) {
    if (!drop_history_enabled)
        return;
    if (reason_idx >= NUM_DROP_REASONS)
        return;
    __u64 now = bpf_ktime_get_boot_ns();
    struct ip_drop_history *h = bpf_map_lookup_elem(&ip_drop_history, &src_ip);
    if (!h) {
        if (!known_source)
            return;
        struct ip_drop_history init = {0};
        init.first_drop_ns = now;
        init.last_drop_ns  = now;
        init.counts[reason_idx] = 1;
        bpf_map_update_elem(&ip_drop_history, &src_ip, &init, BPF_NOEXIST);
        return;
    }
    h->last_drop_ns = now;
    __sync_fetch_and_add(&h->counts[reason_idx], 1);
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
        bpf_map_update_elem(&udp_health, &src_ip, &init, BPF_NOEXIST);
        return;
    }
    if (now - h->window_start_ns > health_window_ns) {
        h->anomalies       = 0;
        h->window_start_ns = now;
    }
    __sync_fetch_and_add(&h->anomalies, 1);
    if (h->anomalies >= health_threshold) {
        h->blacklist_until_ns = now + health_blacklist_ns;
    }
}

static __always_inline bool enet_looks_valid(void *payload, void *data_end) {
    if ((void *)((__u8 *)payload + 2) > data_end)
        return false;

    __u16 header = bpf_ntohs(*(__u16 *)payload);

    if (header & ENET_HEADER_FLAG_COMPRESSED)
        return true;

    __u32 cmd_offset = (header & ENET_HEADER_FLAG_SENT_TIME) ? 4 : 2;

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

static __always_inline bool is_oob_prefix(void *payload, void *data_end) {
    unsigned char *p = payload;
    if ((void *)(p + 4) > data_end)
        return false;
    return (p[0] == 0xff && p[1] == 0xff && p[2] == 0xff && p[3] == 0xff);
}

static __always_inline bool tcp_global_ratelimit_take(void) {

    if (tcp_global_burst == 0 || tcp_global_period_ns == 0)
        return true;
    __u32 zero = 0;
    struct ratelimit *b = bpf_map_lookup_elem(&tcp_global_ratelimit, &zero);
    if (!b)
        return true;

    __u64 now     = bpf_ktime_get_boot_ns();
    __u64 elapsed = now - b->last_refill_ns;
    __u64 refill  = elapsed / tcp_global_period_ns;
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
    if (refill_period_ns == 0 || burst == 0)
        return true;

    struct ratelimit *b = bpf_map_lookup_elem(map, &src_ip);
    __u64 now = bpf_ktime_get_boot_ns();

    if (!b) {
        struct ratelimit init = {
            .tokens         = burst - 1,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(map, &src_ip, &init, BPF_ANY);
        return true;
    }

    __u64 elapsed = now - b->last_refill_ns;
    __u64 refill  = elapsed / refill_period_ns;
    __u64 t       = b->tokens + refill;
    if (t > burst)
        t = burst;
    if (t == 0)
        return false;

    b->tokens          = t - 1;
    b->last_refill_ns += refill * refill_period_ns;
    return true;
}

static __always_inline void whitelist_refresh(__u64 *entry) {
    if (entry)
        *entry = bpf_ktime_get_boot_ns();
}

SEC("xdp")
int fivem_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __be16 h_proto = eth->h_proto;
    void *nh       = (void *)(eth + 1);

    #pragma unroll
    for (int i = 0; i < MAX_VLAN_TAGS; i++) {
        if (h_proto != bpf_htons(ETH_P_8021Q) && h_proto != bpf_htons(ETH_P_8021AD))
            break;
        struct fivem_vlan_hdr *vh = nh;
        if ((void *)(vh + 1) > data_end)
            return XDP_PASS;
        h_proto = vh->encapsulated_proto;
        nh      = (void *)(vh + 1);
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = nh;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return XDP_PASS;
    void *l4 = (void *)ip + ihl;
    if (l4 > data_end)
        return XDP_PASS;

    __u16 frag = bpf_ntohs(ip->frag_off);
    if (frag & IP_OFFSET)
        return XDP_PASS;
    bool more_frags = (frag & IP_MF) != 0;

    __be16 port_be = bpf_htons(target_port);
    __be32 src     = ip->saddr;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        if (tcp->dest != port_be)
            return XDP_PASS;

        if (more_frags) {
            record_drop(src, DROP_REASON_IP_FRAGMENT, false);
            stat_bump(STAT_DROP_IP_FRAGMENT);
            return XDP_DROP;
        }

        __u64 *wl = bpf_map_lookup_elem(&tcp_whitelist, &src);

        if (!tcp->syn) {
            if (!wl &&
                !bpf_map_lookup_elem(&tcp_syn_seen, &src) &&
                !bpf_map_lookup_elem(&tcp_established, &src)) {
                record_drop(src, DROP_REASON_TCP_NO_SYN, false);
                stat_bump(STAT_DROP_TCP_NO_SYN);
                return XDP_DROP;
            }
        } else {

            if (tcp_max_open_per_ip > 0) {
                __u64 *open = bpf_map_lookup_elem(&tcp_open_count, &src);
                if (open && (__s64)*open >= (__s64)tcp_max_open_per_ip) {
                    record_drop(src, DROP_REASON_TCP_TOO_MANY_OPEN, true);
                    stat_bump(STAT_DROP_TCP_TOO_MANY_OPEN);
                    return XDP_DROP;
                }
            }

            if (!tcp_global_ratelimit_take()) {
                record_drop(src, DROP_REASON_TCP_GLOBAL_RATELIMIT, wl != NULL);
                stat_bump(STAT_DROP_TCP_GLOBAL_RATELIMIT);
                return XDP_DROP;
            }
            __u64 now = bpf_ktime_get_boot_ns();
            bpf_map_update_elem(&tcp_syn_seen, &src, &now, BPF_ANY);
        }

        __u32 tcp_hlen = tcp->doff * 4;
        if (tcp_hlen < sizeof(*tcp)) {
            record_drop(src, DROP_REASON_MALFORMED, false);
            stat_bump(STAT_DROP_MALFORMED);
            return XDP_DROP;
        }
        void *payload = (void *)tcp + tcp_hlen;
        if (payload > data_end) {
            record_drop(src, DROP_REASON_MALFORMED, false);
            stat_bump(STAT_DROP_MALFORMED);
            return XDP_DROP;
        }

        int is_post    = match_post_client(payload, data_end);
        int is_getinfo = is_post ? 0 : match_get_endpoint(payload, data_end);

        if (!is_post && !is_getinfo) {
            whitelist_refresh(wl);
            stat_bump(STAT_PASS_TCP);
            return XDP_PASS;
        }

        enum ua_result ua = scan_user_agent(payload, data_end);
        if (ua == UA_BOT) {
            record_drop(src, DROP_REASON_TCP_BAD_USER_AGENT, true);
            stat_bump(STAT_DROP_TCP_BAD_USER_AGENT);
            return XDP_DROP;
        }

        if (is_post) {
            stat_bump(STAT_TCP_POST_CLIENT_SEEN);

            if (!ratelimit_take(&initconnect_ratelimit, src,
                                initconnect_period_ns, initconnect_burst)) {
                record_drop(src, DROP_REASON_TCP_INITCONNECT_RATELIMIT, true);
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
            } else {
                stat_bump(STAT_TCP_POST_UA_UNKNOWN);
            }
            whitelist_refresh(wl);
            stat_bump(STAT_PASS_TCP);
            return XDP_PASS;
        }

        stat_bump(STAT_TCP_GETINFO_SEEN);

        if (!ratelimit_take(&getinfo_ratelimit, src,
                            getinfo_period_ns, getinfo_burst)) {
            record_drop(src, DROP_REASON_TCP_GETINFO_RATELIMIT, true);
            stat_bump(STAT_DROP_TCP_GETINFO_RATELIMIT);
            return XDP_DROP;
        }
        whitelist_refresh(wl);
        stat_bump(STAT_PASS_TCP);
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        if (udp->dest != port_be)
            return XDP_PASS;

        if (more_frags) {
            record_drop(src, DROP_REASON_IP_FRAGMENT, false);
            stat_bump(STAT_DROP_IP_FRAGMENT);
            return XDP_DROP;
        }

        __u64 *last = bpf_map_lookup_elem(&tcp_whitelist, &src);
        if (!last) {
            record_drop(src, DROP_REASON_UDP_NOT_WHITELISTED, false);
            stat_bump(STAT_DROP_UDP_NOT_WHITELISTED);
            return XDP_DROP;
        }

        __u64 now = bpf_ktime_get_boot_ns();
        if (now - *last > whitelist_ttl_ns) {
            record_drop(src, DROP_REASON_UDP_EXPIRED, true);
            stat_bump(STAT_DROP_UDP_EXPIRED);
            return XDP_DROP;
        }

        if (health_is_blacklisted(src)) {
            record_drop(src, DROP_REASON_UDP_UNHEALTHY, true);
            stat_bump(STAT_DROP_UDP_UNHEALTHY);
            return XDP_DROP;
        }

        void *udp_payload = (void *)(udp + 1);
        if (!is_oob_prefix(udp_payload, data_end)) {
            if (!enet_looks_valid(udp_payload, data_end)) {
                health_record_anomaly(src);
                record_drop(src, DROP_REASON_UDP_ENET_MALFORMED, true);
                stat_bump(STAT_DROP_UDP_ENET_MALFORMED);
                return XDP_DROP;
            }
        }

        if (!ratelimit_take(&udp_ratelimit, src,
                            udp_refill_period_ns, udp_burst)) {
            record_drop(src, DROP_REASON_UDP_RATELIMIT, true);
            stat_bump(STAT_DROP_UDP_RATELIMIT);
            return XDP_DROP;
        }

        *last = now;

        stat_bump(STAT_PASS_UDP_WHITELISTED);
        return XDP_PASS;
    }

    return XDP_PASS;
}
