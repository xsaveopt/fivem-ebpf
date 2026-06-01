#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../../core/shared/parse.h"
#include "../../core/shared/ratelimit.h"
#include "../../core/shared/tcp_state.h"
#include "../../core/shared/udp_ratelimit.h"
#include "../../core/shared/health.h"
#include "../../core/shared/stats.h"
#include "stats.h"
#include "maps.h"

char LICENSE[] SEC("license") = "GPL";

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

/* One unrolled pass, not two — two full-width unrolled scans hit the
 * 1M-instruction verifier limit. Don't split it back out. */
#define UA_SCAN_BYTES 128
#define UA_NEEDLE_LEN 10
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

static __always_inline bool enet_looks_valid(void *payload, void *data_end) {
    if ((void *)((__u8 *)payload + 2) > data_end)
        return false;

    __u16 header = bpf_ntohs(*(__u16 *)payload);
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

/* idTech OOB (4×0xff): real FiveM clients send these as the first UDP packet;
 * the ENet structural check would false-positive on them. */
static __always_inline bool is_oob_prefix(void *payload, void *data_end) {
    unsigned char *p = payload;
    if ((void *)(p + 4) > data_end)
        return false;
    return (p[0] == 0xff && p[1] == 0xff && p[2] == 0xff && p[3] == 0xff);
}

SEC("xdp")
int gameshield_fivem_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct parsed_l3l4 p;
    if (parse_eth_ip_l4(data, data_end, &p) < 0)
        return XDP_PASS;

    __be32 src = p.ip->saddr;

    if (p.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = p.l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        __u64 *wl = bpf_map_lookup_elem(&tcp_whitelist, &src);
        if (wl) {
            *wl = bpf_ktime_get_boot_ns();
            STAT_BUMP(fivem_stats, FIVEM_STAT_PASS_TCP);
            return XDP_PASS;
        }

        if (!tcp->syn) {
            if (!bpf_map_lookup_elem(&tcp_syn_seen, &src) &&
                !bpf_map_lookup_elem(&tcp_established, &src)) {
                fivem_drop_history_record(src, FIVEM_DROP_TCP_NO_SYN);
                STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_TCP_NO_SYN);
                return XDP_DROP;
            }
        } else {
            if (tcp_max_open_per_ip > 0) {
                __u64 *open = bpf_map_lookup_elem(&tcp_open_count, &src);
                if (open && *open >= tcp_max_open_per_ip) {
                    fivem_drop_history_record(src, FIVEM_DROP_TCP_TOO_MANY_OPEN);
                    STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_TCP_TOO_MANY_OPEN);
                    return XDP_DROP;
                }
            }
            /* NEW connections only — applying to every TCP packet shed
             * asset-download traffic during floods and broke legit joins. */
            if (!ratelimit_take_percpu(&tcp_global_ratelimit,
                                       tcp_global_period_ns, tcp_global_burst)) {
                fivem_drop_history_record(src, FIVEM_DROP_TCP_GLOBAL_RATELIMIT);
                STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_TCP_GLOBAL_RATELIMIT);
                return XDP_DROP;
            }
            __u64 now = bpf_ktime_get_boot_ns();
            bpf_map_update_elem(&tcp_syn_seen, &src, &now, BPF_ANY);
        }

        __u32 tcp_hlen = tcp->doff * 4;
        if (tcp_hlen < sizeof(*tcp))
            return XDP_PASS;
        void *payload = (void *)tcp + tcp_hlen;
        if (payload > data_end)
            return XDP_PASS;

        STAT_BUMP(fivem_stats, FIVEM_STAT_PASS_TCP);

        int is_post    = match_post_client(payload, data_end);
        int is_getinfo = is_post ? 0 : match_get_endpoint(payload, data_end);

        if (!is_post && !is_getinfo)
            return XDP_PASS;

        /* Drop bot UA before consuming rate-limit tokens — else the drop is a probe vector. */
        enum ua_result ua = scan_user_agent(payload, data_end);
        if (ua == UA_BOT) {
            fivem_drop_history_record(src, FIVEM_DROP_TCP_BAD_USER_AGENT);
            STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_TCP_BAD_USER_AGENT);
            return XDP_DROP;
        }

        if (is_post) {
            STAT_BUMP(fivem_stats, FIVEM_STAT_TCP_POST_CLIENT_SEEN);

            if (!ratelimit_take(&initconnect_ratelimit, src,
                                initconnect_period_ns, initconnect_burst)) {
                fivem_drop_history_record(src, FIVEM_DROP_TCP_INITCONNECT_RATELIMIT);
                STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_TCP_INITCONNECT_RATELIMIT);
                return XDP_DROP;
            }

            if (ua == UA_VALID) {
                __u64 *est = bpf_map_lookup_elem(&tcp_established, &src);
                if (est) {
                    __u64 now = bpf_ktime_get_boot_ns();
                    bpf_map_update_elem(&tcp_whitelist, &src, &now, BPF_ANY);
                    STAT_BUMP(fivem_stats, FIVEM_STAT_TCP_L7_PROMOTED);
                } else {
                    STAT_BUMP(fivem_stats, FIVEM_STAT_TCP_L7_MATCH_NO_EST);
                }
            }
            return XDP_PASS;
        }

        STAT_BUMP(fivem_stats, FIVEM_STAT_TCP_GETINFO_SEEN);

        if (!ratelimit_take(&getinfo_ratelimit, src,
                            getinfo_period_ns, getinfo_burst)) {
            fivem_drop_history_record(src, FIVEM_DROP_TCP_GETINFO_RATELIMIT);
            STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_TCP_GETINFO_RATELIMIT);
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    if (p.proto == IPPROTO_UDP) {
        struct udphdr *udp = p.l4;
        if ((void *)(udp + 1) > data_end) {
            fivem_drop_history_record(src, FIVEM_DROP_MALFORMED);
            STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_MALFORMED);
            return XDP_DROP;
        }

        __u64 *last = bpf_map_lookup_elem(&tcp_whitelist, &src);
        if (!last) {
            fivem_drop_history_record(src, FIVEM_DROP_UDP_NOT_WHITELISTED);
            STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_UDP_NOT_WHITELISTED);
            return XDP_DROP;
        }

        __u64 now = bpf_ktime_get_boot_ns();
        if (now - *last > whitelist_ttl_ns) {
            fivem_drop_history_record(src, FIVEM_DROP_UDP_EXPIRED);
            STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_UDP_EXPIRED);
            return XDP_DROP;
        }

        if (health_is_blacklisted(src)) {
            fivem_drop_history_record(src, FIVEM_DROP_UDP_UNHEALTHY);
            STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_UDP_UNHEALTHY);
            return XDP_DROP;
        }

        void *udp_payload = (void *)(udp + 1);
        if (!is_oob_prefix(udp_payload, data_end)) {
            if (!enet_looks_valid(udp_payload, data_end)) {
                health_record_anomaly(src, health_window_ns, health_threshold,
                                      health_blacklist_ns);
                fivem_drop_history_record(src, FIVEM_DROP_UDP_ENET_MALFORMED);
                STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_UDP_ENET_MALFORMED);
                return XDP_DROP;
            }
        }

        if (!ratelimit_take(&udp_ratelimit, src,
                            udp_refill_period_ns, udp_burst)) {
            fivem_drop_history_record(src, FIVEM_DROP_UDP_RATELIMIT);
            STAT_BUMP(fivem_stats, FIVEM_STAT_DROP_UDP_RATELIMIT);
            return XDP_DROP;
        }

        bpf_map_update_elem(&tcp_whitelist, &src, &now, BPF_ANY);

        STAT_BUMP(fivem_stats, FIVEM_STAT_PASS_UDP_WHITELISTED);
        return XDP_PASS;
    }

    return XDP_PASS;
}
