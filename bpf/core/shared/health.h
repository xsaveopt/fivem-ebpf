#ifndef __GAMESHIELD_HEALTH_H__
#define __GAMESHIELD_HEALTH_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct udp_health {
    __u32 anomalies;
    __u64 window_start_ns;
    __u64 blacklist_until_ns;
};

/*
 * Anomaly-driven blacklist. Modules call health_record_anomaly() when a
 * packet looks structurally invalid for their protocol; once an IP exceeds
 * `threshold` anomalies inside `window_ns`, it is blacklisted for
 * `blacklist_ns`. health_is_blacklisted() is a cheap read for the fast path.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct udp_health);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_health SEC(".maps");

static __always_inline bool health_is_blacklisted(__be32 src_ip) {
    struct udp_health *h = bpf_map_lookup_elem(&udp_health, &src_ip);
    if (!h)
        return false;
    __u64 now = bpf_ktime_get_boot_ns();
    return h->blacklist_until_ns > now;
}

static __always_inline void health_record_anomaly(__be32 src_ip,
                                                  __u64 window_ns,
                                                  __u32 threshold,
                                                  __u64 blacklist_ns) {
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
    if (now - h->window_start_ns > window_ns) {
        h->anomalies       = 0;
        h->window_start_ns = now;
    }
    h->anomalies++;
    if (h->anomalies >= threshold) {
        h->blacklist_until_ns = now + blacklist_ns;
    }
}

#endif
