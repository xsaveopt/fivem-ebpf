#ifndef __FIVEM_MAPS_H__
#define __FIVEM_MAPS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "stats.h"

struct ratelimit {
    __u64 tokens;
    __u64 last_refill_ns;
};

struct udp_health {
    __u32 anomalies;
    __u64 window_start_ns;
    __u64 blacklist_until_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_established SEC(".maps");

/*
 * Src IPs that have sent a TCP SYN to the target port. Lets the XDP path
 * approximate the iptables "conntrack NEW && !SYN → DROP" rule: any non-SYN
 * packet arriving from an IP we have not seen a SYN from (and that isn't
 * already established) is almost certainly a spoofed ACK/FIN/RST flood.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_syn_seen SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ratelimit);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_ratelimit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ratelimit);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} initconnect_ratelimit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ratelimit);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} getinfo_ratelimit SEC(".maps");

/* Single per-CPU bucket — circuit breaker on aggregate TCP load to the
 * target port. Userspace divides the global rate/burst by NumCPU. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ratelimit);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_global_ratelimit SEC(".maps");

/*
 * Number of currently-open TCP sockets to the target port per source IP.
 * Sockops increments on PASSIVE_ESTABLISHED and decrements on STATE_CB
 * transitions to TCP_CLOSE; XDP rejects new SYNs from IPs already holding
 * `max_open_per_ip` connections. Catches connection-hold / slow-loris
 * attackers that complete 3WHS but never speak L7 — the case where every
 * other layer's matchers (ratelimit, UA, payload patterns) never fire.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_open_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct udp_health);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_health SEC(".maps");

#define NUM_DROP_REASONS 12

/*
 * Reason index for ip_drop_history.counts[]. Dense and independent from the
 * sparse STAT_DROP_* slot numbers in stats.h — keeps the array compact.
 * Growing this enum changes struct ip_drop_history's size, which means
 * libbpf will refuse to reuse the existing pin (LIBBPF_PIN_BY_NAME shape
 * mismatch). If you add a reason: rm /sys/fs/bpf/fivem/ip_drop_history.
 */
enum drop_reason_idx {
    DROP_REASON_TCP_NO_SYN                = 0,
    DROP_REASON_TCP_TOO_MANY_OPEN         = 1,
    DROP_REASON_TCP_GLOBAL_RATELIMIT      = 2,
    DROP_REASON_TCP_BAD_USER_AGENT        = 3,
    DROP_REASON_TCP_INITCONNECT_RATELIMIT = 4,
    DROP_REASON_TCP_GETINFO_RATELIMIT     = 5,
    DROP_REASON_MALFORMED                 = 6,
    DROP_REASON_UDP_NOT_WHITELISTED       = 7,
    DROP_REASON_UDP_EXPIRED               = 8,
    DROP_REASON_UDP_UNHEALTHY             = 9,
    DROP_REASON_UDP_ENET_MALFORMED        = 10,
    DROP_REASON_UDP_RATELIMIT             = 11,
};

struct ip_drop_history {
    __u64 first_drop_ns;
    __u64 last_drop_ns;
    __u64 counts[NUM_DROP_REASONS];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ip_drop_history);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_drop_history SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

static __always_inline void stat_bump(__u32 slot) {
    __u64 *c = bpf_map_lookup_elem(&stats, &slot);
    if (c)
        (*c)++;
}

#endif
