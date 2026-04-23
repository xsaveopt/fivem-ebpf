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
