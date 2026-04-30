#ifndef __GAMESHIELD_TCP_STATE_H__
#define __GAMESHIELD_TCP_STATE_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "ratelimit.h"

/*
 * Core per-IP TCP state. Shared across modules — the (src_ip, dest_port)
 * tuple disambiguates which module's traffic an entry belongs to, but for
 * cheap lookups the maps are keyed only by src_ip and modules read whatever
 * the most recent observation was. This is fine because:
 *   - tcp_established / tcp_syn_seen are advisory (drop heuristics on cold
 *     IPs), not security-critical
 *   - tcp_whitelist is per-IP "this IP completed a real handshake somewhere
 *     we trust"; if a host runs both FiveM and Minecraft and an IP joined
 *     either, treating it as known-good for both is correct
 *   - tcp_open_count is aggregated across modules — equally fine.
 */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_established SEC(".maps");

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
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_open_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ratelimit);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_global_ratelimit SEC(".maps");

static __always_inline void tcp_open_count_inc(__be32 src) {
    __u64 zero = 0;
    bpf_map_update_elem(&tcp_open_count, &src, &zero, BPF_NOEXIST);
    __u64 *count = bpf_map_lookup_elem(&tcp_open_count, &src);
    if (count)
        __sync_fetch_and_add(count, 1);
}

static __always_inline void tcp_open_count_dec(__be32 src) {
    __u64 *count = bpf_map_lookup_elem(&tcp_open_count, &src);
    if (count && *count > 0)
        __sync_fetch_and_sub(count, 1);
}

#endif
