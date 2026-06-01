#ifndef __GAMESHIELD_FIVEM_MAPS_H__
#define __GAMESHIELD_FIVEM_MAPS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "../../core/shared/ratelimit.h"
#include "../../core/shared/drop_history.h"
#include "stats.h"

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, FIVEM_STAT_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fivem_stats SEC(".maps");

DEFINE_DROP_HISTORY_MAP(fivem_drop_history, FIVEM_NUM_DROP_REASONS)

#endif
