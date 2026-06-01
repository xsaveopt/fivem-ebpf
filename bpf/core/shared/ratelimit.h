#ifndef __GAMESHIELD_RATELIMIT_H__
#define __GAMESHIELD_RATELIMIT_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct ratelimit {
    __u64 tokens;
    __u64 last_refill_ns;
};

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

static __always_inline bool ratelimit_take_percpu(void *map,
                                                  __u64 refill_period_ns,
                                                  __u64 burst) {
    if (burst == 0 || refill_period_ns == 0)
        return true;
    __u32 zero = 0;
    struct ratelimit *b = bpf_map_lookup_elem(map, &zero);
    if (!b)
        return true;

    __u64 now     = bpf_ktime_get_boot_ns();
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

#endif
