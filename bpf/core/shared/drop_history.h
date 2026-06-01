#ifndef __GAMESHIELD_DROP_HISTORY_H__
#define __GAMESHIELD_DROP_HISTORY_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define DEFINE_DROP_HISTORY_MAP(NAME, NUM_REASONS)                              \
    struct NAME##_value {                                                       \
        __u64 first_drop_ns;                                                    \
        __u64 last_drop_ns;                                                     \
        __u64 counts[NUM_REASONS];                                              \
    };                                                                          \
    struct {                                                                    \
        __uint(type, BPF_MAP_TYPE_LRU_HASH);                                    \
        __type(key, __be32);                                                    \
        __type(value, struct NAME##_value);                                     \
        __uint(max_entries, 100000);                                            \
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                    \
    } NAME SEC(".maps");                                                        \
    static __always_inline void NAME##_record(__be32 src_ip, __u32 reason_idx) {\
        if (reason_idx >= (NUM_REASONS))                                        \
            return;                                                             \
        __u64 now = bpf_ktime_get_boot_ns();                                    \
        struct NAME##_value *h = bpf_map_lookup_elem(&NAME, &src_ip);           \
        if (!h) {                                                               \
            struct NAME##_value init = {0};                                     \
            init.first_drop_ns = now;                                           \
            init.last_drop_ns  = now;                                           \
            init.counts[reason_idx] = 1;                                        \
            bpf_map_update_elem(&NAME, &src_ip, &init, BPF_ANY);                \
            return;                                                             \
        }                                                                       \
        h->last_drop_ns = now;                                                  \
        __sync_fetch_and_add(&h->counts[reason_idx], 1);                        \
    }

#endif
