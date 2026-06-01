#ifndef __GAMESHIELD_UDP_RATELIMIT_H__
#define __GAMESHIELD_UDP_RATELIMIT_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "ratelimit.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ratelimit);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_ratelimit SEC(".maps");

#endif
