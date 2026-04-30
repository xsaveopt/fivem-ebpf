#ifndef __GAMESHIELD_UDP_RATELIMIT_H__
#define __GAMESHIELD_UDP_RATELIMIT_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "ratelimit.h"

/*
 * Per-IP UDP token bucket shared across modules. Modules with UDP-bearing
 * protocols all share this — entry per src_ip. If two modules each set
 * different rates the entries' refill_period semantics differ across
 * lookups, but each module passes its own rate at call time so the bucket
 * just refills faster/slower depending on which module checked it last.
 * Acceptable because UDP-bearing modules on one host are unusual; if it
 * becomes a real problem, partition by giving each module its own pinned
 * map name.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ratelimit);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_ratelimit SEC(".maps");

#endif
