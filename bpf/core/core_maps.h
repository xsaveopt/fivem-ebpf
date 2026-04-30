#ifndef __GAMESHIELD_CORE_MAPS_H__
#define __GAMESHIELD_CORE_MAPS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * Dispatcher → module tail-call mechanism. The XDP dispatcher parses
 * eth/ip/l4, builds a port_router key from (proto, dest_port), looks up the
 * module slot, and bpf_tail_call()s into xdp_modules[slot]. Same idea for
 * sock_ops via sockops_modules.
 *
 * port_router key encoding: ((u32)proto << 16) | (host-order port).
 * This keeps userspace writes intuitive (port=30120, not htons(30120)).
 *
 * GAMESHIELD_MAX_MODULES caps the number of modules that can be enabled
 * concurrently. Bump together with the prog_array max_entries if more are
 * ever needed; current modules: fivem (id=0). Slot allocation is owned by
 * userspace.
 */
#define GAMESHIELD_MAX_MODULES 16

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, GAMESHIELD_MAX_MODULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_modules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, GAMESHIELD_MAX_MODULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sockops_modules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} port_router SEC(".maps");

static __always_inline __u32 port_router_key(__u8 proto, __u16 host_port) {
    return ((__u32)proto << 16) | (__u32)host_port;
}

#endif
