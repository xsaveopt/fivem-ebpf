#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "core_maps.h"

#define IPPROTO_TCP 6

char LICENSE[] SEC("license") = "GPL";

/*
 * Core sock_ops dispatcher. cgroup v2 root accepts only one sock_ops program
 * — this one. Looks up (TCP, local_port) in port_router and tail-calls into
 * the matching module's sock_ops handler. Modules use this signal to fill
 * the shared tcp_established / tcp_open_count maps.
 *
 * skops->local_port is host order (kernel API contract).
 * remote_ip4 is populated for both pure-v4 sockets and v4-mapped-v6
 * dual-stack sockets — modules read it directly. Pure IPv6 connections set
 * remote_ip4=0; modules skip those until v6 support lands.
 */

SEC("sockops")
int gameshield_dispatch_sockops(struct bpf_sock_ops *skops) {
    __u32 key = port_router_key(IPPROTO_TCP, (__u16)skops->local_port);
    __u32 *slot = bpf_map_lookup_elem(&port_router, &key);
    if (!slot)
        return 1;

    bpf_tail_call(skops, &sockops_modules, *slot);
    return 1;
}
