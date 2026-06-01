#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "core_maps.h"

#define IPPROTO_TCP 6

char LICENSE[] SEC("license") = "GPL";

SEC("sockops")
int gameshield_dispatch_sockops(struct bpf_sock_ops *skops) {
    __u32 key = port_router_key(IPPROTO_TCP, (__u16)skops->local_port);
    __u32 *slot = bpf_map_lookup_elem(&port_router, &key);
    if (!slot)
        return 1;

    bpf_tail_call(skops, &sockops_modules, *slot);
    return 1;
}
