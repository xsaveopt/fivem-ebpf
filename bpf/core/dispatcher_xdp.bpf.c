#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "shared/parse.h"
#include "shared/ratelimit.h"
#include "shared/tcp_state.h"
#include "shared/udp_ratelimit.h"
#include "shared/health.h"
#include "core_maps.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Core XDP dispatcher. Owns iface attachment; tail-calls into the per-module
 * XDP program based on (proto, dest_port). Falls through to XDP_PASS when
 * no module is bound or the tail call fails — fail-open is mandatory; the
 * box must not silently black-hole traffic when a module unloads.
 *
 * Modules implementing tail-callable XDP programs declare them with
 * SEC("xdp") and rely on userspace to write their FD into xdp_modules[id].
 */

SEC("xdp")
int gameshield_dispatch_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct parsed_l3l4 p;
    if (parse_eth_ip_l4(data, data_end, &p) < 0)
        return XDP_PASS;

    __u16 dest_port_host = 0;
    if (p.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = p.l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        dest_port_host = bpf_ntohs(tcp->dest);
    } else if (p.proto == IPPROTO_UDP) {
        struct udphdr *udp = p.l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dest_port_host = bpf_ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }

    __u32 key = port_router_key(p.proto, dest_port_host);
    __u32 *slot = bpf_map_lookup_elem(&port_router, &key);
    if (!slot)
        return XDP_PASS;

    bpf_tail_call(ctx, &xdp_modules, *slot);
    /* tail call only returns on failure (slot empty / out of range) — fail
     * open. The dispatcher must not invent verdicts on its own. */
    return XDP_PASS;
}
