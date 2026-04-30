#ifndef __GAMESHIELD_PARSE_H__
#define __GAMESHIELD_PARSE_H__

#include "vmlinux.h"
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/*
 * Parse eth → IPv4 → L4 from an XDP context with explicit bounds checks at
 * each step. On success returns 0 with *out_ip and *out_l4 pointing into
 * packet data; caller still has to widen-bound-check before dereferencing
 * the L4 header itself. Returns non-zero on malformed/truncated frames or
 * non-IPv4 / unsupported protocol — caller should XDP_PASS in that case.
 */
struct parsed_l3l4 {
    struct iphdr  *ip;
    void          *l4;
    __u8           proto;
};

static __always_inline int parse_eth_ip_l4(void *data, void *data_end,
                                           struct parsed_l3l4 *out) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return -1;
    void *l4 = (void *)ip + ihl;
    if (l4 > data_end)
        return -1;

    out->ip    = ip;
    out->l4    = l4;
    out->proto = ip->protocol;
    return 0;
}

#endif
