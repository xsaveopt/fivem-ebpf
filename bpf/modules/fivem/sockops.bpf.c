#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "../../core/shared/tcp_state.h"
#include "../../core/shared/stats.h"
#include "stats.h"
#include "maps.h"

#define AF_INET  2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

/* remote_ip6[3] array indexing trips the verifier's "dereference of modified
 * ctx ptr" check — use remote_ip4 directly (set for v4 and v4-mapped-v6). */

SEC("sockops")
int gameshield_fivem_sockops(struct bpf_sock_ops *skops) {
    if (skops->family != AF_INET && skops->family != AF_INET6)
        return 1;

    __be32 src = skops->remote_ip4;
    if (src == 0)
        return 1;

    if (skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        __u64 now = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&tcp_established, &src, &now, BPF_ANY);
        STAT_BUMP(fivem_stats, FIVEM_STAT_TCP_ESTABLISHED_INSERTS);
        tcp_open_count_inc(src);
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
        return 1;
    }

    if (skops->op == BPF_SOCK_OPS_STATE_CB) {
        /* Only decrement on a genuinely-open → CLOSE transition. Without
         * filtering on old_state, a half-closed peer (idTech-style write-
         * only sink) underflows the counter and falsely blocks new SYNs. */
        __u32 old_state = skops->args[0];
        __u32 new_state = skops->args[1];
        if (new_state == BPF_TCP_CLOSE &&
            (old_state == BPF_TCP_ESTABLISHED ||
             old_state == BPF_TCP_FIN_WAIT1 ||
             old_state == BPF_TCP_FIN_WAIT2 ||
             old_state == BPF_TCP_CLOSE_WAIT ||
             old_state == BPF_TCP_LAST_ACK ||
             old_state == BPF_TCP_TIME_WAIT ||
             old_state == BPF_TCP_CLOSING)) {
            tcp_open_count_dec(src);
        }
        return 1;
    }

    return 1;
}
