#ifndef __GAMESHIELD_STATS_H__
#define __GAMESHIELD_STATS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define STAT_BUMP(MAP, slot) do {                                  \
        __u32 _gs_slot = (slot);                                   \
        __u64 *_gs_c = bpf_map_lookup_elem(&(MAP), &_gs_slot);     \
        if (_gs_c) (*_gs_c)++;                                     \
    } while (0)

#endif
