#ifndef __GAMESHIELD_STATS_H__
#define __GAMESHIELD_STATS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * Each module owns its own PERCPU_ARRAY of stat counters. The map name
 * differs per module (fivem_stats, minecraft_stats, ...) so adding a slot
 * in one module never invalidates another module's pinned map.
 *
 * Use STAT_BUMP(MAP, slot) inside module code; the macro takes the map by
 * name so it expands to a direct &MAP reference (the verifier requires the
 * map argument to bpf_map_lookup_elem to be a known map pointer, not a
 * runtime void*).
 */
#define STAT_BUMP(MAP, slot) do {                                  \
        __u32 _gs_slot = (slot);                                   \
        __u64 *_gs_c = bpf_map_lookup_elem(&(MAP), &_gs_slot);     \
        if (_gs_c) (*_gs_c)++;                                     \
    } while (0)

#endif
