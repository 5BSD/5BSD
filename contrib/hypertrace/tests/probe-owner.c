/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define ASSERT assert
#define MUTEX_HELD(x) 1
#define KM_SLEEP 0
typedef uint32_t dtrace_id_t;
typedef uint64_t dtrace_genid_t;
#include "owner-types.inc"
typedef struct { dtrace_vprobe_owner_t *dts_vprobe_owners; size_t dts_vprobe_registrations; } dtrace_state_t;
typedef struct { dtrace_id_t dtpd_id; } dtrace_probedesc_t;
typedef struct { dtrace_id_t dtpr_id; dtrace_genid_t dtpr_gen; void *dtpr_ecb; } dtrace_probe_t;
static dtrace_probe_t probes[4];
static int disabled[4], allocations;
static void *kmem_zalloc(size_t n, int flags) { assert(flags == KM_SLEEP); allocations++; return calloc(1, n); }
static void kmem_free(void *p, size_t n) { assert(n && allocations > 0); allocations--; free(p); }
static dtrace_probe_t *dtrace_probe_lookup_id(uint16_t vmid, dtrace_id_t id) {
    assert(vmid == 7 && id > 0 && id < 4); return probes[id].dtpr_id ? &probes[id] : NULL;
}
static int disable(uint16_t vmid, dtrace_id_t id) { assert(vmid == 7 && id < 4); disabled[id]++; return 0; }
static int (*hypertrace_disable)(uint16_t, dtrace_id_t) = disable;
#include "owner.inc"
int main(void) {
    dtrace_state_t owner = {0};
    dtrace_probedesc_t descriptions[] = { {1}, {2}, {3} };
    for (unsigned i = 1; i < 4; i++) { probes[i].dtpr_id = i; probes[i].dtpr_gen = 100 + i; }
    dtrace_vprobe_register_owner(&owner, 7, descriptions, 3);
    assert(owner.dts_vprobe_registrations == 3 && allocations == 1);
    probes[2].dtpr_ecb = &owner; /* Another consumer is using it. */
    probes[3].dtpr_gen++; /* A new probe reused the numeric ID. */
    dtrace_vprobe_release_owner(&owner);
    assert(disabled[1] == 1 && disabled[2] == 0 && disabled[3] == 0);
    assert(owner.dts_vprobe_owners == NULL && owner.dts_vprobe_registrations == 0 && allocations == 0);
    dtrace_vprobe_register_owner(&owner, 7, descriptions, 1);
    probes[1].dtpr_id = 0; /* Already reclaimed by a different close. */
    dtrace_vprobe_release_owner(&owner);
    dtrace_vprobe_release_owner(&owner); /* Empty release is harmless. */
    assert(disabled[1] == 1 && allocations == 0);
    puts("PASS: actual abandoned registration cleanup, active consumers, generation reuse and ownership release");
}
