/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#define DIF_VAR_VTIMESTAMP 1
#define DIF_VAR_HVTIMESTAMP 2
#define MUTEX_HELD(lock) ((void)(lock), 1)
#define ASSERT(condition) assert(condition)

typedef struct { unsigned dtdv_id; } dtrace_difv_t;
typedef struct { unsigned unused; } dtrace_vstate_t;
typedef struct {
	unsigned dtdo_refcnt;
	int dtdo_varlen;
	dtrace_difv_t *dtdo_vartab;
} dtrace_difo_t;

static int dtrace_lock;
static uint64_t dtrace_vtime_references;
static unsigned enables, disables, destroys;
static void dtrace_vtime_enable(void) { ++enables; }
static void dtrace_vtime_disable(void) { ++disables; }
static void dtrace_difo_destroy(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	(void)dp;
	(void)vstate;
	++destroys;
}

#include "guest-hvtime.inc"

int
main(void)
{
	dtrace_difv_t host_var[] = {{ DIF_VAR_HVTIMESTAMP }, { 99 }};
	dtrace_difv_t guest_var[] = {{ DIF_VAR_VTIMESTAMP }};
	dtrace_difo_t host = { .dtdo_varlen = 2, .dtdo_vartab = host_var };
	dtrace_difo_t guest = { .dtdo_varlen = 1, .dtdo_vartab = guest_var };
	dtrace_vstate_t vstate = {};

	/* A host-prefixed variable alone must turn accounting on. */
	dtrace_difo_hold(&host);
	assert(dtrace_vtime_references == 1 && enables == 1);
	dtrace_difo_hold(&host);
	assert(dtrace_vtime_references == 2 && enables == 1);
	dtrace_difo_hold(&guest);
	assert(dtrace_vtime_references == 3 && enables == 1);
	dtrace_difo_release(&host, &vstate);
	assert(dtrace_vtime_references == 2 && disables == 0);
	dtrace_difo_release(&guest, &vstate);
	assert(dtrace_vtime_references == 1 && disables == 0);
	dtrace_difo_release(&host, &vstate);
	assert(dtrace_vtime_references == 0 && disables == 1);
	assert(destroys == 2);
	puts("PASS: host and guest virtual-time DIFOs share balanced accounting");
	return (0);
}
