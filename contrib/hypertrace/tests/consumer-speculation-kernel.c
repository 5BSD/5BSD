/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>

#define DTRACEIOC_DRAINABLE 22
#define DTRACE_ACTIVITY_ACTIVE 1
struct dtrace_state { int dts_activity, dts_speculates; };
static int dtrace_lock, enters, exits;
static void mutex_enter(int *lock) { assert(lock == &dtrace_lock); enters++; }
static void mutex_exit(int *lock) { assert(lock == &dtrace_lock); exits++; }

static int
drainable(struct dtrace_state *state)
{
	int error;
	switch (DTRACEIOC_DRAINABLE) {
#include "consumer-speculation-kernel.inc"
	default:
		return (ENOTTY);
	}
}

int
main(void)
{
	struct dtrace_state state = { DTRACE_ACTIVITY_ACTIVE, 0 };
	assert(drainable(&state) == 0);
	state.dts_speculates = 1;
	assert(drainable(&state) == EOPNOTSUPP);
	state.dts_speculates = 0;
	state.dts_activity = 0;
	assert(drainable(&state) == EBUSY);
	assert(enters == 3 && exits == 3);
	return (0);
}
