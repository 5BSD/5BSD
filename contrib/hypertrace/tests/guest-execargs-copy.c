/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CPU_DTRACE_BADADDR 1
#define CPU_DTRACE_NOSCRATCH 2
#define CPU_DTRACE_FAULT 4
#define DTRACE_CPUFLAG_SET(bit) (flags |= (bit))
#define DTRACE_CPUFLAG_ISSET(bit) ((flags & (bit)) != 0)
#define DTRACE_INSCRATCH(m, n) \
	((m)->dtms_scratch_base + (m)->dtms_scratch_size - \
	(m)->dtms_scratch_ptr >= (n))

typedef struct { int unused; } dtrace_state_t;
typedef struct {
	uintptr_t dtms_scratch_base;
	uintptr_t dtms_scratch_ptr;
	size_t dtms_scratch_size;
	const void *dtms_vmhdl;
} dtrace_mstate_t;
static unsigned flags, copies;
static int fault_copy;
static const char guest_string[] = { 'a', '\0', 'b', 'x' };

static void
dtrace_bcopy(const void *vmhdl, const void *src, void *dst, size_t len)
{
	copies++;
	if (fault_copy) {
		flags |= CPU_DTRACE_FAULT;
		return;
	}
	if (vmhdl != NULL) {
		assert((uintptr_t)src == 0x1000 && len == 4);
		memcpy(dst, guest_string, len);
	} else
		memcpy(dst, src, len);
}

/* FUNCTION */

int
main(void)
{
	char scratch[8] = { 0 };
	dtrace_state_t state = { 0 };
	dtrace_mstate_t mstate = {
		.dtms_scratch_base = (uintptr_t)scratch,
		.dtms_scratch_ptr = (uintptr_t)scratch,
		.dtms_scratch_size = sizeof(scratch),
		.dtms_vmhdl = &state,
	};

	assert(dtrace_dif_varstrz(mstate.dtms_vmhdl, 0x1000, 0,
	    &state, &mstate) == 0);
	assert(copies == 0 && flags == 0);
	assert(dtrace_dif_varstrz(mstate.dtms_vmhdl, UINTPTR_MAX, 2, &state,
	    &mstate) == 0);
	assert((flags & CPU_DTRACE_BADADDR) != 0 && copies == 0);
	flags = 0;
	assert(dtrace_dif_varstrz(mstate.dtms_vmhdl, 0x1000,
	    sizeof(scratch) + 1,
	    &state, &mstate) == 0);
	assert((flags & CPU_DTRACE_NOSCRATCH) != 0 && copies == 0);
	flags = 0;
	fault_copy = 1;
	assert(dtrace_dif_varstrz(mstate.dtms_vmhdl, 0x1000, 4,
	    &state, &mstate) == 0);
	assert(mstate.dtms_scratch_ptr == (uintptr_t)scratch);
	flags = 0;
	fault_copy = 0;
	assert(dtrace_dif_varstrz(mstate.dtms_vmhdl, 0x1000, 4, &state,
	    &mstate) == (uintptr_t)scratch);
	assert(memcmp(scratch, "a b", 4) == 0);
	assert(mstate.dtms_scratch_ptr == (uintptr_t)scratch + 4);
	puts("PASS: production guest execargs copy and bounds");
	return (0);
}
