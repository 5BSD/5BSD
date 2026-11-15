/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ASSERT(x) assert(x)
#define DTRACEOPT_STRSIZE 0
#define CPU_DTRACE_BADADDR 1
#define CPU_DTRACE_NOSCRATCH 2
#define CPU_DTRACE_FAULT 4
#define DTRACE_CPUFLAG_SET(bit) (flags |= (bit))
#define DTRACE_CPUFLAG_ISSET(bit) ((flags & (bit)) != 0)
#define DTRACE_INSCRATCH(m, n) \
	((m)->dtms_scratch_base + (m)->dtms_scratch_size - \
	(m)->dtms_scratch_ptr >= (n))

typedef struct { uint64_t dts_options[1]; } dtrace_state_t;
typedef struct {
	uintptr_t dtms_scratch_base;
	uintptr_t dtms_scratch_ptr;
	size_t dtms_scratch_size;
	const void *dtms_vmhdl;
} dtrace_mstate_t;
static unsigned flags, reads;
static int fault_read, race_change;
static const char guest_string[] = "guest";

static size_t
dtrace_strlen(const void *vmhdl, const char *src, size_t lim)
{
	assert(vmhdl != NULL && (uintptr_t)src == 0x1000);
	reads++;
	if (fault_read) {
		flags |= CPU_DTRACE_FAULT;
		return (0);
	}
	for (size_t i = 0; i < lim; i++)
		if (guest_string[i] == '\0')
			return (i);
	return (lim);
}

static void
dtrace_strcpy(const void *vmhdl, const void *src, void *dst, size_t len)
{
	assert(vmhdl != NULL && (uintptr_t)src == 0x1000);
	assert(len <= sizeof(guest_string));
	if (race_change)
		memset(dst, 'x', len);
	else
		memcpy(dst, guest_string, len);
}

/* FUNCTION */

int
main(void)
{
	char scratch[16] = { 0 };
	dtrace_state_t state = { .dts_options = { 8 } };
	dtrace_mstate_t mstate = {
		.dtms_scratch_base = (uintptr_t)scratch,
		.dtms_scratch_ptr = (uintptr_t)scratch,
		.dtms_scratch_size = sizeof(scratch),
		.dtms_vmhdl = &state,
	};

	assert(dtrace_dif_guest_varstr(0x1000, &state,
	    &mstate) == (uintptr_t)scratch);
	assert(strcmp(scratch, "guest") == 0 && reads == 1);
	assert(mstate.dtms_scratch_ptr == (uintptr_t)scratch + 6);
	mstate.dtms_scratch_ptr = (uintptr_t)scratch;
	race_change = 1;
	assert(dtrace_dif_guest_varstr(0x1000, &state,
	    &mstate) == (uintptr_t)scratch);
	assert(scratch[5] == '\0');
	race_change = 0;
	mstate.dtms_scratch_ptr = (uintptr_t)scratch;
	state.dts_options[0] = 4;
	assert(dtrace_dif_guest_varstr(0x1000, &state,
	    &mstate) == (uintptr_t)scratch);
	assert(strcmp(scratch, "gue") == 0);
	mstate.dtms_scratch_ptr = (uintptr_t)scratch;
	mstate.dtms_scratch_size = 3;
	flags = 0;
	assert(dtrace_dif_guest_varstr(0x1000, &state, &mstate) == 0);
	assert((flags & CPU_DTRACE_NOSCRATCH) != 0);
	mstate.dtms_scratch_size = sizeof(scratch);
	flags = 0;
	fault_read = 1;
	assert(dtrace_dif_guest_varstr(0x1000, &state, &mstate) == 0);
	assert((flags & CPU_DTRACE_FAULT) != 0);
	assert(mstate.dtms_scratch_ptr == (uintptr_t)scratch);
	fault_read = 0;
	flags = 0;
	assert(dtrace_dif_guest_varstr(0, &state, &mstate) == 0);
	mstate.dtms_vmhdl = NULL;
	assert(dtrace_dif_guest_varstr(0x1000, &state, &mstate) == 0);
	puts("PASS: production guest string copy and ownership");
	return (0);
}
