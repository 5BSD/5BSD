/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A failed ASSERT is a debug-kernel panic: trap it where a case expects one. */
static jmp_buf assert_trap;
static int assert_armed;
static const char *assert_text;
#define ASSERT(x) do { if (!(x)) { assert(assert_armed); \
    assert_text = #x; longjmp(assert_trap, 1); } } while (0)
/* Only the named assertion will do: say which one tripped instead. */
#define ASSERT_TRIPS(stmt, text) do { assert_armed = 1; \
    if (setjmp(assert_trap) == 0) { stmt; assert(!"ASSERT held"); } \
    if (strcmp(assert_text, text) != 0) { fprintf(stderr, \
    "tripped ASSERT(%s), not ASSERT(%s)\n", assert_text, text); abort(); } \
    assert_armed = 0; } while (0)
#define ALIGNBYTES 7
#define P2ROUNDUP(x, align) (((x) + (align) - 1) & ~((align) - 1))
typedef int64_t dtrace_optval_t;
typedef uint64_t pc_t;

#include "guest-immstack-size.inc"

int
main(void)
{
	/* Read after a call that a trapped ASSERT leaves with longjmp(). */
	static uint32_t size = 99;
	const dtrace_optval_t max_size = INT_MAX - ALIGNBYTES - 1;

	assert(dtrace_immstack_record_size(20, 64, &size) == 0 &&
	    size == 1280);
	assert(dtrace_immstack_record_size(max_size, 1, &size) == 0 &&
	    size == (uint32_t)max_size);
	assert(dtrace_immstack_record_size(1, max_size, &size) == 0 &&
	    size == (uint32_t)max_size);
	for (int64_t frames = -1; frames <= 0; ++frames) {
		size = 99;
		assert(dtrace_immstack_record_size(frames, 1, &size) == EINVAL &&
		    size == 99);
	}
	for (int64_t strsize = -1; strsize <= 0; ++strsize) {
		size = 99;
		assert(dtrace_immstack_record_size(1, strsize, &size) == EINVAL &&
		    size == 99);
	}
	size = 99;
	assert(dtrace_immstack_record_size(max_size + 1, 1, &size) == EINVAL &&
	    size == 99);
	assert(dtrace_immstack_record_size(2, max_size, &size) == EINVAL &&
	    size == 99);
	assert(dtrace_immstack_record_size(INT64_MAX, INT64_MAX, &size) ==
	    EINVAL && size == 99);
	const dtrace_optval_t max_stack_frames =
	    (INT_MAX - ALIGNBYTES - 1) / sizeof(pc_t);
	assert(dtrace_stack_record_size(20, &size) == 0 &&
	    size == 20 * sizeof(pc_t));
	assert(dtrace_stack_record_size(max_stack_frames, &size) == 0 &&
	    size == max_stack_frames * sizeof(pc_t));
	for (int64_t frames = -1; frames <= 0; ++frames) {
		size = 99;
		assert(dtrace_stack_record_size(frames, &size) == EINVAL &&
		    size == 99);
	}
	size = 99;
	assert(dtrace_stack_record_size(max_stack_frames + 1, &size) ==
	    EINVAL && size == 99);
	assert(dtrace_stack_record_size(INT64_MAX, &size) == EINVAL &&
	    size == 99);
	const dtrace_optval_t max_frames =
	    (INT_MAX - ALIGNBYTES) / sizeof(uint64_t) - 1;
	const dtrace_optval_t max_strings =
	    INT_MAX - ALIGNBYTES - 2 * sizeof(uint64_t);
	assert(dtrace_ustack_record_size(20, 64, 0, &size) == 0 &&
	    size == 232);
	assert(dtrace_ustack_record_size(1, 0, 0, &size) == 0 &&
	    size == 16);
	assert(dtrace_ustack_record_size(max_frames, 0, 0, &size) == 0 &&
	    size == INT_MAX - ALIGNBYTES);
	assert(dtrace_ustack_record_size(1, max_strings, 0, &size) == 0 &&
	    size == INT_MAX - ALIGNBYTES);
	assert(dtrace_ustack_record_size(2048, 0, 1, &size) == 0 &&
	    size == (2048 + 1) * sizeof(uint64_t));
	size = 99;
	assert(dtrace_ustack_record_size(2049, 0, 1, &size) == EINVAL &&
	    size == 99);
	assert(dtrace_ustack_record_size(2049, 0, 0, &size) == 0 &&
	    size == (2049 + 1) * sizeof(uint64_t));
	size = 99;
	assert(dtrace_ustack_record_size(0, 0, 0, &size) == EINVAL &&
	    size == 99);
	/* strsize is an unsigned record field or a non-negative option. */
	ASSERT_TRIPS(dtrace_ustack_record_size(1, -1, 0, &size),
	    "strsize >= 0");
	assert(size == 99);
	assert(dtrace_ustack_record_size(max_frames + 1, 0, 0, &size) == EINVAL &&
	    size == 99);
	assert(dtrace_ustack_record_size(1, max_strings + 1, 0, &size) == EINVAL &&
	    size == 99);
	assert(dtrace_ustack_record_size(UINT32_MAX, UINT32_MAX, 0, &size) ==
	    EINVAL && size == 99);
	puts("PASS: kernel, immediate, and user-stack sizes reject overflow");
	return (0);
}
