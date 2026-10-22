/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#define ALIGNBYTES 7
#define P2ROUNDUP(x, align) (((x) + (align) - 1) & ~((align) - 1))
typedef int64_t dtrace_optval_t;
typedef uint64_t pc_t;

#include "guest-immstack-size.inc"

int
main(void)
{
	uint32_t size = 99;
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
	assert(dtrace_ustack_record_size(1, -1, 0, &size) == EINVAL &&
	    size == 99);
	assert(dtrace_ustack_record_size(max_frames + 1, 0, 0, &size) == EINVAL &&
	    size == 99);
	assert(dtrace_ustack_record_size(1, max_strings + 1, 0, &size) == EINVAL &&
	    size == 99);
	assert(dtrace_ustack_record_size(UINT32_MAX, UINT32_MAX, 0, &size) ==
	    EINVAL && size == 99);
	puts("PASS: kernel, immediate, and user-stack sizes reject overflow");
	return (0);
}
