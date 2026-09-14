/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdlib.h>

/*
 * Size and alignment are optional allocator hints.  Ordinary free preserves
 * the allocator's handling of aligned allocations and NULL pointers.
 */
void
free_sized(void *ptr, size_t size __unused)
{

	free(ptr);
}

void
free_aligned_sized(void *ptr, size_t alignment __unused, size_t size __unused)
{

	free(ptr);
}
