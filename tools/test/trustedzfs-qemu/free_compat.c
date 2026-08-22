/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Compatibility shim for running ports packages built with C23 sized-free
 * calls on an older host userland.  This is needed only by the disposable
 * QEMU test runner; the size and alignment are allocator hints.
 */

#include <stdlib.h>

void
free_sized(void *ptr, size_t size)
{

	(void)size;
	free(ptr);
}

void
free_aligned_sized(void *ptr, size_t alignment, size_t size)
{

	(void)alignment;
	(void)size;
	free(ptr);
}
