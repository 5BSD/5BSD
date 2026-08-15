/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <stdint.h>

#include <dev/vmm/vmm_dirty_log.h>

#include "vmmapi.h"

int
vm_dirty_log_result_validate(const struct vmm_dirty_log_result *result,
    size_t buffer_bytes)
{
	uint64_t bitmap_bytes, pages;
	size_t i;

	/*
	 * This is deliberately a userspace implementation of the publication
	 * contract, rather than a link-time dependency on the kernel validator.
	 * A malformed or mismatched kernel response must not be consumed merely
	 * because both sides happened to share one implementation object.
	 */
	if (result == NULL ||
	    result->version != VMM_DIRTY_LOG_RESULT_VERSION ||
	    result->size != VMM_DIRTY_LOG_RESULT_SIZE ||
	    (result->operation != VMM_DIRTY_LOG_REQUEST_OBSERVE &&
	    result->operation != VMM_DIRTY_LOG_REQUEST_CLEAR) ||
	    result->flags != 0 ||
	    result->gpa % VMM_DIRTY_LOG_GRANULARITY != 0 ||
	    result->length == 0 ||
	    result->length % VMM_DIRTY_LOG_GRANULARITY != 0 ||
	    result->gpa > UINT64_MAX - (result->length - 1) ||
	    result->identity == 0 || result->map_generation == 0 ||
	    result->dirty_generation == 0 ||
	    result->bitmap_offset != sizeof(*result))
		return (EINVAL);
	for (i = 0; i < nitems(result->reserved8); i++) {
		if (result->reserved8[i] != 0)
			return (EINVAL);
	}
	pages = result->length / VMM_DIRTY_LOG_GRANULARITY;
	bitmap_bytes = (pages + 7) / 8;
	if (result->bitmap_bytes != bitmap_bytes ||
	    bitmap_bytes > VMM_DIRTY_LOG_MAX_BITMAP_BYTES ||
	    bitmap_bytes > SIZE_MAX - sizeof(*result) ||
	    buffer_bytes != sizeof(*result) + (size_t)bitmap_bytes)
		return (EINVAL);
	return (0);
}
