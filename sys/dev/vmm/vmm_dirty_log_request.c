/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include <dev/vmm/vmm_address_range.h>
#include <dev/vmm/vmm_dirty_log.h>
#include <dev/vmm/vmm_dirty_log_request.h>

static bool
vmm_dirty_log_request_reserved_empty(const uint8_t *reserved, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (reserved[i] != 0)
			return (false);
	}
	return (true);
}

int
vmm_dirty_log_request_validate(const struct vmm_dirty_log_request *request)
{
	struct vmm_dirty_log_range range;
	size_t bitmap_bytes, output_bytes;
	uint64_t last;

	if (request == NULL ||
	    request->version != VMM_DIRTY_LOG_REQUEST_VERSION ||
	    request->size != VMM_DIRTY_LOG_REQUEST_SIZE ||
	    request->operation < VMM_DIRTY_LOG_REQUEST_ENABLE ||
	    request->operation >= VMM_DIRTY_LOG_REQUEST_OPERATION_LAST ||
	    request->flags != 0 || request->reserved64[0] != 0 ||
	    request->reserved64[1] != 0 || request->reserved64[2] != 0 ||
	    !vmm_dirty_log_request_reserved_empty(request->reserved8,
	    sizeof(request->reserved8)))
		return (EINVAL);

	switch (request->operation) {
	case VMM_DIRTY_LOG_REQUEST_ENABLE:
		range = (struct vmm_dirty_log_range) {
			.gpa = request->gpa,
			.length = request->length,
		};
		if (request->output_address != 0 || request->output_bytes != 0 ||
		    vmm_dirty_log_range_validate(&range, NULL) != 0)
			return (EINVAL);
		break;
	case VMM_DIRTY_LOG_REQUEST_OBSERVE:
	case VMM_DIRTY_LOG_REQUEST_CLEAR:
		range = (struct vmm_dirty_log_range) {
			.gpa = request->gpa,
			.length = request->length,
		};
		if (request->output_address == 0 ||
		    vmm_dirty_log_range_validate(&range, &bitmap_bytes) != 0 ||
		    bitmap_bytes > VMM_DIRTY_LOG_MAX_BITMAP_BYTES ||
		    bitmap_bytes > SIZE_MAX - sizeof(struct vmm_dirty_log_result))
			return (EINVAL);
		output_bytes = sizeof(struct vmm_dirty_log_result) + bitmap_bytes;
		if (request->output_bytes != output_bytes ||
		    (uint64_t)(uintptr_t)request->output_address !=
		    request->output_address || request->output_address >
		    UINT64_MAX - (request->output_bytes - 1))
			return (EINVAL);
		last = request->output_address + request->output_bytes - 1;
		if ((uint64_t)(uintptr_t)last != last)
			return (EINVAL);
		break;
	case VMM_DIRTY_LOG_REQUEST_DISABLE:
		if (request->gpa != 0 || request->length != 0 ||
		    request->output_address != 0 || request->output_bytes != 0)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmm_dirty_log_request_output_bytes(const struct vmm_dirty_log_request *request,
    size_t *bitmap_bytes, size_t *output_bytes)
{
	struct vmm_dirty_log_range range;
	size_t bitmap, output;

	if (bitmap_bytes == NULL || output_bytes == NULL ||
	    vmm_dirty_log_request_validate(request) != 0 ||
	    (request->operation != VMM_DIRTY_LOG_REQUEST_OBSERVE &&
	    request->operation != VMM_DIRTY_LOG_REQUEST_CLEAR))
		return (EINVAL);
	range = (struct vmm_dirty_log_range) {
		.gpa = request->gpa,
		.length = request->length,
	};
	if (vmm_dirty_log_range_validate(&range, &bitmap) != 0 ||
	    bitmap > SIZE_MAX - sizeof(struct vmm_dirty_log_result))
		return (EINVAL);
	output = sizeof(struct vmm_dirty_log_result) + bitmap;
	if (request->output_bytes != output)
		return (EINVAL);
	*bitmap_bytes = bitmap;
	*output_bytes = output;
	return (0);
}

int
vmm_dirty_log_result_encode(const struct vmm_dirty_log_request *request,
    uint64_t identity, uint64_t map_generation, uint64_t dirty_generation,
    struct vmm_dirty_log_result *result)
{
	struct vmm_dirty_log_result candidate;
	size_t bitmap_bytes, output_bytes;

	if (result == NULL || identity == 0 || map_generation == 0 ||
	    dirty_generation == 0 || vmm_dirty_log_request_output_bytes(request,
	    &bitmap_bytes, &output_bytes) != 0)
		return (EINVAL);
	(void)output_bytes;
	memset(&candidate, 0, sizeof(candidate));
	candidate.version = VMM_DIRTY_LOG_RESULT_VERSION;
	candidate.size = VMM_DIRTY_LOG_RESULT_SIZE;
	candidate.operation = request->operation;
	candidate.gpa = request->gpa;
	candidate.length = request->length;
	candidate.identity = identity;
	candidate.map_generation = map_generation;
	candidate.dirty_generation = dirty_generation;
	candidate.bitmap_offset = sizeof(candidate);
	candidate.bitmap_bytes = bitmap_bytes;
	*result = candidate;
	return (0);
}

int
vmm_dirty_log_result_validate(const struct vmm_dirty_log_result *result,
    size_t buffer_bytes)
{
	struct vmm_dirty_log_range range;
	size_t bitmap_bytes;

	if (result == NULL || result->version != VMM_DIRTY_LOG_RESULT_VERSION ||
	    result->size != VMM_DIRTY_LOG_RESULT_SIZE ||
	    (result->operation != VMM_DIRTY_LOG_REQUEST_OBSERVE &&
	    result->operation != VMM_DIRTY_LOG_REQUEST_CLEAR) ||
	    result->flags != 0 || result->identity == 0 ||
	    result->map_generation == 0 || result->dirty_generation == 0 ||
	    result->bitmap_offset != sizeof(*result) ||
	    !vmm_dirty_log_request_reserved_empty(result->reserved8,
	    sizeof(result->reserved8)))
		return (EINVAL);
	range = (struct vmm_dirty_log_range) {
		.gpa = result->gpa,
		.length = result->length,
	};
	if (vmm_dirty_log_range_validate(&range, &bitmap_bytes) != 0 ||
	    bitmap_bytes != result->bitmap_bytes ||
	    bitmap_bytes > VMM_DIRTY_LOG_MAX_BITMAP_BYTES ||
	    bitmap_bytes > SIZE_MAX - sizeof(*result) ||
	    buffer_bytes != sizeof(*result) + bitmap_bytes)
		return (EINVAL);
	return (0);
}
