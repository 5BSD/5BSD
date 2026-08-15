/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include <dev/vmm/vmm_startup_run_request.h>

_Static_assert(sizeof(struct vmm_startup_run_request) ==
    VMM_STARTUP_RUN_REQUEST_SIZE, "startup run request size");

static bool
vmm_startup_run_request_reserved_empty(const uint8_t *reserved, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (reserved[i] != 0)
			return (false);
	}
	return (true);
}

static bool
vmm_startup_run_request_range_valid(uint64_t address, uint64_t length,
    uint64_t max_address)
{

	if (address == 0 || length == 0 || address > max_address)
		return (false);
	return (length - 1 <= max_address - address);
}

static bool
vmm_startup_run_request_ranges_overlap(uint64_t left_address,
    uint64_t left_length, uint64_t right_address, uint64_t right_length)
{

	if (left_address <= right_address)
		return (right_address - left_address < left_length);
	return (left_address - right_address < right_length);
}

int
vmm_startup_run_request_validate(
    const struct vmm_startup_run_request *request, uint32_t max_vcpus,
    uint64_t max_cpuset_size, uint64_t expected_exit_size,
    uint64_t max_address)
{

	if (request == NULL || max_vcpus == 0 || max_cpuset_size == 0 ||
	    expected_exit_size == 0 ||
	    request->version != VMM_STARTUP_RUN_REQUEST_VERSION ||
	    request->size != VMM_STARTUP_RUN_REQUEST_SIZE ||
	    request->flags != 0 || request->vcpuid < 0 ||
	    (uint32_t)request->vcpuid >= max_vcpus ||
	    request->reserved32 != 0 || request->generation == 0 ||
	    request->cpuset_size == 0 ||
	    request->cpuset_size > max_cpuset_size ||
	    request->exit_size != expected_exit_size ||
	    !vmm_startup_run_request_range_valid(request->cpuset_address,
	    request->cpuset_size, max_address) ||
	    !vmm_startup_run_request_range_valid(request->exit_address,
	    request->exit_size, max_address) ||
	    vmm_startup_run_request_ranges_overlap(request->cpuset_address,
	    request->cpuset_size, request->exit_address,
	    request->exit_size) ||
	    !vmm_startup_run_request_reserved_empty(request->reserved8,
	    sizeof(request->reserved8)))
		return (EINVAL);
	return (0);
}
