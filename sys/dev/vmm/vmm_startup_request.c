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

#include <dev/vmm/vmm_startup_request.h>
#include <dev/vmm/vmm_address_range.h>
#include <dev/vmm/vmm_startup_handshake.h>

_Static_assert(sizeof(struct vmm_startup_request) ==
    VMM_STARTUP_REQUEST_SIZE, "startup request size");

static bool
vmm_startup_request_reserved_empty(const uint8_t *reserved, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (reserved[i] != 0)
			return (false);
	}
	return (true);
}

static bool
vmm_startup_request_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	if (left == NULL || right == NULL || left_length == 0 ||
	    right_length == 0)
		return (false);
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
vmm_startup_request_status_valid(
    const struct vmm_startup_handshake_status *status)
{

	if (status == NULL || status->generation == 0 ||
	    status->entered_vcpus > status->expected_vcpus ||
	    status->bootstrap_entered > 1 ||
	    status->bootstrap_entered > status->entered_vcpus ||
	    status->phase >= VMM_STARTUP_HANDSHAKE_PHASE_LAST ||
	    status->reserved16 != 0 || status->reserved32 != 0 ||
	    vmm_startup_mode_validate(&status->mode) != 0)
		return (false);
	switch (status->phase) {
	case VMM_STARTUP_HANDSHAKE_OPEN:
		return (status->expected_vcpus == 0 &&
		    status->entered_vcpus == 0 &&
		    status->bootstrap_entered == 0 &&
		    status->mode.locked == 0 &&
		    status->mode.owner == VMM_STARTUP_OWNER_USERSPACE &&
		    status->mode.execution ==
		    VMM_STARTUP_EXECUTION_USERSPACE_RESUME);
	case VMM_STARTUP_HANDSHAKE_COLLECTING:
		return (status->expected_vcpus != 0 &&
		    status->mode.locked == 0 &&
		    status->mode.owner == VMM_STARTUP_OWNER_KERNEL &&
		    status->mode.execution ==
		    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT);
	case VMM_STARTUP_HANDSHAKE_COMMITTED:
		return (status->expected_vcpus != 0 &&
		    status->entered_vcpus == status->expected_vcpus &&
		    status->bootstrap_entered == 1 &&
		    status->mode.locked == 1 &&
		    status->mode.owner == VMM_STARTUP_OWNER_KERNEL &&
		    status->mode.execution ==
		    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT);
	default:
		return (false);
	}
}

static int
vmm_startup_request_status_encode_values(
    const struct vmm_startup_handshake_status *status, uint8_t *phase,
    uint8_t *owner, uint8_t *execution)
{

	switch (status->phase) {
	case VMM_STARTUP_HANDSHAKE_OPEN:
		*phase = VMM_STARTUP_REQUEST_PHASE_OPEN;
		break;
	case VMM_STARTUP_HANDSHAKE_COLLECTING:
		*phase = VMM_STARTUP_REQUEST_PHASE_COLLECTING;
		break;
	case VMM_STARTUP_HANDSHAKE_COMMITTED:
		*phase = VMM_STARTUP_REQUEST_PHASE_COMMITTED;
		break;
	default:
		return (EINVAL);
	}
	switch (status->mode.owner) {
	case VMM_STARTUP_OWNER_USERSPACE:
		*owner = VMM_STARTUP_REQUEST_OWNER_USERSPACE;
		break;
	case VMM_STARTUP_OWNER_KERNEL:
		*owner = VMM_STARTUP_REQUEST_OWNER_KERNEL;
		break;
	default:
		return (EINVAL);
	}
	switch (status->mode.execution) {
	case VMM_STARTUP_EXECUTION_USERSPACE_RESUME:
		*execution = VMM_STARTUP_REQUEST_EXECUTION_USERSPACE;
		break;
	case VMM_STARTUP_EXECUTION_PRESTARTED_WAIT:
		*execution = VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmm_startup_request_validate(const struct vmm_startup_request *request,
    uint32_t max_vcpus)
{

	if (request == NULL || max_vcpus == 0 ||
	    request->version != VMM_STARTUP_REQUEST_VERSION ||
	    request->size != VMM_STARTUP_REQUEST_SIZE ||
	    request->operation < VMM_STARTUP_REQUEST_CONFIGURE ||
	    request->operation >= VMM_STARTUP_REQUEST_OPERATION_LAST ||
	    request->flags != 0 || request->entered_vcpus != 0 ||
	    request->bootstrap_entered != 0 || request->phase != 0 ||
	    request->owner != 0 || request->execution != 0 ||
	    !vmm_startup_request_reserved_empty(request->reserved8,
	    sizeof(request->reserved8)))
		return (EINVAL);

	switch (request->operation) {
	case VMM_STARTUP_REQUEST_CONFIGURE:
		if (request->generation != 0 || request->expected_vcpus == 0 ||
		    request->expected_vcpus > max_vcpus ||
		    request->expected_vcpus > UINT16_MAX)
			return (EINVAL);
		break;
	case VMM_STARTUP_REQUEST_WAIT_READY:
	case VMM_STARTUP_REQUEST_COMMIT:
		if (request->generation == 0 || request->expected_vcpus != 0)
			return (EINVAL);
		break;
	case VMM_STARTUP_REQUEST_STATUS:
		if (request->generation != 0 || request->expected_vcpus != 0)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmm_startup_request_encode_status(const struct vmm_startup_request *request,
    uint32_t max_vcpus, const struct vmm_startup_handshake_status *status,
    struct vmm_startup_request *output)
{
	struct vmm_startup_request candidate;
	uint8_t execution, owner, phase;

	if (request == NULL || output == NULL ||
	    vmm_startup_request_validate(request, max_vcpus) != 0 ||
	    !vmm_startup_request_status_valid(status) ||
	    status->expected_vcpus > max_vcpus ||
	    (request != output && vmm_startup_request_overlap(request,
	    sizeof(*request), output, sizeof(*output))) ||
	    vmm_startup_request_overlap(status, sizeof(*status), output,
	    sizeof(*output)))
		return (EINVAL);

	if (vmm_startup_request_status_encode_values(status, &phase, &owner,
	    &execution) != 0)
		return (EINVAL);
	candidate = *request;
	candidate.generation = status->generation;
	candidate.expected_vcpus = status->expected_vcpus;
	candidate.entered_vcpus = status->entered_vcpus;
	candidate.bootstrap_entered = status->bootstrap_entered;
	candidate.phase = phase;
	candidate.owner = owner;
	candidate.execution = execution;
	memset(candidate.reserved8, 0, sizeof(candidate.reserved8));
	*output = candidate;
	return (0);
}
