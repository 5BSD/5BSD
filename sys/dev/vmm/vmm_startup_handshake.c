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

#include <dev/vmm/vmm_startup_handshake.h>
#include <dev/vmm/vmm_address_range.h>

static bool
startup_handshake_vcpu_empty(const struct vmm_startup_handshake_vcpu *vcpu)
{

	return (vcpu->owner_id == 0 && vcpu->generation == 0 &&
	    vcpu->handshake_cookie == 0 && vcpu->storage_cookie == 0 &&
	    vcpu->vcpuid == 0 && vcpu->bootstrap_processor == 0 &&
	    vcpu->entered == 0 && vcpu->reserved16 == 0);
}

static bool
startup_handshake_vcpu_bound(const struct vmm_startup_handshake *handshake,
    uint32_t vcpuid)
{
	const struct vmm_startup_handshake_vcpu *vcpu;

	vcpu = &handshake->vcpus[vcpuid];
	return (vcpu->owner_id == handshake->owner_id &&
	    vcpu->generation == handshake->generation &&
	    vcpu->handshake_cookie == (uintptr_t)handshake &&
	    vcpu->storage_cookie == (uintptr_t)vcpu &&
	    vcpu->vcpuid == vcpuid && vcpu->bootstrap_processor <= 1 &&
	    vcpu->entered <= 1 && vcpu->reserved16 == 0);
}

static bool
startup_handshake_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
startup_handshake_records_valid(
    const struct vmm_startup_handshake *handshake)
{
	size_t vcpus_length;
	uint32_t bootstrap_count, entered_count, i;

	if (handshake->expected_vcpus == 0 || handshake->vcpus == NULL ||
	    handshake->vcpus_cookie != (uintptr_t)handshake->vcpus ||
	    __builtin_mul_overflow((size_t)handshake->expected_vcpus,
	    sizeof(*handshake->vcpus), &vcpus_length) ||
	    startup_handshake_overlap(handshake, sizeof(*handshake),
	    handshake->vcpus, vcpus_length))
		return (false);
	bootstrap_count = 0;
	entered_count = 0;
	for (i = 0; i < handshake->expected_vcpus; i++) {
		if (!startup_handshake_vcpu_bound(handshake, i) ||
		    handshake->vcpus[i].bootstrap_processor >
		    handshake->vcpus[i].entered)
			return (false);
		entered_count += handshake->vcpus[i].entered;
		bootstrap_count += handshake->vcpus[i].bootstrap_processor;
	}
	return (entered_count == handshake->entered_vcpus &&
	    bootstrap_count == handshake->bootstrap_entered);
}

static void
startup_handshake_records_bind(struct vmm_startup_handshake *handshake)
{
	struct vmm_startup_handshake_vcpu *vcpu;
	uint32_t i;

	for (i = 0; i < handshake->expected_vcpus; i++) {
		vcpu = &handshake->vcpus[i];
		vcpu->owner_id = handshake->owner_id;
		vcpu->generation = handshake->generation;
		vcpu->handshake_cookie = (uintptr_t)handshake;
		vcpu->storage_cookie = (uintptr_t)vcpu;
		vcpu->vcpuid = i;
	}
}

int
vmm_startup_handshake_validate(const struct vmm_startup_handshake *handshake)
{

	if (handshake == NULL || handshake->owner_id == 0 ||
	    handshake->generation == 0 ||
	    handshake->storage_cookie != (uintptr_t)handshake ||
	    handshake->phase >= VMM_STARTUP_HANDSHAKE_PHASE_LAST ||
	    handshake->bootstrap_entered > 1 || handshake->reserved16 != 0 ||
	    handshake->reserved32 != 0 ||
	    vmm_startup_mode_validate(&handshake->mode) != 0)
		return (EINVAL);
	switch (handshake->phase) {
	case VMM_STARTUP_HANDSHAKE_OPEN:
		if (handshake->expected_vcpus != 0 ||
		    handshake->entered_vcpus != 0 ||
		    handshake->bootstrap_entered != 0 ||
		    handshake->vcpus != NULL || handshake->vcpus_cookie != 0 ||
		    handshake->mode.locked != 0 ||
		    handshake->mode.owner != VMM_STARTUP_OWNER_USERSPACE ||
		    handshake->mode.execution !=
		    VMM_STARTUP_EXECUTION_USERSPACE_RESUME)
			return (EINVAL);
		break;
	case VMM_STARTUP_HANDSHAKE_COLLECTING:
		if (!startup_handshake_records_valid(handshake) ||
		    handshake->entered_vcpus > handshake->expected_vcpus ||
		    handshake->mode.owner != VMM_STARTUP_OWNER_KERNEL ||
		    handshake->mode.execution !=
		    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT)
			return (EINVAL);
		break;
	case VMM_STARTUP_HANDSHAKE_COMMITTED:
		if (handshake->mode.locked != 1)
			return (EINVAL);
		if (handshake->mode.owner == VMM_STARTUP_OWNER_USERSPACE) {
			if (handshake->expected_vcpus != 0 ||
			    handshake->entered_vcpus != 0 ||
			    handshake->bootstrap_entered != 0 ||
			    handshake->vcpus != NULL || handshake->vcpus_cookie != 0)
				return (EINVAL);
		} else if (handshake->expected_vcpus == 0 ||
		    !startup_handshake_records_valid(handshake) ||
		    handshake->entered_vcpus != handshake->expected_vcpus ||
		    handshake->bootstrap_entered != 1) {
			return (EINVAL);
		}
		break;
	case VMM_STARTUP_HANDSHAKE_CANCELLED:
		if (handshake->expected_vcpus != 0 ||
		    handshake->entered_vcpus != 0 ||
		    handshake->bootstrap_entered != 0 ||
		    handshake->vcpus != NULL || handshake->vcpus_cookie != 0 ||
		    handshake->mode.locked != 0)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmm_startup_handshake_init(struct vmm_startup_handshake *handshake,
    uint64_t owner_id)
{
	struct vmm_startup_handshake candidate;

	if (handshake == NULL || owner_id == 0)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	vmm_startup_mode_init(&candidate.mode);
	candidate.owner_id = owner_id;
	candidate.generation = 1;
	candidate.storage_cookie = (uintptr_t)handshake;
	*handshake = candidate;
	return (0);
}

int
vmm_startup_handshake_lock_default(struct vmm_startup_handshake *handshake)
{
	struct vmm_startup_handshake candidate;
	int error;

	error = vmm_startup_handshake_validate(handshake);
	if (error != 0 || handshake->phase != VMM_STARTUP_HANDSHAKE_OPEN)
		return (error != 0 ? error : EBUSY);
	candidate = *handshake;
	candidate.storage_cookie = (uintptr_t)&candidate;
	error = vmm_startup_mode_lock(&candidate.mode);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_HANDSHAKE_COMMITTED;
	candidate.storage_cookie = (uintptr_t)handshake;
	*handshake = candidate;
	return (0);
}

int
vmm_startup_handshake_configure_kernel(
    struct vmm_startup_handshake *handshake,
    struct vmm_startup_handshake_vcpu *vcpus, uint32_t expected_vcpus)
{
	struct vmm_startup_handshake candidate;
	size_t vcpus_length;
	uint32_t i;
	int error;

	error = vmm_startup_handshake_validate(handshake);
	if (error != 0)
		return (error);
	if (vcpus == NULL || expected_vcpus == 0 ||
	    __builtin_mul_overflow((size_t)expected_vcpus, sizeof(*vcpus),
	    &vcpus_length))
		return (EINVAL);
	if (handshake->phase != VMM_STARTUP_HANDSHAKE_OPEN)
		return (EBUSY);
	if (startup_handshake_overlap(handshake, sizeof(*handshake), vcpus,
	    vcpus_length))
		return (EINVAL);
	for (i = 0; i < expected_vcpus; i++) {
		if (!startup_handshake_vcpu_empty(&vcpus[i]))
			return (EBUSY);
	}
	candidate = *handshake;
	candidate.storage_cookie = (uintptr_t)&candidate;
	error = vmm_startup_mode_configure(&candidate.mode,
	    VMM_STARTUP_OWNER_KERNEL);
	if (error == 0)
		error = vmm_startup_mode_configure_execution(&candidate.mode,
		    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT);
	if (error != 0)
		return (error);
	candidate.expected_vcpus = expected_vcpus;
	candidate.vcpus = vcpus;
	candidate.vcpus_cookie = (uintptr_t)vcpus;
	candidate.phase = VMM_STARTUP_HANDSHAKE_COLLECTING;
	candidate.storage_cookie = (uintptr_t)handshake;
	*handshake = candidate;
	startup_handshake_records_bind(handshake);
	return (0);
}

int
vmm_startup_handshake_enter(struct vmm_startup_handshake *handshake,
    uint32_t vcpuid, bool bootstrap_processor)
{
	struct vmm_startup_handshake candidate;
	struct vmm_startup_handshake_vcpu *vcpu;
	int error;

	if (handshake == NULL)
		return (EINVAL);
	error = vmm_startup_handshake_validate(handshake);
	if (error != 0)
		return (error);
	if (handshake->phase != VMM_STARTUP_HANDSHAKE_COLLECTING &&
	    handshake->phase != VMM_STARTUP_HANDSHAKE_COMMITTED)
		return (EBUSY);
	if (vcpuid >= handshake->expected_vcpus)
		return (EINVAL);
	vcpu = &handshake->vcpus[vcpuid];
	if (!startup_handshake_vcpu_bound(handshake, vcpuid) ||
	    vcpu->reserved16 != 0)
		return (EBUSY);
	/*
	 * An interrupted generation-bearing VM_RUN may retry after another vCPU
	 * committed the handshake.  Report an exact prior admission separately so
	 * the coordinator can make it successful without signaling or advancing
	 * its wait generation.  A changed BSP classification is never a retry.
	 */
	if (vcpu->entered != 0)
		return (vcpu->bootstrap_processor == bootstrap_processor ?
		    EALREADY : EBUSY);
	if (handshake->phase != VMM_STARTUP_HANDSHAKE_COLLECTING ||
	    handshake->entered_vcpus == handshake->expected_vcpus ||
	    (bootstrap_processor && handshake->bootstrap_entered != 0))
		return (EBUSY);
	candidate = *handshake;
	candidate.entered_vcpus++;
	if (bootstrap_processor)
		candidate.bootstrap_entered = 1;
	*handshake = candidate;
	vcpu->bootstrap_processor = bootstrap_processor;
	vcpu->entered = 1;
	return (0);
}

int
vmm_startup_handshake_commit(struct vmm_startup_handshake *handshake)
{
	struct vmm_startup_handshake candidate;
	uint32_t bootstrap_count, entered_count, i;
	int error;

	error = vmm_startup_handshake_validate(handshake);
	if (error != 0 || handshake->phase !=
	    VMM_STARTUP_HANDSHAKE_COLLECTING)
		return (error != 0 ? error : EBUSY);
	entered_count = 0;
	bootstrap_count = 0;
	for (i = 0; i < handshake->expected_vcpus; i++) {
		if (!startup_handshake_vcpu_bound(handshake, i))
			return (EINVAL);
		entered_count += handshake->vcpus[i].entered;
		bootstrap_count += handshake->vcpus[i].bootstrap_processor;
	}
	if (entered_count != handshake->entered_vcpus ||
	    bootstrap_count != handshake->bootstrap_entered)
		return (EINVAL);
	if (entered_count != handshake->expected_vcpus || bootstrap_count != 1)
		return (EAGAIN);
	candidate = *handshake;
	candidate.storage_cookie = (uintptr_t)&candidate;
	error = vmm_startup_mode_lock(&candidate.mode);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_HANDSHAKE_COMMITTED;
	candidate.storage_cookie = (uintptr_t)handshake;
	*handshake = candidate;
	return (0);
}

int
vmm_startup_handshake_reset_check(
    const struct vmm_startup_handshake *handshake)
{
	int error;

	error = vmm_startup_handshake_validate(handshake);
	if (error != 0)
		return (error);
	if (handshake->phase == VMM_STARTUP_HANDSHAKE_CANCELLED)
		return (ECANCELED);
	if (handshake->generation == UINT64_MAX)
		return (EOVERFLOW);
	return (0);
}

int
vmm_startup_handshake_reset(struct vmm_startup_handshake *handshake)
{
	struct vmm_startup_handshake candidate;
	struct vmm_startup_handshake_vcpu *vcpus;
	size_t vcpus_size;
	int error;

	error = vmm_startup_handshake_reset_check(handshake);
	if (error != 0)
		return (error);
	candidate = *handshake;
	candidate.generation++;
	if (candidate.mode.owner == VMM_STARTUP_OWNER_KERNEL) {
		vcpus = candidate.vcpus;
		vcpus_size = (size_t)candidate.expected_vcpus * sizeof(*vcpus);
		memset(vcpus, 0, vcpus_size);
		candidate.entered_vcpus = 0;
		candidate.bootstrap_entered = 0;
		candidate.phase = VMM_STARTUP_HANDSHAKE_COLLECTING;
		*handshake = candidate;
		startup_handshake_records_bind(handshake);
	} else {
		*handshake = candidate;
	}
	return (0);
}

int
vmm_startup_handshake_status(const struct vmm_startup_handshake *handshake,
    struct vmm_startup_handshake_status *status)
{
	struct vmm_startup_handshake_status candidate;
	size_t vcpus_size;
	int error;

	if (handshake == NULL || status == NULL ||
	    startup_handshake_overlap(handshake, sizeof(*handshake), status,
	    sizeof(*status)))
		return (EINVAL);
	error = vmm_startup_handshake_validate(handshake);
	if (error != 0)
		return (error);
	if (__builtin_mul_overflow((size_t)handshake->expected_vcpus,
	    sizeof(*handshake->vcpus), &vcpus_size) ||
	    startup_handshake_overlap(handshake->vcpus, vcpus_size, status,
	    sizeof(*status)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.mode = handshake->mode;
	candidate.generation = handshake->generation;
	candidate.expected_vcpus = handshake->expected_vcpus;
	candidate.entered_vcpus = handshake->entered_vcpus;
	candidate.bootstrap_entered = handshake->bootstrap_entered;
	candidate.phase = handshake->phase;
	*status = candidate;
	return (0);
}

static void
startup_handshake_terminate(struct vmm_startup_handshake *handshake)
{
	struct vmm_startup_handshake candidate;
	struct vmm_startup_handshake_vcpu *vcpus;
	size_t vcpus_size;

	candidate = *handshake;
	vcpus = candidate.vcpus;
	vcpus_size = (size_t)candidate.expected_vcpus * sizeof(*vcpus);
	if (candidate.generation != UINT64_MAX)
		candidate.generation++;
	candidate.vcpus = NULL;
	candidate.vcpus_cookie = 0;
	candidate.expected_vcpus = 0;
	candidate.entered_vcpus = 0;
	candidate.bootstrap_entered = 0;
	vmm_startup_mode_init(&candidate.mode);
	candidate.phase = VMM_STARTUP_HANDSHAKE_CANCELLED;
	*handshake = candidate;
	if (vcpus != NULL)
		memset(vcpus, 0, vcpus_size);
}

int
vmm_startup_handshake_cancel(struct vmm_startup_handshake *handshake)
{
	int error;

	error = vmm_startup_handshake_validate(handshake);
	if (error != 0)
		return (error);
	if (handshake->phase == VMM_STARTUP_HANDSHAKE_COMMITTED)
		return (EBUSY);
	if (handshake->mode.locked != 0)
		return (EBUSY);
	if (handshake->phase == VMM_STARTUP_HANDSHAKE_CANCELLED)
		return (0);
	startup_handshake_terminate(handshake);
	return (0);
}

int
vmm_startup_handshake_retire(struct vmm_startup_handshake *handshake)
{
	int error;

	error = vmm_startup_handshake_validate(handshake);
	if (error != 0)
		return (error);
	if (handshake->phase == VMM_STARTUP_HANDSHAKE_CANCELLED)
		return (0);
	startup_handshake_terminate(handshake);
	return (0);
}
