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

#include "vmx_nested_entry_runtime.h"

static bool
nvmx_entry_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id));
}

static bool
nvmx_entry_id_equal(const struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	return (nvmx_entry_id_valid(id) &&
	    vmx_nested_vmcs02_id_equal(&runtime->id, id));
}

void
vmx_nested_entry_runtime_init(struct vmx_nested_entry_runtime *runtime)
{

	if (runtime == NULL)
		return;
	memset(runtime, 0, sizeof(*runtime));
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_IDLE;
}

int
vmx_nested_entry_runtime_begin(struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_IDLE || !nvmx_entry_id_valid(id))
		return (EINVAL);
	runtime->id = *id;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_PREPARING;
	return (0);
}

int
vmx_nested_entry_runtime_resources(struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, uint64_t generation)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_PREPARING ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	if (generation == 0)
		return (EINVAL);
	runtime->resource_generation = generation;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_RESOURCES;
	return (0);
}

int
vmx_nested_entry_runtime_vmcs02(struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_MSRS ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_VMCS02;
	return (0);
}

int
vmx_nested_entry_runtime_msrs(struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, uint32_t count)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_RESOURCES ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	runtime->entry_msr_count = count;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_MSRS;
	return (0);
}

int
vmx_nested_entry_runtime_launch(struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_VMCS02 ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	/*
	 * Successful hardware entry consumes the rollback snapshot.  L2's
	 * resulting values are architectural guest state and a later nested
	 * exit reconstructs L1 through VMCS12's host-state controls.
	 */
	runtime->entry_msr_count = 0;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_GUEST;
	return (0);
}

int
vmx_nested_entry_runtime_l0_exit(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_GUEST ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_L0_EXIT;
	return (0);
}

int
vmx_nested_entry_runtime_l0_resume(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_GUEST;
	return (0);
}

static void
nvmx_entry_runtime_abort(struct vmx_nested_entry_runtime *runtime)
{
	uint32_t cleanup;

	/*
	 * Preserve the ownership fence and every outstanding obligation.
	 * ABORTED means that an architecture adapter could not prove rollback;
	 * erasing these values would make later diagnosis or explicit recovery
	 * target the wrong nested execution.
	 */
	cleanup = vmx_nested_entry_runtime_cleanup(runtime);
	if (runtime->rollback_failed)
		cleanup |= VMX_NESTED_ENTRY_CLEANUP_ROLLBACK_MSRS;
	if (cleanup == VMX_NESTED_ENTRY_CLEANUP_NONE)
		cleanup = VMX_NESTED_ENTRY_CLEANUP_CONTINUATION;
	runtime->abort_cleanup = cleanup;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_ABORTED;
	runtime->rollback_failed = true;
}

int
vmx_nested_entry_runtime_l0_abort(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	nvmx_entry_runtime_abort(runtime);
	return (0);
}

int
vmx_nested_entry_runtime_hot_entry_abort(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_GUEST ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	/*
	 * VMfail and machine check do not make VM-exit fields authoritative.
	 * Restore CPU-local state and release the live leases, but never
	 * capture or commit a nested exit from stale VMCS02 exit fields.
	 */
	runtime->abort_cleanup =
	    VMX_NESTED_ENTRY_CLEANUP_RESTORE_VMCS01 |
	    VMX_NESTED_ENTRY_CLEANUP_ROLLBACK_MSRS |
	    VMX_NESTED_ENTRY_CLEANUP_RELEASE;
	runtime->rollback_failed = true;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_ABORTED;
	return (0);
}

int
vmx_nested_entry_runtime_l0_freeze_begin(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_L0_FREEZING;
	return (0);
}

int
vmx_nested_entry_runtime_l0_freeze_complete(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_FREEZING ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	/*
	 * A successful freeze has detached all opaque leases and CPU-local
	 * state.  Only the generation-fenced architectural continuation
	 * remains.
	 */
	runtime->resource_generation = 0;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_L0_COLD;
	return (0);
}

int
vmx_nested_entry_runtime_l0_freeze_abort(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, bool rollback_complete)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_FREEZING ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	if (rollback_complete)
		runtime->state = VMX_NESTED_ENTRY_RUNTIME_L0_EXIT;
	else
		nvmx_entry_runtime_abort(runtime);
	return (0);
}

int
vmx_nested_entry_runtime_l0_thaw_begin(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_L0_THAWING;
	return (0);
}

int
vmx_nested_entry_runtime_l0_thaw_complete(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, uint64_t resource_generation)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_THAWING ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	if (resource_generation == 0)
		return (EINVAL);
	runtime->resource_generation = resource_generation;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_L0_EXIT;
	return (0);
}

int
vmx_nested_entry_runtime_l0_thaw_abort(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, bool rollback_complete)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_THAWING ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	if (rollback_complete)
		runtime->state = VMX_NESTED_ENTRY_RUNTIME_L0_COLD;
	else
		nvmx_entry_runtime_abort(runtime);
	return (0);
}

int
vmx_nested_entry_runtime_l0_refreeze(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    !nvmx_entry_id_equal(runtime, id) ||
	    runtime->resource_generation == 0 ||
	    runtime->entry_msr_count != 0 || runtime->rollback_failed)
		return (ESTALE);
	runtime->resource_generation = 0;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_L0_COLD;
	return (0);
}

int
vmx_nested_entry_runtime_l0_cold_restore(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_IDLE ||
	    !nvmx_entry_id_valid(id))
		return (EINVAL);
	runtime->id = *id;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_L0_COLD;
	return (0);
}

int
vmx_nested_entry_runtime_l0_reflect_complete(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL ||
	    (runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT &&
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_COLD) ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	vmx_nested_entry_runtime_init(runtime);
	return (0);
}

int
vmx_nested_entry_runtime_exit_captured(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL ||
	    (runtime->state != VMX_NESTED_ENTRY_RUNTIME_GUEST &&
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT) ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	/*
	 * The Intel capture operation also restores VMCS01 before returning.
	 * Resources remain owned until the value-only nested-exit transaction
	 * has committed.
	 */
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED;
	return (0);
}

int
vmx_nested_entry_runtime_synthetic_exit_captured(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_RESOURCES ||
	    !nvmx_entry_id_equal(runtime, id) ||
	    runtime->entry_msr_count != 0 || runtime->rollback_failed)
		return (ESTALE);
	/*
	 * No VMCS02 instruction or CPU-local MSR transition occurred.  Keep
	 * resource_generation intact so the ordinary reflected-exit commit
	 * releases the exact prepared transaction after VMCS12 and L1 state
	 * become visible.
	 */
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED;
	return (0);
}

int
vmx_nested_entry_runtime_l0_reflect_captured(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD;
	return (0);
}

int
vmx_nested_entry_runtime_exit_committed(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL ||
	    (runtime->state != VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED &&
	    runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD) ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	if (runtime->state == VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED)
		runtime->state = VMX_NESTED_ENTRY_RUNTIME_RESOURCES;
	else
		vmx_nested_entry_runtime_init(runtime);
	return (0);
}

int
vmx_nested_entry_runtime_exit_poison(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL ||
	    (runtime->state != VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED &&
	    runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD) ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	runtime->rollback_failed = true;
	if (runtime->state == VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED)
		runtime->state = VMX_NESTED_ENTRY_RUNTIME_RESOURCES;
	else
		runtime->state = VMX_NESTED_ENTRY_RUNTIME_ABORTED;
	return (0);
}

int
vmx_nested_entry_runtime_cancel(struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_PREPARING ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	vmx_nested_entry_runtime_init(runtime);
	return (0);
}

int
vmx_nested_entry_runtime_rollback(struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, bool succeeded)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_MSRS ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	runtime->entry_msr_count = 0;
	runtime->rollback_failed = !succeeded;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_RESOURCES;
	return (0);
}

int
vmx_nested_entry_runtime_restore_vmcs01(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_VMCS02 ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_MSRS;
	return (0);
}

int
vmx_nested_entry_runtime_vmcs02_abort(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_VMCS02 ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	nvmx_entry_runtime_abort(runtime);
	return (0);
}

int
vmx_nested_entry_runtime_release(struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{
	bool rollback_failed;

	if (runtime == NULL || runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_RESOURCES ||
	    !nvmx_entry_id_equal(runtime, id))
		return (ESTALE);
	rollback_failed = runtime->rollback_failed;
	if (rollback_failed) {
		/*
		 * Opaque resources were released, but the failed rollback
		 * remains tied to this execution identity.
		 */
		runtime->resource_generation = 0;
		runtime->entry_msr_count = 0;
		nvmx_entry_runtime_abort(runtime);
		return (EIO);
	}
	vmx_nested_entry_runtime_init(runtime);
	return (0);
}

int
vmx_nested_entry_runtime_reset(struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, bool frozen,
    bool recovery_complete)
{

	if (runtime == NULL || !frozen || !recovery_complete ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_ABORTED ||
	    !nvmx_entry_id_equal(runtime, id))
		return (EINVAL);
	vmx_nested_entry_runtime_init(runtime);
	return (0);
}

uint32_t
vmx_nested_entry_runtime_cleanup(
    const struct vmx_nested_entry_runtime *runtime)
{

	if (runtime == NULL)
		return (VMX_NESTED_ENTRY_CLEANUP_NONE);
	switch (runtime->state) {
	case VMX_NESTED_ENTRY_RUNTIME_IDLE:
		return (VMX_NESTED_ENTRY_CLEANUP_NONE);
	case VMX_NESTED_ENTRY_RUNTIME_ABORTED:
		return (runtime->abort_cleanup);
	case VMX_NESTED_ENTRY_RUNTIME_PREPARING:
		return (VMX_NESTED_ENTRY_CLEANUP_CANCEL);
	case VMX_NESTED_ENTRY_RUNTIME_RESOURCES:
		return (VMX_NESTED_ENTRY_CLEANUP_RELEASE);
	case VMX_NESTED_ENTRY_RUNTIME_MSRS:
		return (VMX_NESTED_ENTRY_CLEANUP_ROLLBACK_MSRS |
		    VMX_NESTED_ENTRY_CLEANUP_RELEASE);
	case VMX_NESTED_ENTRY_RUNTIME_VMCS02:
		return (VMX_NESTED_ENTRY_CLEANUP_RESTORE_VMCS01 |
		    VMX_NESTED_ENTRY_CLEANUP_ROLLBACK_MSRS |
		    VMX_NESTED_ENTRY_CLEANUP_RELEASE);
	case VMX_NESTED_ENTRY_RUNTIME_GUEST:
	case VMX_NESTED_ENTRY_RUNTIME_L0_EXIT:
		return (VMX_NESTED_ENTRY_CLEANUP_CAPTURE_EXIT |
		    VMX_NESTED_ENTRY_CLEANUP_COMMIT_EXIT |
		    VMX_NESTED_ENTRY_CLEANUP_RELEASE);
	case VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED:
		return (VMX_NESTED_ENTRY_CLEANUP_COMMIT_EXIT |
		    VMX_NESTED_ENTRY_CLEANUP_RELEASE);
	case VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD:
		return (VMX_NESTED_ENTRY_CLEANUP_COMMIT_EXIT);
	case VMX_NESTED_ENTRY_RUNTIME_L0_FREEZING:
	case VMX_NESTED_ENTRY_RUNTIME_L0_COLD:
	case VMX_NESTED_ENTRY_RUNTIME_L0_THAWING:
		return (VMX_NESTED_ENTRY_CLEANUP_CONTINUATION);
	}
	return (VMX_NESTED_ENTRY_CLEANUP_NONE);
}

int
vmx_nested_entry_runtime_validate(
    const struct vmx_nested_entry_runtime *runtime)
{

	if (runtime == NULL || runtime->state < VMX_NESTED_ENTRY_RUNTIME_IDLE ||
	    runtime->state > VMX_NESTED_ENTRY_RUNTIME_ABORTED)
		return (EINVAL);
	if (runtime->state == VMX_NESTED_ENTRY_RUNTIME_IDLE) {
		if (runtime->id.state_generation != 0 ||
		    runtime->id.execution_epoch != 0 ||
		    runtime->id.vmcs12_gpa != 0 ||
		    runtime->resource_generation != 0 ||
		    runtime->entry_msr_count != 0 ||
		    runtime->abort_cleanup != 0 ||
		    runtime->rollback_failed)
			return (EPROTO);
		return (0);
	}
	if (runtime->state == VMX_NESTED_ENTRY_RUNTIME_ABORTED) {
		if (!runtime->rollback_failed ||
		    !nvmx_entry_id_valid(&runtime->id) ||
		    runtime->abort_cleanup == VMX_NESTED_ENTRY_CLEANUP_NONE ||
		    (runtime->abort_cleanup &
		    ~(VMX_NESTED_ENTRY_CLEANUP_CANCEL |
		    VMX_NESTED_ENTRY_CLEANUP_ROLLBACK_MSRS |
		    VMX_NESTED_ENTRY_CLEANUP_RESTORE_VMCS01 |
		    VMX_NESTED_ENTRY_CLEANUP_RELEASE |
		    VMX_NESTED_ENTRY_CLEANUP_CAPTURE_EXIT |
		    VMX_NESTED_ENTRY_CLEANUP_COMMIT_EXIT |
		    VMX_NESTED_ENTRY_CLEANUP_CONTINUATION)) != 0)
			return (EPROTO);
		return (0);
	}
	if (runtime->abort_cleanup != 0)
		return (EPROTO);
	if (!nvmx_entry_id_valid(&runtime->id))
		return (EPROTO);
	if (runtime->state == VMX_NESTED_ENTRY_RUNTIME_PREPARING) {
		if (runtime->resource_generation != 0 ||
		    runtime->entry_msr_count != 0 ||
		    runtime->rollback_failed)
			return (EPROTO);
		return (0);
	}
	if (runtime->state == VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    runtime->state == VMX_NESTED_ENTRY_RUNTIME_L0_THAWING ||
	    runtime->state ==
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD) {
		if (runtime->resource_generation != 0 ||
		    runtime->entry_msr_count != 0 ||
		    runtime->rollback_failed)
			return (EPROTO);
		return (0);
	}
	if (runtime->resource_generation == 0)
		return (EPROTO);
	if (runtime->state != VMX_NESTED_ENTRY_RUNTIME_MSRS &&
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_VMCS02 &&
	    runtime->entry_msr_count != 0)
		return (EPROTO);
	if (runtime->rollback_failed &&
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_RESOURCES)
		return (EPROTO);
	return (0);
}
