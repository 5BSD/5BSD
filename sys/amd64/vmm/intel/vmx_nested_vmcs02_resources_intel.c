/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/pmap.h>

struct seg_desc;
struct vmx;
struct vmx_vcpu;

#include <machine/vmm.h>

#include <dev/vmm/vmm_vm.h>

#include "vmx.h"
#include "vmx_nested_bitmap.h"
#include "vmx_nested_ept_root.h"
#include "vmx_nested_memory.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs02_lease_intel.h"
#include "vmx_nested_vmcs02_resources_intel.h"

static void
nvmx_resources_intel_clear_staging(struct vmx_vcpu *vcpu)
{

	explicit_bzero(vcpu->nested_l1_io_bitmap,
	    VMX_NESTED_IO_BITMAP_SIZE);
	explicit_bzero(vcpu->nested_l1_io_bitmap_scratch,
	    VMX_NESTED_IO_BITMAP_SIZE);
	/*
	 * VMX defines an MSR bitmap as one architectural 4 KiB region.  These
	 * buffers are VMX-private staging state, not host-page-sized scratch
	 * storage; keeping the operation tied to the wire-defined size prevents
	 * an accidental host-page dependency from leaking into the contract.
	 */
	explicit_bzero(vcpu->nested_msr_bitmap, VMX_NESTED_MSR_BITMAP_SIZE);
	explicit_bzero(vcpu->nested_l1_msr_bitmap,
	    VMX_NESTED_MSR_BITMAP_SIZE);
	explicit_bzero(vcpu->nested_msr_bitmap_scratch,
	    VMX_NESTED_MSR_BITMAP_SIZE);
}

static int
nvmx_resources_intel_acquire(struct vmx_vcpu *vcpu,
    const struct vmx_nested_vmcs02_image *image,
    const struct vmx_nested_entry_controls *entry,
    const struct vmx_nested_memory *memory,
    const struct vmx_nested_vmcs02_resources *l0_fixed,
    struct vmx_nested_vmcs02_resources *resources,
    enum vmx_nested_context_phase required_phase)
{
	struct vmx_nested_vmcs02_lease_intel lease_runtime;
	struct vmx_nested_vmcs02_resources fixed, candidate;
	void *runtime_root;
	bool ept_bound;
	int error, rollback_error;

	if (vcpu == NULL || image == NULL || entry == NULL ||
	    l0_fixed == NULL || resources == NULL || vcpu->vcpu == NULL ||
	    vcpu->vmx == NULL ||
	    vcpu->nested_msr_bitmap == NULL ||
	    vcpu->nested_l1_msr_bitmap == NULL ||
	    vcpu->nested_msr_bitmap_scratch == NULL ||
	    vcpu->nested_l1_io_bitmap == NULL ||
	    vcpu->nested_l1_io_bitmap_scratch == NULL ||
	    vcpu->vmx->msr_bitmap == NULL ||
	    l0_fixed->resource_generation != 0 ||
	    l0_fixed->ept_capability_signature != 0 ||
	    l0_fixed->eptp02 != 0 ||
	    !vmx_nested_vmcs02_id_valid(&image->id) ||
	    !vmx_nested_vmcs02_id_valid(&l0_fixed->id) ||
	    !vmx_nested_vmcs02_id_equal(&l0_fixed->id, &image->id))
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(resources, sizeof(*resources),
	    vcpu, sizeof(*vcpu)) ||
	    vmx_nested_state_ranges_overlap(resources, sizeof(*resources),
	    image, sizeof(*image)) ||
	    vmx_nested_state_ranges_overlap(resources, sizeof(*resources),
	    entry, sizeof(*entry)) ||
	    vmx_nested_state_ranges_overlap(resources, sizeof(*resources),
	    memory, memory == NULL ? 0 : sizeof(*memory)) ||
	    vmx_nested_state_ranges_overlap(resources, sizeof(*resources),
	    l0_fixed, sizeof(*l0_fixed)))
		return (EINVAL);
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	error = vmx_nested_vmcs02_lease_owner_validate(
	    &vcpu->nested_vmcs02_leases);
	if (error != 0)
		return (error);
	if (vcpu->nested_vmcs02_leases.active)
		return (EBUSY);
	error = vmx_nested_ept_binding_validate(&vcpu->nested_ept_binding);
	if (error != 0)
		return (error);
	if (vcpu->nested_ept_binding.active)
		return (EBUSY);
	if (vcpu->nested.phase != required_phase ||
	    image->id.state_generation != vcpu->nested.state_generation ||
	    image->id.execution_epoch != vcpu->nested.execution_epoch ||
	    image->id.vmcs12_gpa !=
	    vcpu->nested.machine.current_vmcs_gpa)
		return (ESTALE);

	error = vmx_nested_io_bitmap_materialize(entry->primary,
	    entry->io_bitmap_a, entry->io_bitmap_b, memory,
	    vcpu->nested_l1_io_bitmap,
	    vcpu->nested_l1_io_bitmap_scratch);
	if (error != 0) {
		/*
		 * A guest-memory read may have filled part of the scratch bitmap
		 * before reporting an error.  No VMCS02 is published on this path,
		 * but keep failed acquisitions indistinguishable from a fresh vCPU
		 * so a later retry cannot retain stale VMX-private staging data.
		 */
		nvmx_resources_intel_clear_staging(vcpu);
		return (error);
	}
	error = vmx_nested_msr_bitmap_materialize(entry->primary,
	    entry->msr_bitmap, memory, (const uint8_t *)vcpu->vmx->msr_bitmap,
	    vcpu->nested_msr_bitmap,
	    vcpu->nested_l1_msr_bitmap,
	    vcpu->nested_msr_bitmap_scratch);
	if (error != 0) {
		nvmx_resources_intel_clear_staging(vcpu);
		return (error);
	}

	fixed = *l0_fixed;
	fixed.msr_bitmap = vtophys(vcpu->nested_msr_bitmap);

	ept_bound = false;
	if (image->ept_enabled) {
		error = vmx_nested_ept_binding_bind(&vcpu->nested_ept_cache,
		    &vcpu->nested_ept_binding, &image->ept);
		if (error != 0)
			goto fail;
		ept_bound = true;
		error = vmx_nested_ept_binding_resolve(
		    &vcpu->nested_ept_cache, &vcpu->nested_ept_binding,
		    &image->ept, &runtime_root);
		if (error != 0)
			goto fail;
		fixed.ept_capability_signature =
		    image->ept.capability_signature;
		fixed.eptp02 = vmx_nested_ept_root_eptp(runtime_root);
	}

	error = vmx_nested_vmcs02_lease_intel_init(&lease_runtime,
	    vcpu->vcpu);
	if (error != 0)
		goto fail;
	error = vmx_nested_vmcs02_lease_acquire(
	    &vcpu->nested_vmcs02_leases, &image->id, entry,
	    vmx_nested_vmcs02_lease_intel_ops(), &lease_runtime, &fixed,
	    &candidate);
	if (error != 0)
		goto fail;
	*resources = candidate;
	return (0);

fail:
	if (ept_bound) {
		rollback_error = vmx_nested_ept_binding_unbind(
		    &vcpu->nested_ept_cache, &vcpu->nested_ept_binding);
		if (rollback_error != 0) {
			nvmx_resources_intel_clear_staging(vcpu);
			return (EPROTO);
		}
	}
	nvmx_resources_intel_clear_staging(vcpu);
	return (error);
}

int
vmx_nested_vmcs02_resources_intel_acquire(struct vmx_vcpu *vcpu,
    const struct vmx_nested_vmcs02_image *image,
    const struct vmx_nested_entry_controls *entry,
    const struct vmx_nested_memory *memory,
    const struct vmx_nested_vmcs02_resources *l0_fixed,
    struct vmx_nested_vmcs02_resources *resources)
{

	return (nvmx_resources_intel_acquire(vcpu, image, entry, memory,
	    l0_fixed, resources, VMX_NESTED_CONTEXT_ENTRY_PENDING));
}

int
vmx_nested_vmcs02_resources_intel_reacquire(struct vmx_vcpu *vcpu,
    const struct vmx_nested_vmcs02_image *image,
    const struct vmx_nested_entry_controls *entry,
    const struct vmx_nested_memory *memory,
    const struct vmx_nested_vmcs02_resources *l0_fixed,
    struct vmx_nested_vmcs02_resources *resources)
{

	return (nvmx_resources_intel_acquire(vcpu, image, entry, memory,
	    l0_fixed, resources, VMX_NESTED_CONTEXT_GUEST));
}

int
vmx_nested_vmcs02_resources_intel_release(struct vmx_vcpu *vcpu,
    const struct vmx_nested_vmcs02_resources *resources)
{
	struct vmx_nested_vmcs02_lease_intel lease_runtime;
	int error;

	if (vcpu == NULL || resources == NULL || vcpu->vcpu == NULL ||
	    !vmx_nested_vmcs02_id_valid(&resources->id) ||
	    resources->resource_generation == 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(resources, sizeof(*resources),
	    vcpu, sizeof(*vcpu)))
		return (EINVAL);
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN ||
	    vcpu->nested_vmcs02_intel.transaction_active ||
	    vcpu->nested_vmcs02_intel.launch.current)
		return (EBUSY);
	error = vmx_nested_vmcs02_lease_owner_validate(
	    &vcpu->nested_vmcs02_leases);
	if (error != 0)
		return (error);
	error = vmx_nested_ept_binding_validate(&vcpu->nested_ept_binding);
	if (error != 0)
		return (error);
	if (!vcpu->nested_vmcs02_leases.active)
		return (ENOENT);
	if (vcpu->nested_vmcs02_leases.active_generation !=
	    resources->resource_generation ||
	    !vmx_nested_vmcs02_id_equal(&vcpu->nested_vmcs02_leases.id,
	    &resources->id))
		return (ESTALE);
	error = vmx_nested_vmcs02_lease_intel_init(&lease_runtime,
	    vcpu->vcpu);
	if (error != 0)
		return (error);
	/*
	 * EPT cache release is the only fallible teardown operation.  Perform
	 * it before the mapping leases so a failure leaves the complete
	 * generation intact and retryable.  The generation checks above make
	 * the subsequent lease release non-failing by contract.
	 */
	if (vcpu->nested_ept_binding.active) {
		error = vmx_nested_ept_binding_unbind(
		    &vcpu->nested_ept_cache, &vcpu->nested_ept_binding);
		if (error != 0)
			return (error);
	}
	error = vmx_nested_vmcs02_lease_release(
	    &vcpu->nested_vmcs02_leases, &resources->id,
	    resources->resource_generation,
	    vmx_nested_vmcs02_lease_intel_ops(), &lease_runtime);
	if (error != 0)
		return (EPROTO);
	return (0);
}
