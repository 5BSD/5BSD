/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/lock.h>
#include <sys/systm.h>
#include <sys/sx.h>

#include <vm/vm.h>

#include <machine/vmm.h>

#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_vm.h>

#include "vmx_nested_instruction_runtime.h"

static struct vmx_nested_instruction_access_result
nvmx_runtime_access(enum vmx_nested_instruction_access kind, int error)
{
	struct vmx_nested_instruction_access_result result;

	memset(&result, 0, sizeof(result));
	result.kind = kind;
	result.error = error;
	return (result);
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_error(int error)
{

	if (error == EAGAIN || error == EBUSY || error == ENOMEM ||
	    error == ERESTART || error == EINTR)
		return (nvmx_runtime_access(
		    VMX_NESTED_INSTRUCTION_ACCESS_RETRY, error));
	return (nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_FATAL,
	    error == 0 ? EPROTO : error));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_fault(struct vmx_nested_instruction_runtime *runtime,
    uint64_t address)
{
	struct vmx_nested_instruction_access_result result;
	uint64_t info1, info2;

	if (vm_get_intinfo(runtime->vcpu, &info1, &info2) != 0 ||
	    (info2 & VM_INTINFO_VALID) == 0 ||
	    (info2 & VM_INTINFO_TYPE) != VM_INTINFO_HWEXCEPTION)
		return (nvmx_runtime_error(EPROTO));
	result = nvmx_runtime_access(
	    VMX_NESTED_INSTRUCTION_ACCESS_GUEST_FAULT, 0);
	result.fault.linear_address = address;
	result.fault.vector = VM_INTINFO_VECTOR(info2);
	result.fault.error_code_valid =
	    (info2 & VM_INTINFO_DEL_ERRCODE) != 0;
	if (result.fault.error_code_valid)
		result.fault.error_code = info2 >> 32;
	result.fault.injected = true;
	return (result);
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_linear(void *arg, uint64_t address, void *buffer,
    size_t length, bool write)
{
	struct vmx_nested_instruction_runtime *runtime;
	struct vm_copyinfo copyinfo[2];
	int error, fault;

	runtime = arg;
	if (runtime == NULL || buffer == NULL || length == 0 ||
	    length > 2 * sizeof(uint64_t))
		return (nvmx_runtime_error(EINVAL));
	fault = 0;
	error = vm_copy_setup(runtime->vcpu, &runtime->paging, address,
	    length, write ? VM_PROT_WRITE : VM_PROT_READ, copyinfo,
	    nitems(copyinfo), &fault);
	if (error != 0 || fault != 0) {
		vm_copy_teardown(copyinfo, nitems(copyinfo));
		if (fault != 0)
			return (nvmx_runtime_fault(runtime, address));
		return (nvmx_runtime_error(error));
	}
	if (write)
		vm_copyout(buffer, copyinfo, length);
	else
		vm_copyin(copyinfo, buffer, length);
	vm_copy_teardown(copyinfo, nitems(copyinfo));
	return (nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_OK, 0));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_linear_read(void *arg, uint64_t address, void *value,
    size_t length)
{

	return (nvmx_runtime_linear(arg, address, value, length, false));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_linear_write(void *arg, uint64_t address, const void *value,
    size_t length)
{

	/*
	 * vm_copyout() does not retain or modify the source buffer.
	 * Keep the handoff callback const-correct at its boundary.
	 */
	return (nvmx_runtime_linear(arg, address, __DECONST(void *, value),
	    length, true));
}

static void *
nvmx_runtime_revision_hold(struct vmx_nested_instruction_runtime *runtime,
    uint64_t gpa, void **cookie)
{

	*cookie = NULL;
	/*
	 * VMXON and VMCS regions have an architectural 4 KiB alignment and
	 * size.  Do not couple the guest ABI check to the host VM page size:
	 * the backing mapping may use a larger host page without changing the
	 * alignment required by the Intel VMX instruction.
	 */
	if ((gpa & (VMX_NESTED_VMCS_REGION_SIZE - 1)) != 0 ||
	    runtime->capabilities.vmcs_region_size !=
	    VMX_NESTED_VMCS_REGION_SIZE)
		return (NULL);
	return (vm_gpa_hold(runtime->vcpu, gpa, sizeof(uint32_t),
	    VM_PROT_READ,
	    cookie));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_check_region(void *arg, uint64_t gpa, bool vmxon)
{
	struct vmx_nested_instruction_runtime *runtime;
	void *cookie, *region;
	uint32_t revision;
	int error;

	runtime = arg;
	if (runtime == NULL)
		return (nvmx_runtime_error(EINVAL));
	region = nvmx_runtime_revision_hold(runtime, gpa, &cookie);
	if (region == NULL)
		return (nvmx_runtime_access(
		    VMX_NESTED_INSTRUCTION_ACCESS_INVALID_REGION, 0));
	revision = le32dec(region);
	vm_gpa_release(cookie);
	if (!vmx_nested_revision_valid(&runtime->capabilities, revision,
	    false)) {
		error = EINVAL;
	} else if (vmxon) {
		error = 0;
	} else {
		sx_xlock(runtime->vmcs_sx);
		error = vmx_nested_vmcs_registry_select(runtime->registry,
		    gpa, revision, runtime->owner);
		sx_xunlock(runtime->vmcs_sx);
	}
	if (error == EBUSY || error == ENOMEM)
		return (nvmx_runtime_error(error));
	if (error != 0)
		return (nvmx_runtime_access(
		    VMX_NESTED_INSTRUCTION_ACCESS_INVALID_REGION, 0));
	return (nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_OK, 0));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_vmxoff_release(void *arg)
{
	struct vmx_nested_instruction_runtime *runtime;
	int error;

	runtime = arg;
	if (runtime == NULL)
		return (nvmx_runtime_error(EINVAL));
	sx_xlock(runtime->vmcs_sx);
	error = vmx_nested_vmcs_registry_release(runtime->registry,
	    runtime->owner);
	sx_xunlock(runtime->vmcs_sx);
	/* VMXOFF is also valid when no VMCS is current. */
	if (error == ENOENT)
		error = 0;
	return (error == 0 ?
	    nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_OK, 0) :
	    nvmx_runtime_error(error));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_vmcs_clear(void *arg, uint64_t gpa)
{
	struct vmx_nested_instruction_runtime *runtime;
	int error;

	runtime = arg;
	if (runtime == NULL)
		return (nvmx_runtime_error(EINVAL));
	/*
	 * Intel guards implementation-defined writeback with "ensure data
	 * is in memory"; the architectural VMCLEAR can therefore succeed
	 * without ordinary RAM at the GPA.  The L0 registry is authoritative.
	 */
	sx_xlock(runtime->vmcs_sx);
	error = vmx_nested_vmcs_registry_clear(runtime->registry, gpa,
	    runtime->owner);
	sx_xunlock(runtime->vmcs_sx);
	if (error == ENOENT)
		error = 0;
	return (error == 0 ?
	    nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_OK, 0) :
	    nvmx_runtime_error(error));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_vmcs_read(void *arg, uint64_t gpa, uint32_t encoding,
    uint64_t *value)
{
	struct vmx_nested_instruction_runtime *runtime;
	int error;

	runtime = arg;
	if (runtime == NULL || value == NULL)
		return (nvmx_runtime_error(EINVAL));
	sx_slock(runtime->vmcs_sx);
	error = vmx_nested_vmcs_registry_read(runtime->registry, gpa,
	    runtime->owner, encoding, value);
	sx_sunlock(runtime->vmcs_sx);
	return (error == 0 ?
	    nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_OK, 0) :
	    nvmx_runtime_error(error));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_vmcs_write(void *arg, uint64_t gpa, uint32_t encoding,
    uint64_t value)
{
	struct vmx_nested_instruction_runtime *runtime;
	int error;

	runtime = arg;
	if (runtime == NULL)
		return (nvmx_runtime_error(EINVAL));
	sx_xlock(runtime->vmcs_sx);
	error = vmx_nested_vmcs_registry_write(runtime->registry, gpa,
	    runtime->owner, encoding, value);
	sx_xunlock(runtime->vmcs_sx);
	return (error == 0 ?
	    nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_OK, 0) :
	    nvmx_runtime_error(error));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_vmcs_launch_state(void *arg, uint64_t gpa, bool *launched,
    uint64_t *epoch)
{
	struct vmx_nested_instruction_runtime *runtime;
	int error;

	runtime = arg;
	if (runtime == NULL || launched == NULL || epoch == NULL)
		return (nvmx_runtime_error(EINVAL));
	sx_slock(runtime->vmcs_sx);
	error = vmx_nested_vmcs_registry_launched(runtime->registry, gpa,
	    runtime->owner, launched, epoch);
	sx_sunlock(runtime->vmcs_sx);
	return (error == 0 ?
	    nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_OK, 0) :
	    nvmx_runtime_error(error));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_vmcs_set_error(void *arg, uint64_t gpa, uint32_t error_code)
{
	struct vmx_nested_instruction_runtime *runtime;
	int error;

	runtime = arg;
	if (runtime == NULL)
		return (nvmx_runtime_error(EINVAL));
	sx_xlock(runtime->vmcs_sx);
	error = vmx_nested_vmcs_registry_set_instruction_error(
	    runtime->registry, gpa, runtime->owner, error_code);
	sx_xunlock(runtime->vmcs_sx);
	return (error == 0 ?
	    nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_OK, 0) :
	    nvmx_runtime_error(error));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_invept(void *arg,
    const struct vmx_nested_invalidation *invalidation)
{
	struct vmx_nested_instruction_runtime *runtime;
	int error;

	runtime = arg;
	if (runtime == NULL || runtime->ept_cache == NULL)
		return (nvmx_runtime_error(EINVAL));
	error = vmx_nested_ept_cache_invalidate(runtime->ept_cache,
	    invalidation);
	return (error == 0 ?
	    nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_OK, 0) :
	    nvmx_runtime_error(error));
}

static struct vmx_nested_instruction_access_result
nvmx_runtime_invvpid(void *arg,
    const struct vmx_nested_invalidation *invalidation)
{
	struct vmx_nested_instruction_runtime *runtime;
	struct vmx_nested_invalidation hardware;
	int error;

	runtime = arg;
	if (runtime == NULL || runtime->vpid_owner == NULL ||
	    invalidation == NULL)
		return (nvmx_runtime_error(EINVAL));

	/*
	 * VMX-instruction handling runs while the vCPU is frozen, not
	 * necessarily on the CPU that will next run VMCS02.  Record a
	 * conservative whole-effective-context invalidation and consume it
	 * only on that final pinned CPU.  When a VPID02 already exists,
	 * translate now as an ownership assertion; an INVVPID issued before
	 * the first L2 entry remains valid and acquisition supplies the
	 * destination-local target later.
	 */
	if (runtime->vpid_owner->active) {
		error = vmx_nested_invvpid_translate(invalidation,
		    runtime->vpid_owner->effective_vpid, &hardware);
		if (error != 0 ||
		    hardware.scope != VMX_NESTED_INVALIDATE_VPID_SINGLE ||
		    hardware.context !=
		    runtime->vpid_owner->effective_vpid)
			return (nvmx_runtime_error(error == 0 ? EPROTO :
			    error));
	}
	error = vmx_nested_vpid_owner_request_flush(runtime->vpid_owner);
	return (error == 0 ?
	    nvmx_runtime_access(VMX_NESTED_INSTRUCTION_ACCESS_OK, 0) :
	    nvmx_runtime_error(error));
}

static const struct vmx_nested_instruction_handoff_ops nvmx_runtime_ops = {
	.linear_read = nvmx_runtime_linear_read,
	.linear_write = nvmx_runtime_linear_write,
	.check_region = nvmx_runtime_check_region,
	.vmxoff_release = nvmx_runtime_vmxoff_release,
	.vmcs_clear = nvmx_runtime_vmcs_clear,
	.vmcs_read = nvmx_runtime_vmcs_read,
	.vmcs_write = nvmx_runtime_vmcs_write,
	.vmcs_launch_state = nvmx_runtime_vmcs_launch_state,
	.vmcs_set_error = nvmx_runtime_vmcs_set_error,
	.invept = nvmx_runtime_invept,
	.invvpid = nvmx_runtime_invvpid,
};

int
vmx_nested_instruction_runtime_init(
    struct vmx_nested_instruction_runtime *runtime, struct vcpu *vcpu,
    struct sx *vmcs_sx, struct vmx_nested_vmcs_registry *registry,
    struct vmx_nested_ept_cache *ept_cache,
    struct vmx_nested_vpid_owner *vpid_owner,
    const struct vm_guest_paging *paging,
    const struct vmx_nested_capabilities *capabilities)
{
	int state;

	if (runtime == NULL || vcpu == NULL || vmcs_sx == NULL ||
	    !lock_initialized(&vmcs_sx->lock_object) || registry == NULL ||
	    ept_cache == NULL ||
	    paging == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    paging->cpl < 0 || paging->cpl > 3 ||
	    paging->cpu_mode < CPU_MODE_REAL ||
	    paging->cpu_mode > CPU_MODE_64BIT ||
	    paging->paging_mode < PAGING_MODE_FLAT ||
	    paging->paging_mode > PAGING_MODE_64_LA57)
		return (EINVAL);
	state = vmx_nested_ept_cache_header_validate(ept_cache);
	if (state != 0)
		return (state);
	state = vmx_nested_vpid_owner_validate(vpid_owner);
	if (state != 0)
		return (state);
	state = vcpu_get_state(vcpu, NULL);
	if (state != VCPU_FROZEN)
		return (EBUSY);
	sx_xlock(vmcs_sx);
	if (!registry->initialized) {
		state = vmx_nested_vmcs_registry_init(registry, capabilities,
		    VMX_NESTED_VMCS_REGISTRY_LIMIT);
	} else {
		state = vmx_nested_capabilities_equal(
		    &registry->capabilities, capabilities) ? 0 : ESTALE;
	}
	sx_xunlock(vmcs_sx);
	if (state != 0)
		return (state);
	memset(runtime, 0, sizeof(*runtime));
	runtime->vcpu = vcpu;
	runtime->vmcs_sx = vmcs_sx;
	runtime->registry = registry;
	runtime->ept_cache = ept_cache;
	runtime->vpid_owner = vpid_owner;
	runtime->owner = vcpu_vcpuid(vcpu);
	runtime->paging = *paging;
	runtime->capabilities = *capabilities;
	return (0);
}

const struct vmx_nested_instruction_handoff_ops *
vmx_nested_instruction_runtime_ops(void)
{

	return (&nvmx_runtime_ops);
}
