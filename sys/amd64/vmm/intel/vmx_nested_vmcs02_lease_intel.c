/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/vm_page.h>

#include <machine/vmm.h>

#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_vm.h>

#include "vmx_nested_vmcs02_lease_intel.h"

static int
nvmx_vmcs02_lease_intel_acquire(void *arg,
    enum vmx_nested_vmcs02_lease_kind kind, uint64_t guest_address,
    uint64_t length, uint64_t alignment,
    struct vmx_nested_vmcs02_lease *lease)
{
	struct vmx_nested_vmcs02_lease_intel *runtime;
	vm_page_t page;
	void *mapping, *cookie;
	uint64_t host_address, page_offset;

	runtime = arg;
	if (runtime == NULL || runtime->vcpu == NULL || lease == NULL ||
	    kind < VMX_NESTED_VMCS02_LEASE_VIRTUAL_APIC ||
	    kind > VMX_NESTED_VMCS02_LEASE_POSTED_INTERRUPT ||
	    length == 0 || length > PAGE_SIZE || alignment == 0 ||
	    (alignment & (alignment - 1)) != 0 ||
	    (guest_address & (alignment - 1)) != 0 ||
	    guest_address > UINT64_MAX - (length - 1))
		return (EINVAL);
	page_offset = guest_address & PAGE_MASK;
	if (length > PAGE_SIZE - page_offset)
		return (EINVAL);
	if (vcpu_get_state(runtime->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);

	cookie = NULL;
	mapping = vm_gpa_hold(runtime->vcpu, guest_address, length,
	    VM_PROT_READ | VM_PROT_WRITE, &cookie);
	if (mapping == NULL)
		return (EFAULT);
	page = cookie;
	host_address = VM_PAGE_TO_PHYS(page) + page_offset;
	if ((host_address & (alignment - 1)) != 0 ||
	    host_address > UINT64_MAX - (length - 1)) {
		vm_gpa_release(cookie);
		return (EFAULT);
	}

	memset(lease, 0, sizeof(*lease));
	lease->kind = kind;
	lease->guest_address = guest_address;
	lease->host_address = host_address;
	lease->length = length;
	lease->alignment = alignment;
	lease->cookie = (uintptr_t)cookie;
	return (0);
}

static void
nvmx_vmcs02_lease_intel_release(void *arg,
    const struct vmx_nested_vmcs02_lease *lease)
{
	struct vmx_nested_vmcs02_lease_intel *runtime;

	runtime = arg;
	if (runtime == NULL || runtime->vcpu == NULL)
		panic("%s: invalid runtime", __func__);
	if (vcpu_get_state(runtime->vcpu, NULL) != VCPU_FROZEN)
		panic("%s: vCPU is not frozen", __func__);
	if (lease == NULL || lease->cookie == 0)
		panic("%s: invalid lease", __func__);
	vm_gpa_release((void *)lease->cookie);
}

static const struct vmx_nested_vmcs02_lease_ops nvmx_vmcs02_lease_intel_ops = {
	.acquire = nvmx_vmcs02_lease_intel_acquire,
	.release = nvmx_vmcs02_lease_intel_release,
};

int
vmx_nested_vmcs02_lease_intel_init(
    struct vmx_nested_vmcs02_lease_intel *runtime, struct vcpu *vcpu)
{

	if (runtime == NULL || vcpu == NULL)
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	memset(runtime, 0, sizeof(*runtime));
	runtime->vcpu = vcpu;
	return (0);
}

const struct vmx_nested_vmcs02_lease_ops *
vmx_nested_vmcs02_lease_intel_ops(void)
{

	return (&nvmx_vmcs02_lease_intel_ops);
}
