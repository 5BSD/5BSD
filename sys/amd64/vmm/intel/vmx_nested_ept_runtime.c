/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include <machine/atomic.h>
#include <machine/vmm.h>

#include <vm/vm.h>

#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_vm.h>

#include "vmx_nested_ept_root.h"
#include "vmx_nested_ept_runtime.h"

static int
nvmx_ept_runtime_load(void *arg, uint64_t gpa, uint8_t bytes[8])
{
	struct vmx_nested_ept_runtime *runtime;
	volatile uint64_t *entry;
	uint64_t value;
	void *cookie;

	runtime = arg;
	if (runtime == NULL || runtime->vcpu == NULL || bytes == NULL ||
	    (gpa & (sizeof(value) - 1)) != 0 ||
	    gpa > UINT64_MAX - (sizeof(value) - 1))
		return (EINVAL);
	if (vcpu_get_state(runtime->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	cookie = NULL;
	entry = vm_gpa_hold(runtime->vcpu, gpa, sizeof(value),
	    VM_PROT_READ, &cookie);
	if (entry == NULL)
		return (EFAULT);
	value = atomic_load_acq_64(entry);
	vm_gpa_release(cookie);
	le64enc(bytes, value);
	return (0);
}

static int
nvmx_ept_runtime_compare_exchange(void *arg, uint64_t gpa,
    const uint8_t expected_bytes[8], const uint8_t desired_bytes[8],
    uint8_t observed_bytes[8], bool *exchanged)
{
	struct vmx_nested_ept_runtime *runtime;
	volatile uint64_t *entry;
	uint64_t desired, observed;
	void *cookie;

	runtime = arg;
	if (runtime == NULL || runtime->vcpu == NULL ||
	    expected_bytes == NULL ||
	    desired_bytes == NULL || observed_bytes == NULL ||
	    exchanged == NULL || (gpa & (sizeof(observed) - 1)) != 0 ||
	    gpa > UINT64_MAX - (sizeof(observed) - 1))
		return (EINVAL);
	if (vcpu_get_state(runtime->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	observed = le64dec(expected_bytes);
	desired = le64dec(desired_bytes);
	cookie = NULL;
	entry = vm_gpa_hold(runtime->vcpu, gpa, sizeof(observed),
	    VM_PROT_READ | VM_PROT_WRITE, &cookie);
	if (entry == NULL)
		return (EFAULT);
	*exchanged = atomic_fcmpset_64(entry, &observed, desired);
	vm_gpa_release(cookie);
	le64enc(observed_bytes, observed);
	return (0);
}

static int
nvmx_ept_runtime_populate(void *arg, uint64_t l2_gpa, uint64_t l1_gpa,
    uint8_t permissions, bool mode_based_execute)
{
	struct vmx_nested_ept_runtime *runtime;

	runtime = arg;
	if (runtime == NULL || runtime->vcpu == NULL ||
	    runtime->runtime_root == NULL)
		return (EINVAL);
	if (vcpu_get_state(runtime->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	return (vmx_nested_ept_root_populate(runtime->runtime_root,
	    runtime->vcpu, l2_gpa, l1_gpa, permissions,
	    mode_based_execute));
}

static const struct vmx_nested_ept_handoff_ops nvmx_ept_runtime_ops = {
	.populate = nvmx_ept_runtime_populate,
};

int
vmx_nested_ept_runtime_init(struct vmx_nested_ept_runtime *runtime,
    struct vcpu *vcpu, void *runtime_root)
{

	if (runtime == NULL || vcpu == NULL || runtime_root == NULL)
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	memset(runtime, 0, sizeof(*runtime));
	runtime->vcpu = vcpu;
	runtime->runtime_root = runtime_root;
	runtime->memory.load = nvmx_ept_runtime_load;
	runtime->memory.compare_exchange =
	    nvmx_ept_runtime_compare_exchange;
	runtime->memory.arg = runtime;
	return (0);
}

const struct vmx_nested_ept_memory *
vmx_nested_ept_runtime_memory(
    const struct vmx_nested_ept_runtime *runtime)
{

	if (runtime == NULL || runtime->vcpu == NULL ||
	    runtime->runtime_root == NULL ||
	    runtime->memory.load != nvmx_ept_runtime_load ||
	    runtime->memory.compare_exchange !=
	    nvmx_ept_runtime_compare_exchange ||
	    runtime->memory.arg != runtime)
		return (NULL);
	return (&runtime->memory);
}

const struct vmx_nested_ept_handoff_ops *
vmx_nested_ept_runtime_ops(void)
{

	return (&nvmx_ept_runtime_ops);
}
