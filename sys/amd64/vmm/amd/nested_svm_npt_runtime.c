/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include <machine/atomic.h>
#include <machine/vmm.h>

#include <vm/vm.h>

#include <dev/vmm/vmm_vm.h>

#include "nested_svm_npt_runtime.h"

static int
svm_nested_npt_runtime_read(void *arg, uint64_t gpa, uint64_t *value)
{
	struct svm_nested_npt_runtime *runtime;
	volatile uint64_t *entry;
	void *cookie;

	runtime = arg;
	if (runtime == NULL || runtime->vcpu == NULL || value == NULL ||
	    (gpa & 7) != 0 || gpa > UINT64_MAX - 7)
		return (EINVAL);
	if (vcpu_get_state(runtime->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	cookie = NULL;
	entry = vm_gpa_hold(runtime->vcpu, gpa, sizeof(*entry),
	    VM_PROT_READ, &cookie);
	if (entry == NULL)
		return (EFAULT);
	*value = atomic_load_acq_64(entry);
	vm_gpa_release(cookie);
	return (0);
}

static int
svm_nested_npt_runtime_compare_exchange(void *arg, uint64_t gpa,
    uint64_t expected, uint64_t desired, uint64_t *observed)
{
	struct svm_nested_npt_runtime *runtime;
	volatile uint64_t *entry;
	void *cookie;

	runtime = arg;
	if (runtime == NULL || runtime->vcpu == NULL || observed == NULL ||
	    (gpa & 7) != 0 || gpa > UINT64_MAX - 7)
		return (EINVAL);
	if (vcpu_get_state(runtime->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	cookie = NULL;
	entry = vm_gpa_hold(runtime->vcpu, gpa, sizeof(*entry),
	    VM_PROT_READ | VM_PROT_WRITE, &cookie);
	if (entry == NULL)
		return (EFAULT);
	*observed = expected;
	(void)atomic_fcmpset_64(entry, observed, desired);
	vm_gpa_release(cookie);
	return (0);
}

int
svm_nested_npt_runtime_init(struct svm_nested_npt_runtime *runtime,
    struct vcpu *vcpu)
{

	if (runtime == NULL || vcpu == NULL)
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	bzero(runtime, sizeof(*runtime));
	runtime->vcpu = vcpu;
	runtime->memory.read64 = svm_nested_npt_runtime_read;
	runtime->memory.compare_exchange64 =
	    svm_nested_npt_runtime_compare_exchange;
	runtime->memory.arg = runtime;
	return (0);
}
