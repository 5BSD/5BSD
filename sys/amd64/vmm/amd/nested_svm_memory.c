/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include <vm/vm.h>

#include <machine/segments.h>
#include <machine/vmm.h>

#include <dev/vmm/vmm_vm.h>

#include "vmcb.h"
#include "nested_svm_aux.h"
#include "nested_svm_bitmap.h"
#include "nested_svm_memory.h"
#include "nested_svm_reflect.h"
#include "nested_svm_policy.h"

CTASSERT(sizeof(struct vmcb) == SVM_NESTED_PAGE_SIZE);

static int
svm_nested_bitmap_read8(void *arg, uint64_t gpa, uint8_t *value)
{
	struct vcpu *vcpu;
	const uint8_t *mapping;
	void *cookie;

	vcpu = arg;
	if (vcpu == NULL || value == NULL ||
	    vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	cookie = NULL;
	mapping = vm_gpa_hold(vcpu, gpa, 1, VM_PROT_READ, &cookie);
	if (mapping == NULL)
		return (EFAULT);
	*value = *mapping;
	vm_gpa_release(cookie);
	return (0);
}

int
svm_nested_bitmap_reader_init(struct vcpu *vcpu,
    struct svm_nested_bitmap_reader *reader)
{

	if (vcpu == NULL || reader == NULL)
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	reader->read8 = svm_nested_bitmap_read8;
	reader->arg = vcpu;
	return (0);
}

/*
 * VMRUN names a guest physical 4 KiB VMCB.  This read runs only after the
 * instruction exit has reached a frozen-vCPU stage, where vm_gpa_hold() may
 * safely pin the mapping.  Hold the backing page only long enough to obtain
 * a stable private image.  The caller must use that image for validation and
 * composition; retaining the mapping across L2 execution would allow L1 to
 * change admission inputs after validation.
 */
int
svm_nested_vmcb12_read(struct vcpu *vcpu, uint64_t gpa, uint8_t width,
    struct vmcb *destination)
{
	void *cookie, *mapping;

	if (vcpu == NULL || destination == NULL ||
	    (gpa & (SVM_NESTED_PAGE_SIZE - 1)) != 0 ||
	    !svm_nested_guest_physical_range_valid(gpa,
	    SVM_NESTED_PAGE_SIZE, width))
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	cookie = NULL;
	mapping = vm_gpa_hold(vcpu, gpa, SVM_NESTED_PAGE_SIZE, VM_PROT_READ,
	    &cookie);
	if (mapping == NULL)
		return (EFAULT);
	bcopy(mapping, destination, sizeof(*destination));
	vm_gpa_release(cookie);
	return (0);
}

int
svm_nested_vmcb12_aux_save(struct vcpu *vcpu, uint64_t gpa, uint8_t width,
    const struct vmcb *source)
{
	struct vmcb *mapping;
	void *cookie;

	if (vcpu == NULL || source == NULL ||
	    (gpa & (SVM_NESTED_PAGE_SIZE - 1)) != 0 ||
	    !svm_nested_guest_physical_range_valid(gpa,
	    SVM_NESTED_PAGE_SIZE, width))
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	cookie = NULL;
	mapping = vm_gpa_hold(vcpu, gpa, SVM_NESTED_PAGE_SIZE,
	    VM_PROT_READ | VM_PROT_WRITE, &cookie);
	if (mapping == NULL)
		return (EFAULT);
	svm_nested_vmcb_aux_copy(mapping, source);
	vm_gpa_release(cookie);
	return (0);
}

int
svm_nested_vmcb12_invalid_exit(struct vcpu *vcpu, uint64_t gpa,
    uint8_t width)
{
	struct vmcb *mapping;
	void *cookie;

	if (vcpu == NULL ||
	    (gpa & (SVM_NESTED_PAGE_SIZE - 1)) != 0 ||
	    !svm_nested_guest_physical_range_valid(gpa,
	    SVM_NESTED_PAGE_SIZE, width))
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	cookie = NULL;
	mapping = vm_gpa_hold(vcpu, gpa, SVM_NESTED_PAGE_SIZE,
	    VM_PROT_READ | VM_PROT_WRITE, &cookie);
	if (mapping == NULL)
		return (EFAULT);
	mapping->ctrl.exitcode = VMCB_EXIT_INVALID;
	mapping->ctrl.exitinfo1 = 0;
	mapping->ctrl.exitinfo2 = 0;
	mapping->ctrl.exitintinfo = 0;
	vm_gpa_release(cookie);
	return (0);
}

int
svm_nested_vmcb12_exit_write(struct vcpu *vcpu, uint64_t gpa,
    uint8_t width, const struct vmcb *source, bool l1_lbr_enabled,
    bool l1_npt_enabled)
{
	struct vmcb *mapping;
	void *cookie;

	if (vcpu == NULL || source == NULL ||
	    (gpa & (SVM_NESTED_PAGE_SIZE - 1)) != 0 ||
	    !svm_nested_guest_physical_range_valid(gpa,
	    SVM_NESTED_PAGE_SIZE, width))
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	cookie = NULL;
	mapping = vm_gpa_hold(vcpu, gpa, SVM_NESTED_PAGE_SIZE,
	    VM_PROT_READ | VM_PROT_WRITE, &cookie);
	if (mapping == NULL)
		return (EFAULT);
	svm_nested_vmcb_exit_copy(mapping, source, l1_lbr_enabled,
	    l1_npt_enabled);
	vm_gpa_release(cookie);
	return (0);
}

int
svm_nested_vmcb12_shutdown_write(struct vcpu *vcpu, uint64_t gpa,
    uint8_t width)
{
	struct vmcb *mapping;
	void *cookie;

	if (vcpu == NULL || (gpa & (SVM_NESTED_PAGE_SIZE - 1)) != 0 ||
	    !svm_nested_guest_physical_range_valid(gpa,
	    SVM_NESTED_PAGE_SIZE, width))
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	cookie = NULL;
	mapping = vm_gpa_hold(vcpu, gpa, SVM_NESTED_PAGE_SIZE,
	    VM_PROT_READ | VM_PROT_WRITE, &cookie);
	if (mapping == NULL)
		return (EFAULT);
	svm_nested_vmcb_shutdown_copy(mapping);
	vm_gpa_release(cookie);
	return (0);
}
