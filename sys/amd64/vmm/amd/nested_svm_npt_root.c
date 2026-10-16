/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_param.h>

#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_vm.h>

#include "nested_svm_npt.h"
#include "nested_svm_npt_root.h"
#include "nested_svm_npt_runtime.h"
#include "npt.h"

struct svm_nested_npt_root {
	struct vmspace *vmspace;
	pmap_t pmap;
	uint64_t n_cr3;
	uint64_t max_address;
};

static MALLOC_DEFINE(M_SVM_NESTED_NPT, "svm_nested_npt",
    "SVM nested NPT02 roots");

int
svm_nested_npt_root_create(uint64_t max_address,
    struct svm_nested_npt_root **result)
{
	struct svm_nested_npt_root *root;
	struct vmspace *vmspace;

	if (result == NULL || max_address < PAGE_SIZE ||
	    max_address > VM_MAXUSER_ADDRESS_LA48 ||
	    (max_address & PAGE_MASK) != 0)
		return (EINVAL);
	vmspace = svm_nested_npt_alloc(0, max_address);
	if (vmspace == NULL)
		return (ENOMEM);
	root = malloc(sizeof(*root), M_SVM_NESTED_NPT, M_WAITOK | M_ZERO);
	root->vmspace = vmspace;
	root->pmap = vmspace_pmap(vmspace);
	root->n_cr3 = vtophys(root->pmap->pm_pmltop);
	root->max_address = max_address;
	*result = root;
	return (0);
}

void
svm_nested_npt_root_destroy(struct svm_nested_npt_root *root)
{

	if (root == NULL)
		return;
	svm_npt_free(root->vmspace);
	free(root, M_SVM_NESTED_NPT);
}

int
svm_nested_npt_root_clear(struct svm_nested_npt_root *root)
{
	int error;

	if (root == NULL)
		return (EINVAL);
	error = vm_map_remove(&root->vmspace->vm_map, 0, root->max_address);
	return (error == KERN_SUCCESS ? 0 : vm_mmap_to_errno(error));
}

uint64_t
svm_nested_npt_root_pa(const struct svm_nested_npt_root *root)
{

	return (root == NULL ? 0 : root->n_cr3);
}

struct pmap *
svm_nested_npt_root_pmap(struct svm_nested_npt_root *root)
{

	return (root == NULL ? NULL : root->pmap);
}

int
svm_nested_npt_root_populate(struct svm_nested_npt_root *root,
    struct vcpu *vcpu, uint64_t l2_gpa, uint64_t l1_gpa,
    uint8_t permissions, uint8_t access)
{
	int access_prot, error, prot;

	if (root == NULL || vcpu == NULL ||
	    ((l2_gpa | l1_gpa) & PAGE_MASK) != 0 ||
	    l2_gpa > root->max_address - PAGE_SIZE ||
	    (permissions & SVM_NESTED_NPT_READ) == 0 ||
	    (permissions & ~(SVM_NESTED_NPT_READ |
	    SVM_NESTED_NPT_WRITE | SVM_NESTED_NPT_EXECUTE)) != 0 ||
	    (access != SVM_NESTED_NPT_READ &&
	    access != SVM_NESTED_NPT_WRITE &&
	    access != SVM_NESTED_NPT_EXECUTE) ||
	    (permissions & access) == 0)
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	prot = VM_PROT_READ;
	if ((permissions & SVM_NESTED_NPT_WRITE) != 0)
		prot |= VM_PROT_WRITE;
	if ((permissions & SVM_NESTED_NPT_EXECUTE) != 0)
		prot |= VM_PROT_EXECUTE;
	access_prot = access == SVM_NESTED_NPT_WRITE ? VM_PROT_WRITE :
	    access == SVM_NESTED_NPT_EXECUTE ? VM_PROT_EXECUTE :
	    VM_PROT_READ;

	/* Rewalked NPT12 permissions replace only this L2 page. */
	error = vm_map_remove(&root->vmspace->vm_map, l2_gpa,
	    l2_gpa + PAGE_SIZE);
	if (error != KERN_SUCCESS)
		return (vm_mmap_to_errno(error));
	error = vm_gpa_map_alias(vcpu, root->vmspace, l2_gpa, l1_gpa,
	    PAGE_SIZE, prot, access_prot, NULL);
	if (error != 0)
		return (error);
	error = vm_map_wire(&root->vmspace->vm_map, l2_gpa,
	    l2_gpa + PAGE_SIZE, VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_NOHOLES);
	if (error != KERN_SUCCESS) {
		(void)vm_map_remove(&root->vmspace->vm_map, l2_gpa,
		    l2_gpa + PAGE_SIZE);
		return (error == KERN_RESOURCE_SHORTAGE ? ENOMEM : EFAULT);
	}
	return (0);
}

int
svm_nested_npt_root_translate(struct svm_nested_npt_root *root,
    struct vcpu *vcpu, uint64_t npt12_root_gpa, uint64_t l2_gpa,
    uint8_t access, uint8_t physical_width, bool allow_1g_pages,
    bool commit_ad,
    struct svm_nested_npt_result *result)
{
	struct svm_nested_npt_runtime runtime;
	struct svm_nested_npt_walk walk;
	int error;

	if (root == NULL || vcpu == NULL || result == NULL ||
	    l2_gpa >= root->max_address)
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	error = svm_nested_npt_runtime_init(&runtime, vcpu);
	if (error != 0)
		return (error);
	bzero(&walk, sizeof(walk));
	walk.root_gpa = npt12_root_gpa;
	walk.l2_gpa = l2_gpa;
	walk.physical_width = physical_width;
	walk.access = access;
	walk.allow_1g_pages = allow_1g_pages;
	error = svm_nested_npt_walk(&walk, &runtime.memory, result);
	if (error != 0 || result->outcome != SVM_NESTED_NPT_TRANSLATED)
		return (error);
	if (!commit_ad)
		return (0);
	error = svm_nested_npt_commit_ad(result, &runtime.memory);
	return (error);
}

int
svm_nested_npt_root_resolve(struct svm_nested_npt_root *root,
    struct vcpu *vcpu, uint64_t npt12_root_gpa, uint64_t l2_gpa,
    uint8_t access, uint8_t physical_width, bool allow_1g_pages,
    struct svm_nested_npt_result *result)
{
	int error;

	error = svm_nested_npt_root_translate(root, vcpu, npt12_root_gpa,
	    l2_gpa, access, physical_width, allow_1g_pages, true, result);
	if (error != 0 || result->outcome != SVM_NESTED_NPT_TRANSLATED)
		return (error);
	/* Device addresses have no RAM alias in NPT02. */
	if (!vm_mem_allocated(vcpu, result->l1_gpa))
		return (ENXIO);
	return (svm_nested_npt_root_populate(root, vcpu,
	    l2_gpa & ~PAGE_MASK, result->l1_gpa & ~PAGE_MASK,
	    result->permissions, access));
}
