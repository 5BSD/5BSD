/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <sys/smr.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_param.h>

#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_vm.h>

#include "ept.h"
#include "vmx_cpufunc.h"
#include "vmx_nested_ept.h"
#include "vmx_nested_ept_cache.h"
#include "vmx_nested_ept_root.h"
#include "vmx_nested_state_range.h"

struct vmx_nested_ept_root {
	struct vmspace *vmspace;
	pmap_t pmap;
	uint64_t eptp;
	long eptgen[MAXCPU];
	struct vmx_nested_ept_cache_key key;
};

static MALLOC_DEFINE(M_VMX_NESTED_EPT, "vmx_nested_ept",
    "VMX nested EPT02 roots");

static void
nvmx_ept_remove_partial(struct vmx_nested_ept_root *root, vm_offset_t start,
    vm_offset_t end)
{
	int error;

	error = vm_map_remove(&root->vmspace->vm_map, start, end);
	if (error != KERN_SUCCESS)
		panic("%s: cannot remove partial nested-EPT alias: %d", __func__,
		    error);
}

int
vmx_nested_ept_root_create(void *arg,
    const struct vmx_nested_ept_cache_key *key, void **result)
{
	const struct vmx_nested_ept_root_backend *backend;
	struct vmx_nested_ept_root *root;
	struct vmspace *vmspace;

	backend = arg;
	if (backend == NULL || key == NULL || result == NULL ||
	    backend->min_address >= backend->max_address ||
	    key->capability_signature == 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(result, sizeof(*result), backend,
	    sizeof(*backend)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), key,
	    sizeof(*key)))
		return (EINVAL);

	vmspace = ept_nested_vmspace_alloc(backend->min_address,
	    backend->max_address);
	if (vmspace == NULL)
		return (ENOMEM);
	root = malloc(sizeof(*root), M_VMX_NESTED_EPT, M_WAITOK | M_ZERO);
	root->vmspace = vmspace;
	root->pmap = vmspace_pmap(vmspace);
	root->eptp = eptp_without_ad(vtophys(root->pmap->pm_pmltop));
	root->key = *key;
	*result = root;
	return (0);
}

void
vmx_nested_ept_root_destroy(void *arg __unused, void *value)
{
	struct vmx_nested_ept_root *root;

	root = value;
	if (root == NULL)
		panic("%s: NULL root", __func__);
	ept_invalidate_mappings(root->eptp);
	ept_vmspace_free(root->vmspace);
	free(root, M_VMX_NESTED_EPT);
}

int
vmx_nested_ept_root_invalidate(void *arg __unused, void *value)
{
	struct vmx_nested_ept_root *root;
	int error;

	root = value;
	if (root == NULL)
		panic("%s: NULL root", __func__);
	error = vm_map_remove(&root->vmspace->vm_map,
	    vm_map_min(&root->vmspace->vm_map),
	    vm_map_max(&root->vmspace->vm_map));
	if (error != KERN_SUCCESS)
		return (vm_mmap_to_errno(error));
	ept_invalidate_mappings(root->eptp);
	return (0);
}

uint64_t
vmx_nested_ept_root_eptp(const void *value)
{
	const struct vmx_nested_ept_root *root;

	root = value;
	if (root == NULL)
		panic("%s: NULL root", __func__);
	return (root->eptp);
}

void
vmx_nested_ept_root_activate(void *value)
{
	struct vmx_nested_ept_root *root;
	long eptgen;
	int cpu;

	root = value;
	if (root == NULL)
		panic("%s: NULL root", __func__);
	cpu = curcpu;
	CPU_SET_ATOMIC(cpu, &root->pmap->pm_active);
	smr_enter(root->pmap->pm_eptsmr);
	eptgen = atomic_load_long(&root->pmap->pm_eptgen);
	if (eptgen != root->eptgen[cpu]) {
		root->eptgen[cpu] = eptgen;
		invept(INVEPT_TYPE_SINGLE_CONTEXT,
		    (struct invept_desc){ .eptp = root->eptp, ._res = 0 });
	}
}

void
vmx_nested_ept_root_deactivate(void *value)
{
	struct vmx_nested_ept_root *root;

	root = value;
	if (root == NULL)
		panic("%s: NULL root", __func__);
	smr_exit(root->pmap->pm_eptsmr);
	CPU_CLR_ATOMIC(curcpu, &root->pmap->pm_active);
}

int
vmx_nested_ept_root_populate(void *value, struct vcpu *vcpu,
    uint64_t l2_gpa, uint64_t l1_gpa, uint8_t permissions,
    bool mode_based_execute)
{
	struct vmx_nested_ept_root *root;
	int error, map_prot, prot;

	root = value;
	if (root == NULL || vcpu == NULL ||
	    ((l2_gpa | l1_gpa) & PAGE_MASK) != 0 ||
	    l2_gpa > UINT64_MAX - PAGE_SIZE ||
	    l1_gpa > UINT64_MAX - PAGE_SIZE ||
	    permissions == 0 ||
	    (permissions & ~(VMX_NESTED_EPT_ACCESS_READ |
	    VMX_NESTED_EPT_ACCESS_WRITE |
	    VMX_NESTED_EPT_ACCESS_EXECUTE |
	    VMX_NESTED_EPT_PERMISSION_USER_EXECUTE)) != 0 ||
	    (!mode_based_execute &&
	    (permissions &
	    VMX_NESTED_EPT_PERMISSION_USER_EXECUTE) != 0))
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);

	/*
	 * MBEC bit 10 aliases the amd64 pmap's PG_MANAGED software marker.
	 * Keep MBEC fail-closed until a distinct pmap representation exists;
	 * otherwise every managed EPT02 alias would become user-executable.
	 */
	if (mode_based_execute)
		return (ENOTSUP);
	prot = 0;
	if ((permissions & VMX_NESTED_EPT_ACCESS_READ) != 0)
		prot |= VM_PROT_READ;
	if ((permissions & VMX_NESTED_EPT_ACCESS_WRITE) != 0)
		prot |= VM_PROT_WRITE;
	if ((permissions & VMX_NESTED_EPT_ACCESS_EXECUTE) != 0)
		prot |= VM_PROT_EXECUTE;

	/*
	 * A repeated fault may require broader EPT12 permissions than the
	 * existing alias.  Rebuild exactly this leaf from the current walk;
	 * L1 remains responsible for issuing INVEPT after changing EPT12.
	 */
	error = vm_map_remove(&root->vmspace->vm_map, l2_gpa,
	    l2_gpa + PAGE_SIZE);
	if (error != KERN_SUCCESS)
		return (vm_mmap_to_errno(error));
	/*
	 * The common amd64 pmap path assumes executable EPT mappings and uses
	 * the host NX bit for non-executable VM mappings.  Enter a wired
	 * executable alias first, then atomically replace its architectural
	 * EPT R/W/X bits through the dedicated EPT permission interface.
	 */
	map_prot = prot | VM_PROT_EXECUTE;
	error = vm_gpa_map_alias(vcpu, root->vmspace, l2_gpa, l1_gpa,
	    PAGE_SIZE, map_prot);
	if (error != 0)
		return (error);
	error = vm_map_wire(&root->vmspace->vm_map, l2_gpa,
	    l2_gpa + PAGE_SIZE, VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_NOHOLES);
	if (error != KERN_SUCCESS) {
		nvmx_ept_remove_partial(root, l2_gpa, l2_gpa + PAGE_SIZE);
		return (error == KERN_RESOURCE_SHORTAGE ? ENOMEM : EFAULT);
	}
	error = pmap_ept_set_permissions(root->pmap, l2_gpa,
	    permissions & PMAP_EPT_PERM_MASK);
	if (error != 0) {
		nvmx_ept_remove_partial(root, l2_gpa, l2_gpa + PAGE_SIZE);
		return (error);
	}
	return (0);
}
