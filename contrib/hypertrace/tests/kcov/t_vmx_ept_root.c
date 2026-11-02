/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for sys/amd64/vmm/intel/vmx_nested_ept_root.c compiled unmodified as
 * a kernel translation unit: the lifetime of the EPT02 vmspace that aliases
 * L1 memory for an L2 guest.
 *
 * The VM map is a model of the vm_map(9) rules this file depends on, not a
 * copy of vm_map.c:
 *  - vm_map_wire(VM_MAP_WIRE_SYSTEM) adds a system wiring to the entry;
 *  - vm_map_unwire(VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_HOLESOK) drops one per
 *    entry in the range and fails with KERN_INVALID_ARGUMENT, unwiring
 *    nothing, on an entry that is not system-wired;
 *  - vm_map_remove() on a non-kernel map runs vm_map_delete(), which sleeps
 *    in vm_map_unlock_and_wait() while an entry still holds a system wiring
 *    (sys/vm/vm_map.c, "Also wait for any system wirings to disappear on
 *    user maps").  Nothing else drops EPT02 wirings, so that sleep never
 *    ends.  The model counts it in model_sleeps instead of sleeping.
 *
 * This is the Intel twin of svm_nested_npt_root: the same sleep froze L1 on
 * AMD on its second VMRUN of L2 (2026-11-02).
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/smr.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <machine/vmm.h>

#include <dev/vmm/vmm_vm.h>

#include "khx_kern.h"

#include "../../../../sys/amd64/vmm/intel/ept.h"
#include "../../../../sys/amd64/vmm/intel/vmx_nested_ept.h"
#include "../../../../sys/amd64/vmm/intel/vmx_nested_ept_cache.h"
#include "../../../../sys/amd64/vmm/intel/vmx_nested_ept_root.h"

#define	MODEL_ENTRIES	16
#define	MINADDR		0
#define	MAXADDR		VM_MAXUSER_ADDRESS_LA48

struct model_entry {
	bool used;
	vm_offset_t start, end;
	int system_wired;
};

static struct vmspace model_vmspace;
static struct model_entry model[MODEL_ENTRIES];
static bool model_allocated;
static int model_sleeps;	/* vm_map_delete() waits that never end */
static int model_wire_error;	/* KERN_* returned by the next wire */
static int model_perm_error;	/* errno of the next permission update */
static int model_frees;
static int model_invalidations;

static bool
model_overlaps(const struct model_entry *e, vm_offset_t start, vm_offset_t end)
{
	return (e->used && e->start < end && start < e->end);
}

static int
model_count(void)
{
	int i, n;

	for (i = n = 0; i < MODEL_ENTRIES; i++)
		n += model[i].used;
	return (n);
}

static int
model_wired(void)
{
	int i, n;

	for (i = n = 0; i < MODEL_ENTRIES; i++)
		if (model[i].used)
			n += model[i].system_wired;
	return (n);
}

static void
model_reset(void)
{
	memset(model, 0, sizeof(model));
	memset(&model_vmspace, 0, sizeof(model_vmspace));
	model_allocated = false;
	model_sleeps = 0;
	model_wire_error = KERN_SUCCESS;
	model_perm_error = 0;
	model_frees = 0;
	model_invalidations = 0;
}

/* ---- the kernel interfaces vmx_nested_ept_root.c uses -------------------- */

struct vmspace *
ept_nested_vmspace_alloc(vm_offset_t min, vm_offset_t max)
{
	KHX_CHECK(!model_allocated);
	model_allocated = true;
	/* vm_map_init(): vm_map_min() is header.end, vm_map_max() start. */
	model_vmspace.vm_map.header.end = min;
	model_vmspace.vm_map.header.start = max;
	return (&model_vmspace);
}

void
ept_vmspace_free(struct vmspace *vmspace)
{
	KHX_CHECK(vmspace == &model_vmspace);
	/* vmspace_dofree(): vm_map_remove() of the whole map. */
	(void)vm_map_remove(&vmspace->vm_map, vm_map_min(&vmspace->vm_map),
	    vm_map_max(&vmspace->vm_map));
	model_allocated = false;
	model_frees++;
}

/* KLD_MODULE builds see vm_map_min()/vm_map_max() as KBI functions. */
vm_offset_t
vm_map_min_KBI(const struct vm_map *map)
{
	return (map->header.end);
}

vm_offset_t
vm_map_max_KBI(const struct vm_map *map)
{
	return (map->header.start);
}

void
ept_invalidate_mappings(u_long eptp __unused)
{
	model_invalidations++;
}

uint64_t
eptp_without_ad(uint64_t pml4)
{
	return (pml4 | 0x1e);
}

int
vm_map_remove(vm_map_t map, vm_offset_t start, vm_offset_t end)
{
	int i;

	KHX_CHECK(map == &model_vmspace.vm_map);
	for (i = 0; i < MODEL_ENTRIES; i++) {
		if (!model_overlaps(&model[i], start, end))
			continue;
		if (model[i].system_wired != 0) {
			/* vm_map_delete(): _vm_map_unlock_and_wait() forever. */
			model_sleeps++;
			return (KERN_SUCCESS);
		}
	}
	for (i = 0; i < MODEL_ENTRIES; i++)
		if (model_overlaps(&model[i], start, end))
			model[i].used = false;
	return (KERN_SUCCESS);
}

int
vm_map_unwire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags)
{
	int i;

	KHX_CHECK(map == &model_vmspace.vm_map);
	KHX_EQ(flags, VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_HOLESOK);
	for (i = 0; i < MODEL_ENTRIES; i++)
		if (model_overlaps(&model[i], start, end) &&
		    model[i].system_wired == 0)
			return (KERN_INVALID_ARGUMENT);
	for (i = 0; i < MODEL_ENTRIES; i++)
		if (model_overlaps(&model[i], start, end))
			model[i].system_wired--;
	return (KERN_SUCCESS);
}

int
vm_map_wire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags)
{
	int i;

	KHX_CHECK(map == &model_vmspace.vm_map);
	KHX_CHECK((flags & VM_MAP_WIRE_USER) == 0);	/* SYSTEM is 0 */
	if (model_wire_error != KERN_SUCCESS)
		return (model_wire_error);
	for (i = 0; i < MODEL_ENTRIES; i++)
		if (model_overlaps(&model[i], start, end))
			model[i].system_wired++;
	return (KERN_SUCCESS);
}

int
vm_gpa_map_alias(struct vcpu *vcpu __unused, struct vmspace *dst,
    vm_paddr_t dst_gpa, vm_paddr_t src_gpa __unused, size_t len, int prot,
    int required_prot __unused, int *effective)
{
	int i;

	KHX_CHECK(dst == &model_vmspace);
	for (i = 0; i < MODEL_ENTRIES; i++)
		/* vm_map_insert() refuses an occupied range. */
		if (model_overlaps(&model[i], dst_gpa, dst_gpa + len))
			return (ENOMEM);
	for (i = 0; i < MODEL_ENTRIES; i++) {
		if (model[i].used)
			continue;
		model[i] = (struct model_entry){ true, dst_gpa,
		    dst_gpa + len, 0 };
		if (effective != NULL)
			*effective = prot;
		return (0);
	}
	return (ENOMEM);
}

int
pmap_ept_set_permissions(pmap_t pmap, vm_offset_t va __unused,
    u_int permissions __unused)
{
	KHX_CHECK(pmap == vmspace_pmap(&model_vmspace));
	return (model_perm_error);
}

int
vm_mmap_to_errno(int rv)
{
	return (rv == KERN_SUCCESS ? 0 : rv == KERN_RESOURCE_SHORTAGE ?
	    ENOMEM : EINVAL);
}

enum vcpu_state
vcpu_get_state(struct vcpu *vcpu __unused, int *hostcpu __unused)
{
	return (VCPU_FROZEN);
}

/* vmx_nested_ept_root_create(): eptp from vtophys(pm_pmltop). */
vm_paddr_t
pmap_kextract(vm_offset_t va)
{
	return ((vm_paddr_t)va);
}

/* ---- cases --------------------------------------------------------------- */

#define	R	VMX_NESTED_EPT_ACCESS_READ
#define	W	VMX_NESTED_EPT_ACCESS_WRITE
#define	X	VMX_NESTED_EPT_ACCESS_EXECUTE
#define	RWX	(R | W | X)
#define	VCPU	((struct vcpu *)(uintptr_t)0x1000)

static const struct vmx_nested_ept_root_backend backend = {
	.min_address = MINADDR,
	.max_address = MAXADDR,
};

static void *
root_new(void)
{
	struct vmx_nested_ept_cache_key key;
	void *root;

	model_reset();
	memset(&key, 0, sizeof(key));
	key.capability_signature = 1;
	root = NULL;
	KHX_EQ(vmx_nested_ept_root_create(__DECONST(void *, &backend), &key,
	    &root), 0);
	KHX_CHECK(root != NULL);
	return (root);
}

static int
populate(void *root, uint64_t l2_gpa, uint64_t l1_gpa, uint8_t perms,
    uint8_t access)
{
	return (vmx_nested_ept_root_populate(root, VCPU, l2_gpa, l1_gpa, perms,
	    access, false));
}

/*
 * L2 faults pages into EPT02, then L1 changes EPT12 and invalidates (INVEPT,
 * or a memory map change).  The invalidation must not wait on the wiring.
 */
static void
case_invalidate_after_populate(void)
{
	void *root;

	khx_host_case("invalidate after populate");
	root = root_new();
	KHX_EQ(vmx_nested_ept_root_invalidate(NULL, root), 0);	/* empty */
	KHX_EQ(populate(root, 0x200000, 0x5000, RWX, X), 0);
	KHX_EQ(populate(root, 0x7000, 0x9000, RWX, W), 0);
	KHX_EQ(model_count(), 2);
	KHX_EQ(model_wired(), 2);
	KHX_EQ(vmx_nested_ept_root_invalidate(NULL, root), 0);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_count(), 0);
	KHX_EQ(model_invalidations, 2);
	/* EPT02 is reused: the next L2 run populates and invalidates again. */
	KHX_EQ(populate(root, 0x200000, 0x5000, RWX, R), 0);
	KHX_EQ(vmx_nested_ept_root_invalidate(NULL, root), 0);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_count(), 0);
	vmx_nested_ept_root_destroy(NULL, root);
	KHX_EQ(model_frees, 1);
}

/* A rewalk of one L2 page (e.g. a write after a read) replaces its alias. */
static void
case_repopulate_same_page(void)
{
	void *root;

	khx_host_case("repopulate one page");
	root = root_new();
	KHX_EQ(populate(root, 0x3000, 0x4000, R, R), 0);
	KHX_EQ(populate(root, 0x3000, 0x4000, RWX, W), 0);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_count(), 1);
	KHX_EQ(model_wired(), 1);
	vmx_nested_ept_root_destroy(NULL, root);
	KHX_EQ(model_sleeps, 0);
}

/* The EPT02 cache evicts or tears down a populated root. */
static void
case_destroy_populated(void)
{
	void *root;

	khx_host_case("destroy populated EPT02");
	root = root_new();
	KHX_EQ(populate(root, 0x1000, 0x2000, RWX, R), 0);
	KHX_EQ(populate(root, 0x3000, 0x2000, R, R), 0);
	vmx_nested_ept_root_destroy(NULL, root);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_count(), 0);
	KHX_EQ(model_frees, 1);
}

/* A failed wiring leaves no alias behind; later invalidations still work. */
static void
case_wire_failure(void)
{
	void *root;

	khx_host_case("wire failure");
	root = root_new();
	model_wire_error = KERN_RESOURCE_SHORTAGE;
	KHX_EQ(populate(root, 0x1000, 0x2000, RWX, R), ENOMEM);
	KHX_EQ(model_count(), 0);
	model_wire_error = KERN_SUCCESS;
	KHX_EQ(populate(root, 0x1000, 0x2000, RWX, R), 0);
	KHX_EQ(vmx_nested_ept_root_invalidate(NULL, root), 0);
	KHX_EQ(model_sleeps, 0);
	vmx_nested_ept_root_destroy(NULL, root);
	KHX_EQ(model_frees, 1);
}

/* A refused permission update drops the already wired alias. */
static void
case_permission_failure(void)
{
	void *root;

	khx_host_case("permission update failure");
	root = root_new();
	model_perm_error = EINVAL;
	KHX_EQ(populate(root, 0x1000, 0x2000, RWX, R), EINVAL);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_count(), 0);
	model_perm_error = 0;
	KHX_EQ(populate(root, 0x1000, 0x2000, RWX, R), 0);
	vmx_nested_ept_root_destroy(NULL, root);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_frees, 1);
}

static void
destroy_cb(void *root)
{
	vmx_nested_ept_root_destroy(NULL, root);
}

/*
 * An alias without a system wiring breaks populate's invariant.  Refusing
 * the invalidation is a recoverable error and destroy reports the broken
 * invariant; sleeping on a later alias is neither.
 */
static void
case_unwired_alias_refused(void)
{
	void *root;

	khx_host_case("unwired alias is refused, not slept on");
	root = root_new();
	KHX_EQ(populate(root, 0x1000, 0x2000, RWX, R), 0);
	KHX_EQ(vm_gpa_map_alias(VCPU, &model_vmspace, 0x8000, 0x8000,
	    PAGE_SIZE, VM_PROT_READ, VM_PROT_READ, NULL), 0);
	KHX_EQ(vmx_nested_ept_root_invalidate(NULL, root), EPROTO);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_count(), 2);
	KHX_CHECK(KHX_PANICS(destroy_cb, root));
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_frees, 0);
}

int
khx_test_main(void)
{
	khx_kern_boot();
	case_invalidate_after_populate();
	case_repopulate_same_page();
	case_destroy_populated();
	case_wire_failure();
	case_permission_failure();
	case_unwired_alias_refused();
	return (khx_host_finish("vmx_nested_ept_root"));
}
