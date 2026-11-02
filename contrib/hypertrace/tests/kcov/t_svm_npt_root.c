/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for sys/amd64/vmm/amd/nested_svm_npt_root.c compiled unmodified as a
 * kernel translation unit: the lifetime of the per-vCPU NPT02 vmspace that
 * aliases L1 memory for an L2 guest.
 *
 * The VM map is a model of the vm_map(9) rules this file depends on, not a
 * copy of vm_map.c:
 *  - vm_map_wire(VM_MAP_WIRE_SYSTEM) adds a system wiring to the entry;
 *  - vm_map_unwire(VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_HOLESOK) drops one per
 *    entry in the range and fails with KERN_INVALID_ARGUMENT on an entry
 *    that is not system-wired;
 *  - vm_map_remove() on a non-kernel map runs vm_map_delete(), which sleeps
 *    in vm_map_unlock_and_wait() while an entry still holds a system wiring
 *    (sys/vm/vm_map.c, "Also wait for any system wirings to disappear on
 *    user maps").  Nothing else drops NPT02 wirings, so that sleep never
 *    ends.  The model counts it in model_sleeps instead of sleeping.
 *
 * 2026-11-02 host run: L1 vCPU 2 slept forever in svm_nested_npt_root_clear
 * -> vm_map_remove -> vm_map_delete -> _vm_map_unlock_and_wait on L1's second
 * VMRUN of L2 and the whole L1 froze.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <machine/vmm.h>

#include <dev/vmm/vmm_vm.h>

#include "khx_kern.h"

#include "../../../../sys/amd64/vmm/amd/nested_svm_npt.h"
#include "../../../../sys/amd64/vmm/amd/nested_svm_npt_root.h"
#include "../../../../sys/amd64/vmm/amd/nested_svm_npt_runtime.h"
#include "../../../../sys/amd64/vmm/amd/npt.h"

#define	MODEL_ENTRIES	16

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
static int model_frees;

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
	model_frees = 0;
}

/* ---- the kernel interfaces nested_svm_npt_root.c uses ------------------- */

struct vmspace *
svm_nested_npt_alloc(vm_offset_t min __unused, vm_offset_t max __unused)
{
	KHX_CHECK(!model_allocated);
	model_allocated = true;
	return (&model_vmspace);
}

void
svm_npt_free(struct vmspace *vmspace)
{
	KHX_CHECK(vmspace == &model_vmspace);
	/* vmspace_dofree(): vm_map_remove() of the whole map. */
	(void)vm_map_remove(&vmspace->vm_map, 0, VM_MAXUSER_ADDRESS_LA48);
	model_allocated = false;
	model_frees++;
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
    vm_paddr_t dst_gpa, vm_paddr_t src_gpa __unused, size_t len,
    int prot __unused, int required_prot __unused, int *effective __unused)
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
		return (0);
	}
	return (ENOMEM);
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

/* svm_nested_npt_root_create(): n_cr3 = vtophys(pm_pmltop). */
vm_paddr_t
pmap_kextract(vm_offset_t va)
{
	return ((vm_paddr_t)va);
}

/* Translation is covered by svm_nested_policy_test; never reached here. */
bool
vm_mem_allocated(struct vcpu *vcpu __unused, vm_paddr_t gpa __unused)
{
	KHX_CHECK(0);
	return (false);
}

int
svm_nested_npt_runtime_init(struct svm_nested_npt_runtime *r __unused,
    struct vcpu *vcpu __unused)
{
	KHX_CHECK(0);
	return (EINVAL);
}

int
svm_nested_npt_walk(const struct svm_nested_npt_walk *w __unused,
    const struct svm_nested_npt_memory *m __unused,
    struct svm_nested_npt_result *r __unused)
{
	KHX_CHECK(0);
	return (EINVAL);
}

int
svm_nested_npt_commit_ad(const struct svm_nested_npt_result *r __unused,
    const struct svm_nested_npt_memory *m __unused)
{
	KHX_CHECK(0);
	return (EINVAL);
}

/* ---- cases --------------------------------------------------------------- */

#define	RWX	(SVM_NESTED_NPT_READ | SVM_NESTED_NPT_WRITE | \
	SVM_NESTED_NPT_EXECUTE)
#define	VCPU	((struct vcpu *)(uintptr_t)0x1000)
#define	MAXADDR	VM_MAXUSER_ADDRESS_LA48

static struct svm_nested_npt_root *
root_new(void)
{
	struct svm_nested_npt_root *root;

	model_reset();
	root = NULL;
	KHX_EQ(svm_nested_npt_root_create(MAXADDR, &root), 0);
	KHX_CHECK(root != NULL);
	return (root);
}

/*
 * L1's first VMRUN creates NPT02, L2 faults a page in, L2 exits to L1 and
 * L1's second VMRUN clears NPT02.  The clear must not wait on the wiring.
 */
static void
case_clear_after_populate(void)
{
	struct svm_nested_npt_root *root;

	khx_host_case("clear after populate (second L1 VMRUN)");
	root = root_new();
	KHX_EQ(svm_nested_npt_root_clear(root), 0);	/* first VMRUN: empty */
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, 0x200000, 0x5000,
	    RWX, SVM_NESTED_NPT_EXECUTE), 0);
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, 0x7000, 0x9000,
	    RWX, SVM_NESTED_NPT_WRITE), 0);
	KHX_EQ(model_count(), 2);
	KHX_EQ(model_wired(), 2);
	KHX_EQ(svm_nested_npt_root_clear(root), 0);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_count(), 0);
	/* NPT02 is reused: the next L2 run populates and clears again. */
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, 0x200000, 0x5000,
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(svm_nested_npt_root_clear(root), 0);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_count(), 0);
	svm_nested_npt_root_destroy(root);
	KHX_EQ(model_frees, 1);
}

/* A rewalk of one L2 page (e.g. a write after a read) replaces its alias. */
static void
case_repopulate_same_page(void)
{
	struct svm_nested_npt_root *root;

	khx_host_case("repopulate one page");
	root = root_new();
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, 0x3000, 0x4000,
	    SVM_NESTED_NPT_READ, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, 0x3000, 0x4000,
	    RWX, SVM_NESTED_NPT_WRITE), 0);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_count(), 1);
	KHX_EQ(model_wired(), 1);
	svm_nested_npt_root_destroy(root);
	KHX_EQ(model_sleeps, 0);
}

/* L1 teardown (vCPU cleanup, INIT, restore) frees a populated NPT02. */
static void
case_destroy_populated(void)
{
	struct svm_nested_npt_root *root;

	khx_host_case("destroy populated NPT02");
	root = root_new();
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, 0x1000, 0x2000,
	    RWX, SVM_NESTED_NPT_READ), 0);
	svm_nested_npt_root_destroy(root);
	KHX_EQ(model_sleeps, 0);
	KHX_EQ(model_count(), 0);
	KHX_EQ(model_frees, 1);
}

/* A failed wiring leaves no alias behind; later clears still work. */
static void
case_wire_failure(void)
{
	struct svm_nested_npt_root *root;

	khx_host_case("wire failure");
	root = root_new();
	model_wire_error = KERN_RESOURCE_SHORTAGE;
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, 0x1000, 0x2000,
	    RWX, SVM_NESTED_NPT_READ), ENOMEM);
	KHX_EQ(model_count(), 0);
	model_wire_error = KERN_SUCCESS;
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, 0x1000, 0x2000,
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(svm_nested_npt_root_clear(root), 0);
	KHX_EQ(model_sleeps, 0);
	svm_nested_npt_root_destroy(root);
}

/*
 * An alias without a system wiring breaks populate's invariant.  Refusing
 * the clear is a recoverable error; sleeping on a later alias is not.
 */
static void
case_unwired_alias_refused(void)
{
	struct svm_nested_npt_root *root;

	khx_host_case("unwired alias is refused, not slept on");
	root = root_new();
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, 0x1000, 0x2000,
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(vm_gpa_map_alias(VCPU, &model_vmspace, 0x8000, 0x8000,
	    PAGE_SIZE, VM_PROT_READ, VM_PROT_READ, NULL), 0);
	KHX_EQ(svm_nested_npt_root_clear(root), EPROTO);
	KHX_EQ(model_sleeps, 0);
}

int
khx_test_main(void)
{
	khx_kern_boot();
	case_clear_after_populate();
	case_repopulate_same_page();
	case_destroy_populated();
	case_wire_failure();
	case_unwired_alias_refused();
	return (khx_host_finish("svm_nested_npt_root"));
}
