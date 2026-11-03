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
#include "../../../../sys/amd64/vmm/amd/vmcb.h"

#define	MODEL_ENTRIES	16
#define	NPT12_D		(1ULL << 6)	/* NPT12 leaf dirty bit */

struct model_entry {
	bool used;
	vm_offset_t start, end;
	int system_wired;
	int prot;
	struct vmspace *vs;	/* the NPT02 holding the alias */
};

/* One NPT02 per L1 vCPU; two model L1 vCPUs that share an NPT12. */
static struct vmspace model_vmspaces[2];
static struct model_entry model[MODEL_ENTRIES];
static bool model_allocated[nitems(model_vmspaces)];
static int model_maps;		/* aliases inserted: one per NPT02 fill */
/* What the NPT12 walk of the next resolve returns. */
static struct svm_nested_npt_result model_walk;
static int model_sleeps;	/* vm_map_delete() waits that never end */
static int model_wire_error;	/* KERN_* returned by the next wire */
static int model_frees;

static bool
model_overlaps(const struct model_entry *e, const struct vmspace *vs,
    vm_offset_t start, vm_offset_t end)
{
	return (e->used && e->vs == vs && e->start < end && start < e->end);
}

/* The model NPT02 whose map this is. */
static struct vmspace *
model_space(vm_map_t map)
{
	u_int i;

	for (i = 0; i < nitems(model_vmspaces); i++)
		if (map == &model_vmspaces[i].vm_map)
			return (&model_vmspaces[i]);
	KHX_CHECK(false);
	return (NULL);
}

/* Aliases in one NPT02. */
static int
model_count_in(const struct vmspace *vs)
{
	int i, n;

	for (i = n = 0; i < MODEL_ENTRIES; i++)
		n += model[i].used && model[i].vs == vs;
	return (n);
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
	memset(model_vmspaces, 0, sizeof(model_vmspaces));
	memset(model_allocated, 0, sizeof(model_allocated));
	model_sleeps = 0;
	model_wire_error = KERN_SUCCESS;
	model_frees = 0;
	model_maps = 0;
	memset(&model_walk, 0, sizeof(model_walk));
}

/* ---- the kernel interfaces nested_svm_npt_root.c uses ------------------- */

struct vmspace *
svm_nested_npt_alloc(vm_offset_t min __unused, vm_offset_t max __unused)
{
	u_int i;

	for (i = 0; i < nitems(model_vmspaces); i++) {
		if (model_allocated[i])
			continue;
		model_allocated[i] = true;
		return (&model_vmspaces[i]);
	}
	KHX_CHECK(false);
	return (NULL);
}

void
svm_npt_free(struct vmspace *vmspace)
{
	struct vmspace *vs;

	vs = model_space(&vmspace->vm_map);
	/* vmspace_dofree(): vm_map_remove() of the whole map. */
	(void)vm_map_remove(&vs->vm_map, 0, VM_MAXUSER_ADDRESS_LA48);
	model_allocated[vs - model_vmspaces] = false;
	model_frees++;
}

int
vm_map_remove(vm_map_t map, vm_offset_t start, vm_offset_t end)
{
	struct vmspace *vs;
	int i;

	vs = model_space(map);
	for (i = 0; i < MODEL_ENTRIES; i++) {
		if (!model_overlaps(&model[i], vs, start, end))
			continue;
		if (model[i].system_wired != 0) {
			/* vm_map_delete(): _vm_map_unlock_and_wait() forever. */
			model_sleeps++;
			return (KERN_SUCCESS);
		}
	}
	for (i = 0; i < MODEL_ENTRIES; i++)
		if (model_overlaps(&model[i], vs, start, end))
			model[i].used = false;
	return (KERN_SUCCESS);
}

int
vm_map_unwire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags)
{
	struct vmspace *vs;
	int i;

	vs = model_space(map);
	KHX_EQ(flags, VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_HOLESOK);
	for (i = 0; i < MODEL_ENTRIES; i++)
		if (model_overlaps(&model[i], vs, start, end) &&
		    model[i].system_wired == 0)
			return (KERN_INVALID_ARGUMENT);
	for (i = 0; i < MODEL_ENTRIES; i++)
		if (model_overlaps(&model[i], vs, start, end))
			model[i].system_wired--;
	return (KERN_SUCCESS);
}

int
vm_map_wire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags)
{
	struct vmspace *vs;
	int i;

	vs = model_space(map);
	KHX_CHECK((flags & VM_MAP_WIRE_USER) == 0);	/* SYSTEM is 0 */
	if (model_wire_error != KERN_SUCCESS)
		return (model_wire_error);
	for (i = 0; i < MODEL_ENTRIES; i++)
		if (model_overlaps(&model[i], vs, start, end))
			model[i].system_wired++;
	return (KERN_SUCCESS);
}

int
vm_gpa_map_alias(struct vcpu *vcpu __unused, struct vmspace *dst,
    vm_paddr_t dst_gpa, vm_paddr_t src_gpa __unused, size_t len,
    int prot, int required_prot __unused, int *effective __unused)
{
	struct vmspace *vs;
	int i;

	vs = model_space(&dst->vm_map);
	for (i = 0; i < MODEL_ENTRIES; i++)
		/* vm_map_insert() refuses an occupied range. */
		if (model_overlaps(&model[i], vs, dst_gpa, dst_gpa + len))
			return (ENOMEM);
	for (i = 0; i < MODEL_ENTRIES; i++) {
		if (model[i].used)
			continue;
		model[i] = (struct model_entry){ true, dst_gpa,
		    dst_gpa + len, 0, prot, vs };
		model_maps++;
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

/*
 * The NPT12 walk itself is covered by svm_nested_policy_test; here it returns
 * model_walk so resolve's use of the result can be checked.
 */
bool
vm_mem_allocated(struct vcpu *vcpu __unused, vm_paddr_t gpa __unused)
{
	return (true);
}

int
svm_nested_npt_runtime_init(struct svm_nested_npt_runtime *r __unused,
    struct vcpu *vcpu __unused)
{
	return (0);
}

int
svm_nested_npt_walk(const struct svm_nested_npt_walk *w,
    const struct svm_nested_npt_memory *m __unused,
    struct svm_nested_npt_result *r)
{
	*r = model_walk;
	r->l1_gpa |= w->l2_gpa & PAGE_MASK;
	return (0);
}

int
svm_nested_npt_commit_ad(const struct svm_nested_npt_result *r __unused,
    const struct svm_nested_npt_memory *m __unused)
{
	return (0);
}

/* nested_svm_npt.c: leaf D set or about to be committed. */
bool
svm_nested_npt_result_dirty(const struct svm_nested_npt_result *r)
{
	return ((r->ad_desired[r->count - 1] & NPT12_D) != 0);
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

static void
destroy_cb(void *root)
{
	svm_nested_npt_root_destroy(root);
}

/*
 * An alias without a system wiring breaks populate's invariant.  Refusing
 * the clear is a recoverable error and destroy reports the broken
 * invariant; sleeping on a later alias is neither.
 */
static void
case_unwired_alias_refused(void)
{
	struct svm_nested_npt_root *root;

	khx_host_case("unwired alias is refused, not slept on");
	root = root_new();
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, 0x1000, 0x2000,
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(vm_gpa_map_alias(VCPU, &model_vmspaces[0], 0x8000, 0x8000,
	    PAGE_SIZE, VM_PROT_READ, VM_PROT_READ, NULL), 0);
	KHX_EQ(svm_nested_npt_root_clear(root), EPROTO);
	KHX_EQ(model_sleeps, 0);
	KHX_CHECK(KHX_PANICS(destroy_cb, root));
	KHX_EQ(model_sleeps, 0);
}

#define	ASID	1
#define	NP_ON	1		/* VMCB12 NP_ENABLE */
#define	NCR3	0x10000		/* VMCB12 nCR3: the NPT12 root */
#define	L2PAGE(n)	(0x100000 + (vm_offset_t)(n) * PAGE_SIZE)
#define	L1PAGE(n)	(0x800000 + (vm_offset_t)(n) * PAGE_SIZE)
#define	WSET		8	/* pages L2 touches between exits to L1 */
#define	SLICE_FAULTS	6	/* nested NPFs L0 serves before L1's timer */
#define	SLICES		40

static struct model_entry *
model_lookup(vm_offset_t gpa)
{
	int i;

	for (i = 0; i < MODEL_ENTRIES; i++)
		if (model[i].used && model[i].start <= gpa &&
		    gpa < model[i].end)
			return (&model[i]);
	return (NULL);
}

/* L2 runs until it has its working set or L1's next interrupt exits it. */
static bool
l2_slice(struct svm_nested_npt_root *root, int *faults)
{
	int budget, page;

	budget = SLICE_FAULTS;
	for (page = 0; page < WSET; page++) {
		if (model_lookup(L2PAGE(page)) != NULL)
			continue;
		if (budget-- == 0)
			return (false);
		(*faults)++;
		KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(page),
		    L1PAGE(page), RWX, SVM_NESTED_NPT_READ), 0);
	}
	return (true);
}

/*
 * 2026-11-02 host run (gen6): L2 never reached its marker.  L0 served 598816
 * nested NPFs in 20 s for a 512 MB L2 (131072 pages), so it was refaulting
 * the same pages: L1's VMRUN after every L2 exit cleared NPT02, and L1's
 * timer exited L2 again before its working set was back.  L1 does not edit
 * NPT12 here, so NPT02 must survive VMRUN and L2 must finish.
 */
static void
case_vmrun_keeps_npt02(void)
{
	struct svm_nested_npt_root *root;
	int faults, slice;
	bool done;

	khx_host_case("L1 VMRUN keeps NPT02: L2 progresses across exits");
	root = root_new();
	faults = 0;
	done = false;
	for (slice = 0; slice < SLICES && !done; slice++) {
		KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
		    VMCB_TLB_FLUSH_NOTHING), 0);
		done = l2_slice(root, &faults);
	}
	KHX_CHECK(done);
	KHX_EQ(slice, 2);
	KHX_EQ(faults, WSET);
	KHX_EQ(model_maps, WSET);
	KHX_EQ(model_sleeps, 0);
	svm_nested_npt_root_destroy(root);
	KHX_EQ(model_sleeps, 0);
}

/* Every way L1 can make an NPT12 edit visible discards NPT02. */
static void
case_vmrun_flush_rules(void)
{
	static const struct {
		uint32_t asid;
		uint64_t np;
		uint64_t ncr3;
		uint8_t tlb_ctrl;
	} change[] = {
		{ ASID, NP_ON, NCR3, VMCB_TLB_FLUSH_ALL },
		{ ASID, NP_ON, NCR3, VMCB_TLB_FLUSH_GUEST },
		{ ASID, NP_ON, NCR3, VMCB_TLB_FLUSH_GUEST_NONGLOBAL },
		{ ASID + 1, NP_ON, NCR3, VMCB_TLB_FLUSH_NOTHING },
		{ ASID, 0, NCR3, VMCB_TLB_FLUSH_NOTHING },
		{ ASID, NP_ON, NCR3 + PAGE_SIZE, VMCB_TLB_FLUSH_NOTHING },
	};
	struct svm_nested_npt_root *root;
	u_int i;

	khx_host_case("VMRUN discards NPT02 on flush, ASID, NP or nCR3 change");
	KHX_EQ(svm_nested_npt_root_vmrun(NULL, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), EINVAL);
	root = root_new();
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(0), L1PAGE(0),
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(model_count(), 1);
	for (i = 0; i < nitems(change); i++) {
		KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
		    VMCB_TLB_FLUSH_NOTHING), 0);
		KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(0),
		    L1PAGE(0), RWX, SVM_NESTED_NPT_READ), 0);
		KHX_EQ(svm_nested_npt_root_vmrun(root, change[i].asid,
		    change[i].np, change[i].ncr3, change[i].tlb_ctrl), 0);
		KHX_EQ(model_count(), 0);
	}
	/* L1's INVLPGA cannot sleep; the next VMRUN does the discarding. */
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(0), L1PAGE(0),
	    RWX, SVM_NESTED_NPT_READ), 0);
	svm_nested_npt_root_flush(root);
	svm_nested_npt_root_flush(NULL);
	KHX_EQ(model_count(), 1);
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(model_count(), 0);
	/* An L0 memory-map change clears at once and forgets the context. */
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(0), L1PAGE(0),
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(svm_nested_npt_root_clear(root), 0);
	KHX_EQ(model_count(), 0);
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(1), L1PAGE(1),
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(model_count(), 0);
	/* A refused discard is not mistaken for a kept context. */
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(0), L1PAGE(0),
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(vm_gpa_map_alias(VCPU, &model_vmspaces[0], L2PAGE(1), L1PAGE(1),
	    PAGE_SIZE, VM_PROT_READ, VM_PROT_READ, NULL), 0);
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_GUEST), EPROTO);
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), EPROTO);
	KHX_EQ(model_sleeps, 0);
	KHX_CHECK(KHX_PANICS(destroy_cb, root));
}

/*
 * The walk sets NPT12 D only for a write.  A writable alias for a read
 * would let L2 dirty the page without D ever reaching L1, now that the alias
 * lives across VMRUNs.
 */
static void
case_resolve_clean_page_read_only(void)
{
	struct svm_nested_npt_result result;
	struct svm_nested_npt_root *root;
	struct model_entry *e;

	khx_host_case("resolve maps a clean NPT12 page read-only");
	root = root_new();
	model_walk.outcome = SVM_NESTED_NPT_TRANSLATED;
	model_walk.l1_gpa = L1PAGE(0);
	model_walk.count = 4;
	model_walk.permissions = RWX;
	model_walk.ad_desired[3] = L1PAGE(0) | 0x27;	/* P RW US A */
	KHX_EQ(svm_nested_npt_root_resolve(root, VCPU, NCR3, L2PAGE(0) | 0x10,
	    SVM_NESTED_NPT_READ, 48, false, &result), 0);
	e = model_lookup(L2PAGE(0));
	KHX_CHECK(e != NULL);
	if (e != NULL)
		KHX_EQ(e->prot, VM_PROT_READ | VM_PROT_EXECUTE);
	/* L2's first write faults again; that walk sets D. */
	model_walk.ad_desired[3] |= NPT12_D;
	KHX_EQ(svm_nested_npt_root_resolve(root, VCPU, NCR3, L2PAGE(0),
	    SVM_NESTED_NPT_WRITE, 48, false, &result), 0);
	e = model_lookup(L2PAGE(0));
	KHX_CHECK(e != NULL);
	if (e != NULL)
		KHX_EQ(e->prot, VM_PROT_ALL);
	/* A leaf that is already dirty may be aliased writable on a read. */
	KHX_EQ(svm_nested_npt_root_resolve(root, VCPU, NCR3, L2PAGE(1),
	    SVM_NESTED_NPT_READ, 48, false, &result), 0);
	e = model_lookup(L2PAGE(1));
	KHX_CHECK(e != NULL);
	if (e != NULL)
		KHX_EQ(e->prot, VM_PROT_ALL);
	KHX_EQ(model_count(), 2);
	svm_nested_npt_root_destroy(root);
	KHX_EQ(model_sleeps, 0);
}

/*
 * svm.c turns L1's INVLPGA into svm_nested_npt_root_flush() and an L0
 * memory-map change into svm_nested_npt_root_clear().  Either must make the
 * next VMRUN start from an empty NPT02 although L1 resumes L2 with the same
 * ASID, NP controls and nCR3 and no TLB_CONTROL; the VMRUN after that keeps
 * NPT02 again.
 */
static void
case_flush_events_clear_next_vmrun(void)
{
	struct svm_nested_npt_root *root;

	khx_host_case("INVLPGA and memmap invalidation clear the next VMRUN");
	root = root_new();
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(0), L1PAGE(0),
	    RWX, SVM_NESTED_NPT_READ), 0);

	/* INVLPGA exit while L1 runs; L2 resumes in the same context. */
	svm_nested_npt_root_flush(root);
	KHX_EQ(model_count(), 1);
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(model_count(), 0);
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(1), L1PAGE(1),
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(model_count(), 1);

	/*
	 * Memory-map invalidation at a frozen boundary, then an L2 exit that
	 * L0 serves before L1's next VMRUN.
	 */
	KHX_EQ(svm_nested_npt_root_clear(root), 0);
	KHX_EQ(model_count(), 0);
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(2), L1PAGE(2),
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(model_count(), 0);
	KHX_EQ(svm_nested_npt_root_populate(root, VCPU, L2PAGE(2), L1PAGE(2),
	    RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(svm_nested_npt_root_vmrun(root, ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(model_count(), 1);
	KHX_EQ(model_sleeps, 0);
	svm_nested_npt_root_destroy(root);
	KHX_EQ(model_sleeps, 0);
}

/*
 * Two L1 vCPUs run L2 vCPUs on one NPT12 with the same ASID.  Each has its
 * own NPT02, as each CPU has its own TLB, so a flush by one vCPU (INVLPGA or
 * TLB_CONTROL) clears only that vCPU's NPT02; the other keeps its aliases
 * until it flushes itself.
 */
static void
case_shared_npt12_per_vcpu_flush(void)
{
	struct svm_nested_npt_root *root[2];
	int v;

	khx_host_case("two L1 vCPUs sharing an NPT12 clear on their own flush");
	root[0] = root_new();
	root[1] = NULL;
	KHX_EQ(svm_nested_npt_root_create(MAXADDR, &root[1]), 0);
	KHX_CHECK(root[1] != NULL);
	for (v = 0; v < 2; v++) {
		KHX_EQ(svm_nested_npt_root_vmrun(root[v], ASID, NP_ON, NCR3,
		    VMCB_TLB_FLUSH_NOTHING), 0);
		KHX_EQ(svm_nested_npt_root_populate(root[v], VCPU, L2PAGE(0),
		    L1PAGE(0), RWX, SVM_NESTED_NPT_READ), 0);
		KHX_EQ(svm_nested_npt_root_populate(root[v], VCPU, L2PAGE(1),
		    L1PAGE(1), RWX, SVM_NESTED_NPT_READ), 0);
	}
	KHX_EQ(model_count_in(&model_vmspaces[0]), 2);
	KHX_EQ(model_count_in(&model_vmspaces[1]), 2);

	/* vCPU 0 executes INVLPGA. */
	svm_nested_npt_root_flush(root[0]);
	for (v = 0; v < 2; v++)
		KHX_EQ(svm_nested_npt_root_vmrun(root[v], ASID, NP_ON, NCR3,
		    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(model_count_in(&model_vmspaces[0]), 0);
	KHX_EQ(model_count_in(&model_vmspaces[1]), 2);

	/* vCPU 1 asks for a guest TLB flush in its VMCB12. */
	KHX_EQ(svm_nested_npt_root_populate(root[0], VCPU, L2PAGE(0),
	    L1PAGE(0), RWX, SVM_NESTED_NPT_READ), 0);
	KHX_EQ(svm_nested_npt_root_vmrun(root[0], ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_NOTHING), 0);
	KHX_EQ(svm_nested_npt_root_vmrun(root[1], ASID, NP_ON, NCR3,
	    VMCB_TLB_FLUSH_GUEST), 0);
	KHX_EQ(model_count_in(&model_vmspaces[0]), 1);
	KHX_EQ(model_count_in(&model_vmspaces[1]), 0);
	KHX_EQ(model_sleeps, 0);
	for (v = 0; v < 2; v++)
		svm_nested_npt_root_destroy(root[v]);
	KHX_EQ(model_frees, 2);
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
	case_vmrun_keeps_npt02();
	case_vmrun_flush_rules();
	case_resolve_clean_page_read_only();
	case_flush_events_clear_next_vmrun();
	case_shared_npt12_per_vcpu_flush();
	return (khx_host_finish("svm_nested_npt_root"));
}
