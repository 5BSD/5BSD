/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/sx.h>
#include <sys/systm.h>

#include <machine/vmm.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

#include <dev/vmm/vmm_dev.h>
#include <dev/vmm/vmm_address_range.h>
#include <dev/vmm/vmm_dirty_log.h>
#include <dev/vmm/vmm_dirty_log_collector.h>
#include <dev/vmm/vmm_dirty_log_map.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_vm.h>

static void vm_free_memmap(struct vm *vm, int ident);

/*
 * A wrapped generation must never make an old dirty-log ticket valid again.
 * Mapping changes still work after exhaustion; only future dirty-log capture
 * is withheld until a new VM supplies a fresh map identity.
 */
static void
vm_mem_dirty_log_map_changed(struct vm *vm)
{
	struct vm_mem *mem;
	uint64_t next;
	int error __diagused;

	vm_assert_memseg_xlocked(vm);
	mem = vm_mem(vm);
	if (mem->mem_map_generation == 0 ||
	    vmm_dirty_log_generation_next(mem->mem_map_generation, &next) != 0) {
		mem->mem_map_generation = 0;
	} else {
		mem->mem_map_generation = next;
	}
	/* A map change revokes a live ticket even if its generation wrapped. */
	error = vmm_dirty_log_owner_invalidate(&mem->mem_dirty_log_owner);
	KASSERT(error == 0 || error == EOVERFLOW,
	    ("%s: invalid dirty-log owner state %d", __func__, error));
}

int
vm_mem_init(struct vm_mem *mem, vm_offset_t lo, vm_offset_t hi)
{
	mem->mem_vmspace = vmmops_vmspace_alloc(lo, hi);
	if (mem->mem_vmspace == NULL)
		return (ENOMEM);
	sx_init(&mem->mem_segs_lock, "vm_mem_segs");
	mem->mem_map_generation = 1;
	bzero(&mem->mem_dirty_log_owner, sizeof(mem->mem_dirty_log_owner));
	return (0);
}

static bool
sysmem_mapping(struct vm_mem *mem, int idx)
{
	if (mem->mem_maps[idx].len != 0 &&
	    mem->mem_segs[mem->mem_maps[idx].segid].sysmem)
		return (true);
	else
		return (false);
}

bool
vm_memseg_sysmem(struct vm *vm, int ident)
{
	struct vm_mem *mem;

	mem = vm_mem(vm);
	vm_assert_memseg_locked(vm);

	if (ident < 0 || ident >= VM_MAX_MEMSEGS)
		return (false);

	return (mem->mem_segs[ident].sysmem);
}

void
vm_mem_cleanup(struct vm *vm)
{
	struct vm_mem *mem;

	mem = vm_mem(vm);
	vm_assert_memseg_xlocked(vm);
	/* Reset/destroy revokes tickets even when the sysmem map is unchanged. */
	(void)vm_mem_dirty_log_invalidate(vm);

	/*
	 * System memory is removed from the guest address space only when
	 * the VM is destroyed. This is because the mapping remains the same
	 * across VM reset.
	 *
	 * Device memory can be relocated by the guest (e.g. using PCI BARs)
	 * so those mappings are removed on a VM reset.
	 */
	for (int i = 0; i < VM_MAX_MEMMAPS; i++) {
		if (!sysmem_mapping(mem, i))
			vm_free_memmap(vm, i);
	}
}

void
vm_mem_destroy(struct vm *vm)
{
	struct vm_mem *mem;

	mem = vm_mem(vm);
	vm_assert_memseg_xlocked(vm);

	for (int i = 0; i < VM_MAX_MEMMAPS; i++) {
		if (sysmem_mapping(mem, i))
			vm_free_memmap(vm, i);
	}

	for (int i = 0; i < VM_MAX_MEMSEGS; i++)
		vm_free_memseg(vm, i);

	vmmops_vmspace_free(mem->mem_vmspace);

	sx_xunlock(&mem->mem_segs_lock);
	sx_destroy(&mem->mem_segs_lock);
}

struct vmspace *
vm_vmspace(struct vm *vm)
{
	struct vm_mem *mem;

	mem = vm_mem(vm);
	return (mem->mem_vmspace);
}

void
vm_slock_memsegs(struct vm *vm)
{
	sx_slock(&vm_mem(vm)->mem_segs_lock);
}

void
vm_xlock_memsegs(struct vm *vm)
{
	sx_xlock(&vm_mem(vm)->mem_segs_lock);
}

void
vm_unlock_memsegs(struct vm *vm)
{
	sx_unlock(&vm_mem(vm)->mem_segs_lock);
}

void
vm_assert_memseg_locked(struct vm *vm)
{
	sx_assert(&vm_mem(vm)->mem_segs_lock, SX_LOCKED);
}

void
vm_assert_memseg_xlocked(struct vm *vm)
{
	sx_assert(&vm_mem(vm)->mem_segs_lock, SX_XLOCKED);
}

/*
 * Return 'true' if 'gpa' is allocated in the guest address space.
 *
 * This function is called in the context of a running vcpu which acts as
 * an implicit lock on 'vm->mem_maps[]'.
 */
bool
vm_mem_allocated(struct vcpu *vcpu, vm_paddr_t gpa)
{
	struct vm *vm = vcpu_vm(vcpu);
	struct vm_mem_map *mm;
	int i;

#ifdef INVARIANTS
	int hostcpu, state;
	state = vcpu_get_state(vcpu, &hostcpu);
	KASSERT(state == VCPU_RUNNING && hostcpu == curcpu,
	    ("%s: invalid vcpu state %d/%d", __func__, state, hostcpu));
#endif

	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm_mem(vm)->mem_maps[i];
		if (mm->len != 0 && gpa >= mm->gpa && gpa < mm->gpa + mm->len)
			return (true);		/* 'gpa' is sysmem or devmem */
	}

	return (false);
}

int
vm_alloc_memseg(struct vm *vm, int ident, size_t len, bool sysmem,
    struct domainset *obj_domainset)
{
	struct vm_mem_seg *seg;
	struct vm_mem *mem;
	vm_object_t obj;

	mem = vm_mem(vm);
	vm_assert_memseg_xlocked(vm);

	if (ident < 0 || ident >= VM_MAX_MEMSEGS)
		return (EINVAL);

	if (len == 0 || (len & PAGE_MASK))
		return (EINVAL);

	seg = &mem->mem_segs[ident];
	if (seg->object != NULL) {
		if (seg->len == len && seg->sysmem == sysmem)
			return (EEXIST);
		else
			return (EINVAL);
	}

	/*
	 * When given an impossible policy, signal an
	 * error to the user.
	 */
	if (obj_domainset != NULL && domainset_empty_vm(obj_domainset))
		return (EINVAL);
	obj = vm_object_allocate(OBJT_SWAP, len >> PAGE_SHIFT);
	if (obj == NULL)
		return (ENOMEM);

	seg->len = len;
	seg->object = obj;
	if (obj_domainset != NULL)
		seg->object->domain.dr_policy = obj_domainset;
	seg->sysmem = sysmem;

	return (0);
}

int
vm_get_memseg(struct vm *vm, int ident, size_t *len, bool *sysmem,
    vm_object_t *objptr)
{
	struct vm_mem *mem;
	struct vm_mem_seg *seg;

	mem = vm_mem(vm);

	vm_assert_memseg_locked(vm);

	if (ident < 0 || ident >= VM_MAX_MEMSEGS)
		return (EINVAL);

	seg = &mem->mem_segs[ident];
	if (len)
		*len = seg->len;
	if (sysmem)
		*sysmem = seg->sysmem;
	if (objptr)
		*objptr = seg->object;
	return (0);
}

void
vm_free_memseg(struct vm *vm, int ident)
{
	struct vm_mem_seg *seg;

	KASSERT(ident >= 0 && ident < VM_MAX_MEMSEGS,
	    ("%s: invalid memseg ident %d", __func__, ident));

	seg = &vm_mem(vm)->mem_segs[ident];
	if (seg->object != NULL) {
		vm_object_deallocate(seg->object);
		bzero(seg, sizeof(struct vm_mem_seg));
	}
}

int
vm_mmap_memseg(struct vm *vm, vm_paddr_t gpa, int segid, vm_ooffset_t first,
    size_t len, int prot, int flags)
{
	struct vm_mem *mem;
	struct vm_mem_seg *seg;
	struct vm_mem_map *m, *map;
	struct vm_map *vmmap;
	vm_ooffset_t last;
	int i, error;

	if (prot == 0 || (prot & ~(VM_PROT_ALL)) != 0)
		return (EINVAL);

	if (flags & ~VM_MEMMAP_F_WIRED)
		return (EINVAL);

	if (segid < 0 || segid >= VM_MAX_MEMSEGS)
		return (EINVAL);

	mem = vm_mem(vm);
	seg = &mem->mem_segs[segid];
	if (seg->object == NULL)
		return (EINVAL);

	if (first + len < first || gpa + len < gpa)
		return (EINVAL);
	last = first + len;
	if (first >= last || last > seg->len)
		return (EINVAL);

	if ((gpa | first | last) & PAGE_MASK)
		return (EINVAL);

	map = NULL;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		m = &mem->mem_maps[i];
		if (m->len == 0) {
			map = m;
			break;
		}
	}
	if (map == NULL)
		return (ENOSPC);

	vmmap = &mem->mem_vmspace->vm_map;
	vm_object_reference(seg->object);
	vm_map_lock(vmmap);
	error = vm_map_insert(vmmap, seg->object, first, gpa, gpa + len,
	    prot, prot, 0);
	vm_map_unlock(vmmap);
	if (error != KERN_SUCCESS) {
		vm_object_deallocate(seg->object);
		return (vm_mmap_to_errno(error));
	}

	if (flags & VM_MEMMAP_F_WIRED) {
		error = vm_map_wire(vmmap, gpa, gpa + len,
		    VM_MAP_WIRE_USER | VM_MAP_WIRE_NOHOLES);
		if (error != KERN_SUCCESS) {
			vm_map_remove(vmmap, gpa, gpa + len);
			return (error == KERN_RESOURCE_SHORTAGE ? ENOMEM :
			    EFAULT);
		}
	}

	map->gpa = gpa;
	map->len = len;
	map->segoff = first;
	map->segid = segid;
	map->prot = prot;
	map->flags = flags;
	vm_mem_dirty_log_map_changed(vm);
	return (0);
}

int
vm_munmap_memseg(struct vm *vm, vm_paddr_t gpa, size_t len)
{
	struct vm_mem *mem;
	struct vm_mem_map *m;
	int i;

	mem = vm_mem(vm);
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		m = &mem->mem_maps[i];
#ifdef VM_MEMMAP_F_IOMMU
		if ((m->flags & VM_MEMMAP_F_IOMMU) != 0)
			continue;
#endif
		if (m->gpa == gpa && m->len == len) {
			vm_free_memmap(vm, i);
			return (0);
		}
	}

	return (EINVAL);
}

int
vm_mmap_getnext(struct vm *vm, vm_paddr_t *gpa, int *segid,
    vm_ooffset_t *segoff, size_t *len, int *prot, int *flags)
{
	struct vm_mem *mem;
	struct vm_mem_map *mm, *mmnext;
	int i;

	mem = vm_mem(vm);

	mmnext = NULL;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &mem->mem_maps[i];
		if (mm->len == 0 || mm->gpa < *gpa)
			continue;
		if (mmnext == NULL || mm->gpa < mmnext->gpa)
			mmnext = mm;
	}

	if (mmnext != NULL) {
		*gpa = mmnext->gpa;
		if (segid)
			*segid = mmnext->segid;
		if (segoff)
			*segoff = mmnext->segoff;
		if (len)
			*len = mmnext->len;
		if (prot)
			*prot = mmnext->prot;
		if (flags)
			*flags = mmnext->flags;
		return (0);
	} else {
		return (ENOENT);
	}
}

int
vm_mem_dirty_log_map_snapshot(struct vm *vm,
    struct vmm_dirty_log_map_entry *entries, size_t capacity,
    size_t *nentries, uint64_t *generation)
{
	struct vmm_dirty_log_map_entry candidate, staging[VM_MAX_MEMMAPS];
	struct vm_mem *mem;
	struct vm_mem_map *map;
	size_t count, i, j;
	int error;

	if (vm == NULL || entries == NULL || nentries == NULL ||
	    generation == NULL)
		return (EINVAL);
	/*
	 * mem_segs_lock makes the mapping table stable.  The higher-level dirty
	 * collection path freezes vCPUs before it retains this generation; that
	 * lifecycle condition intentionally remains outside this common memory
	 * helper so non-VMX backends can share it.
	 */
	vm_assert_memseg_locked(vm);
	mem = vm_mem(vm);
	if (mem->mem_map_generation == 0)
		return (EOVERFLOW);
	count = 0;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		map = &mem->mem_maps[i];
		if (map->len == 0)
			continue;
		if (map->segid < 0 || map->segid >= VM_MAX_MEMSEGS)
			return (EPROTO);
		if (map->gpa > UINT64_MAX || map->len > UINT64_MAX)
			return (EOVERFLOW);
		candidate = (struct vmm_dirty_log_map_entry) {
			.range = {
				.gpa = map->gpa,
				.length = map->len,
			},
			.flags = mem->mem_segs[map->segid].sysmem ?
			    VMM_DIRTY_LOG_MAP_F_COLLECTABLE : 0,
		};
		for (j = count; j != 0 &&
		    staging[j - 1].range.gpa > candidate.range.gpa; j--)
			staging[j] = staging[j - 1];
		staging[j] = candidate;
		count++;
	}
	if (count == 0 || capacity < count)
		return (count == 0 ? ENOENT : ENOSPC);
	if (!vmm_address_range_valid(entries, count * sizeof(*entries)) ||
	    !vmm_address_range_valid(nentries, sizeof(*nentries)) ||
	    !vmm_address_range_valid(generation, sizeof(*generation)) ||
	    vmm_address_ranges_overlap(entries, count * sizeof(*entries), mem,
	    sizeof(*mem)) ||
	    vmm_address_ranges_overlap(nentries, sizeof(*nentries), mem,
	    sizeof(*mem)) ||
	    vmm_address_ranges_overlap(generation, sizeof(*generation), mem,
	    sizeof(*mem)) ||
	    vmm_address_ranges_overlap(entries, count * sizeof(*entries),
	    nentries, sizeof(*nentries)) ||
	    vmm_address_ranges_overlap(entries, count * sizeof(*entries),
	    generation, sizeof(*generation)) ||
	    vmm_address_ranges_overlap(nentries, sizeof(*nentries), generation,
	    sizeof(*generation)))
		return (EINVAL);
	if ((error = vmm_dirty_log_map_validate(staging, count)) != 0)
		return (error == E2BIG ? EPROTO : error);
	memcpy(entries, staging, count * sizeof(*entries));
	*nentries = count;
	*generation = mem->mem_map_generation;
	return (0);
}

int
vm_mem_dirty_log_enable(struct vm *vm, const struct vmm_dirty_log_range *range)
{
	struct vmm_dirty_log_map_entry entries[VM_MAX_MEMMAPS];
	struct vm_mem *mem;
	size_t nentries;
	uint64_t generation;
	int error;

	if (vm == NULL || range == NULL)
		return (EINVAL);
	vm_assert_memseg_xlocked(vm);
	if ((error = vm_mem_dirty_log_map_snapshot(vm, entries,
	    nitems(entries), &nentries, &generation)) != 0)
		return (error);
	mem = vm_mem(vm);
	return (vmm_dirty_log_owner_enable(&mem->mem_dirty_log_owner, entries,
	    nentries, generation, range));
}

int
vm_mem_dirty_log_begin(struct vm *vm, const struct vmm_dirty_log_range *range,
    enum vmm_dirty_log_collect_mode mode,
    struct vmm_dirty_log_ticket *ticket)
{
	struct vmm_dirty_log_map_entry entries[VM_MAX_MEMMAPS];
	struct vm_mem *mem;
	size_t nentries;
	uint64_t generation;
	int error;

	if (vm == NULL || range == NULL || ticket == NULL)
		return (EINVAL);
	vm_assert_memseg_xlocked(vm);
	if ((error = vm_mem_dirty_log_map_snapshot(vm, entries,
	    nitems(entries), &nentries, &generation)) != 0)
		return (error);
	mem = vm_mem(vm);
	return (vmm_dirty_log_owner_begin(&mem->mem_dirty_log_owner, entries,
	    nentries, generation, range, mode, ticket));
}

int
vm_mem_dirty_log_ticket_check(struct vm *vm,
    const struct vmm_dirty_log_ticket *ticket)
{

	if (vm == NULL || ticket == NULL)
		return (EINVAL);
	vm_assert_memseg_xlocked(vm);
	return (vmm_dirty_log_owner_ticket_check(
	    &vm_mem(vm)->mem_dirty_log_owner, ticket));
}

int
vm_mem_dirty_log_collect(struct vm *vm,
    const struct vmm_dirty_log_ticket *ticket,
    const struct vmm_dirty_log_collector *collector, void *arg,
    uint8_t *staging, size_t staging_bytes, uint8_t *bitmap,
    size_t bitmap_bytes)
{

	if (vm == NULL)
		return (EINVAL);
	vm_assert_memseg_xlocked(vm);
	return (vmm_dirty_log_collect(&vm_mem(vm)->mem_dirty_log_owner,
	    ticket, collector, arg, staging, staging_bytes, bitmap,
	    bitmap_bytes));
}

int
vm_mem_dirty_log_clear(struct vm *vm,
    const struct vmm_dirty_log_ticket *ticket,
    const struct vmm_dirty_log_collector *collector, void *arg)
{

	if (vm == NULL)
		return (EINVAL);
	vm_assert_memseg_xlocked(vm);
	return (vmm_dirty_log_clear(&vm_mem(vm)->mem_dirty_log_owner, ticket,
	    collector, arg));
}

int
vm_mem_dirty_log_finish(struct vm *vm,
    const struct vmm_dirty_log_ticket *ticket)
{

	if (vm == NULL || ticket == NULL)
		return (EINVAL);
	vm_assert_memseg_xlocked(vm);
	return (vmm_dirty_log_owner_finish(&vm_mem(vm)->mem_dirty_log_owner,
	    ticket));
}

int
vm_mem_dirty_log_abort(struct vm *vm,
    const struct vmm_dirty_log_ticket *ticket)
{

	if (vm == NULL || ticket == NULL)
		return (EINVAL);
	vm_assert_memseg_xlocked(vm);
	return (vmm_dirty_log_owner_abort(&vm_mem(vm)->mem_dirty_log_owner,
	    ticket));
}

int
vm_mem_dirty_log_invalidate(struct vm *vm)
{

	if (vm == NULL)
		return (EINVAL);
	vm_assert_memseg_xlocked(vm);
	return (vmm_dirty_log_owner_invalidate(&vm_mem(vm)->mem_dirty_log_owner));
}

static void
vm_free_memmap(struct vm *vm, int ident)
{
	struct vm_mem_map *mm;
	int error __diagused;

	mm = &vm_mem(vm)->mem_maps[ident];
	if (mm->len) {
		error = vm_map_remove(&vm_vmspace(vm)->vm_map, mm->gpa,
		    mm->gpa + mm->len);
		KASSERT(error == KERN_SUCCESS, ("%s: vm_map_remove error %d",
		    __func__, error));
		bzero(mm, sizeof(struct vm_mem_map));
		vm_mem_dirty_log_map_changed(vm);
	}
}

vm_paddr_t
vmm_sysmem_maxaddr(struct vm *vm)
{
	struct vm_mem *mem;
	struct vm_mem_map *mm;
	vm_paddr_t maxaddr;
	int i;

	mem = vm_mem(vm);
	maxaddr = 0;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &mem->mem_maps[i];
		if (sysmem_mapping(mem, i)) {
			if (maxaddr < mm->gpa + mm->len)
				maxaddr = mm->gpa + mm->len;
		}
	}
	return (maxaddr);
}

static void *
_vm_gpa_hold(struct vm *vm, vm_paddr_t gpa, size_t len, int reqprot,
    void **cookie)
{
	struct vm_mem_map *mm;
	vm_page_t m;
	int i, count, pageoff;

	pageoff = gpa & PAGE_MASK;
	if (len > PAGE_SIZE - pageoff)
		panic("vm_gpa_hold: invalid gpa/len: 0x%016lx/%lu", gpa, len);

	count = 0;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm_mem(vm)->mem_maps[i];
		if (gpa >= mm->gpa && gpa < mm->gpa + mm->len) {
			count = vm_fault_quick_hold_pages(
			    &vm_vmspace(vm)->vm_map, trunc_page(gpa),
			    PAGE_SIZE, reqprot, &m, 1);
			break;
		}
	}

	if (count == 1) {
		*cookie = m;
		return ((char *)VM_PAGE_TO_DMAP(m) + pageoff);
	} else {
		*cookie = NULL;
		return (NULL);
	}
}

void *
vm_gpa_hold(struct vcpu *vcpu, vm_paddr_t gpa, size_t len, int reqprot,
    void **cookie)
{
#ifdef INVARIANTS
	/*
	 * The current vcpu should be frozen to ensure 'vm_memmap[]'
	 * stability.
	 */
	int state = vcpu_get_state(vcpu, NULL);
	KASSERT(state == VCPU_FROZEN, ("%s: invalid vcpu state %d",
	    __func__, state));
#endif
	return (_vm_gpa_hold(vcpu_vm(vcpu), gpa, len, reqprot, cookie));
}

void *
vm_gpa_hold_global(struct vm *vm, vm_paddr_t gpa, size_t len, int reqprot,
    void **cookie)
{
	vm_assert_memseg_locked(vm);
	return (_vm_gpa_hold(vm, gpa, len, reqprot, cookie));
}

void
vm_gpa_release(void *cookie)
{
	vm_page_t m = cookie;

	vm_page_unwire(m, PQ_ACTIVE);
}

/*
 * Map a page-aligned range from the VM's guest-physical address space into a
 * private secondary vmspace.  The source memory map is stable while the
 * caller's vCPU is frozen: changing it requires every vCPU to be frozen.
 *
 * The destination map owns its own object reference.  This is intentionally
 * an object alias rather than a raw physical mapping so normal RAM cache
 * attributes and object lifetime remain under the VM system's control.
 */
int
vm_gpa_map_alias(struct vcpu *vcpu, struct vmspace *dst_vmspace,
    vm_paddr_t dst_gpa, vm_paddr_t src_gpa, size_t len, int prot)
{
	struct vm_mem_map *mm;
	struct vm_mem_seg *seg;
	struct vm_map *dst_map;
	vm_ooffset_t offset;
	int error;

	if (vcpu == NULL || dst_vmspace == NULL || len == 0 ||
	    ((dst_gpa | src_gpa | len) & PAGE_MASK) != 0 ||
	    dst_gpa + len < dst_gpa || src_gpa + len < src_gpa ||
	    prot == 0 || (prot & ~VM_PROT_ALL) != 0)
		return (EINVAL);
#ifdef INVARIANTS
	KASSERT(vcpu_get_state(vcpu, NULL) == VCPU_FROZEN,
	    ("%s: vCPU is not frozen", __func__));
#endif

	mm = NULL;
	for (int i = 0; i < VM_MAX_MEMMAPS; i++) {
		struct vm_mem_map *candidate;
		vm_paddr_t relative;

		candidate = &vm_mem(vcpu_vm(vcpu))->mem_maps[i];
		if (candidate->len == 0 || src_gpa < candidate->gpa)
			continue;
		relative = src_gpa - candidate->gpa;
		if (relative >= candidate->len ||
		    len > candidate->len - relative)
			continue;
		mm = candidate;
		break;
	}
	if (mm == NULL || (prot & mm->prot) != prot)
		return (EFAULT);
	seg = &vm_mem(vcpu_vm(vcpu))->mem_segs[mm->segid];
	if (seg->object == NULL)
		return (EFAULT);
	offset = mm->segoff + (src_gpa - mm->gpa);
	if (offset < mm->segoff || offset + len < offset ||
	    offset + len > seg->len)
		return (EOVERFLOW);

	dst_map = &dst_vmspace->vm_map;
	if (dst_gpa < vm_map_min(dst_map) ||
	    dst_gpa + len > vm_map_max(dst_map))
		return (EFAULT);
	vm_object_reference(seg->object);
	vm_map_lock(dst_map);
	error = vm_map_insert(dst_map, seg->object, offset, dst_gpa,
	    dst_gpa + len, prot, prot, 0);
	vm_map_unlock(dst_map);
	if (error != KERN_SUCCESS) {
		vm_object_deallocate(seg->object);
		return (vm_mmap_to_errno(error));
	}
	return (0);
}
