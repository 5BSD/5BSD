/* SPDX-License-Identifier: BSD-2-Clause */
/* Production vmm_mem.c and dirty collector with model VM primitives. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <machine/vmm.h>
#include <dev/vmm/vmm_vm.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_dirty_log_machdep.h>
#include "khx_kern.h"

vm_paddr_t dmaplimit;
struct kva_layout_s kva_layout;
static struct vmspace primary;
static int insert_error, pmap_queries, invalidations;
static int refs;
bool domainset_empty_vm(struct domainset *d __unused) { return (false); }
struct vmspace *vmmops_vmspace_alloc(vm_offset_t lo __unused,
    vm_offset_t hi __unused) { return (&primary); }
void vmmops_vmspace_free(struct vmspace *v __unused) {}
enum vcpu_state vcpu_get_state(struct vcpu *v, int *c __unused)
{ return (v->state); }
void _vm_map_lock(vm_map_t m __unused, const char *f __unused, int l __unused) {}
void _vm_map_unlock(vm_map_t m __unused, const char *f __unused, int l __unused) {}
vm_offset_t vm_map_min_KBI(const struct vm_map *m __unused) { return (0); }
vm_offset_t vm_map_max_KBI(const struct vm_map *m __unused) { return (1UL << 40); }
int vm_map_insert(vm_map_t m __unused, vm_object_t o __unused,
    vm_ooffset_t off __unused, vm_offset_t lo __unused,
    vm_offset_t hi __unused, vm_prot_t p __unused, vm_prot_t max __unused,
    int flags __unused) { return (insert_error); }
int vm_map_remove(vm_map_t m __unused, vm_offset_t lo __unused,
    vm_offset_t hi __unused) { return (KERN_SUCCESS); }
int vm_map_wire(vm_map_t m __unused, vm_offset_t lo __unused,
    vm_offset_t hi __unused, int flags __unused) { return (KERN_SUCCESS); }
int vm_mmap_to_errno(int e) { return (e == KERN_SUCCESS ? 0 : ENOMEM); }
int vm_nested_memmap_invalidate(struct vm *v __unused)
{ invalidations++; return (0); }
vm_object_t vm_object_allocate(objtype_t t __unused, vm_pindex_t n __unused)
{ panic("unexpected allocation"); }
void vm_object_reference(vm_object_t o __unused) { refs++; }
void vm_object_deallocate(vm_object_t o __unused) { refs--; }
void vm_page_unwire(vm_page_t p __unused, uint8_t q __unused)
{ panic("unexpected unwire"); }
int vm_fault_quick_hold_pages(vm_map_t m __unused, vm_offset_t a __unused,
    vm_size_t n __unused, vm_prot_t p __unused, vm_page_t *pages __unused,
    int count __unused) { panic("unexpected hold"); }
int pmap_guest_query_dirty(pmap_t p __unused, vm_offset_t a __unused,
    bool clear __unused, struct pmap_guest_dirty_leaf *leaf __unused)
{ pmap_queries++; return (ENOENT); }


int
khx_test_main(void)
{
	static struct vm vm;
	static struct vcpu vcpu;
	static struct vm_object object;
	static struct vmspace secondary;
	struct vmm_dirty_log_range range = { .gpa = PAGE_SIZE, .length = PAGE_SIZE * 4 };
	struct vmm_dirty_log_ticket ticket;
	struct vmm_dirty_log_leaf leaf;
	uint8_t staging, bitmap;
	int prot;

	khx_kern_boot();
	KHX_EQ(vm_mem_init(&vm.mem, 0, 1UL << 40), 0);
	vcpu.vm = &vm;
	vcpu.state = VCPU_FROZEN;
	vm.mem.mem_segs[0].object = &object;
	vm.mem.mem_segs[0].len = PAGE_SIZE * 8;
	vm.mem.mem_segs[0].sysmem = true;
	vm.mem.mem_maps[0] = (struct vm_mem_map) {
		.gpa = PAGE_SIZE, .len = PAGE_SIZE * 4, .segid = 0,
		.prot = VM_PROT_ALL,
	};
	vm_xlock_memsegs(&vm);
	khx_host_case("primary-clean");
	KHX_EQ(vmm_dirty_log_machdep_query(&vm, PAGE_SIZE, &leaf), 0);
	KHX_CHECK(!leaf.dirty);
	KHX_EQ(pmap_queries, 1);
	khx_host_case("readonly-alias");
	KHX_EQ(vm_gpa_map_alias(&vcpu, &secondary, 0, PAGE_SIZE,
	    PAGE_SIZE, VM_PROT_READ, VM_PROT_READ, &prot), 0);
	KHX_EQ(prot, VM_PROT_READ);
	KHX_EQ(vmm_dirty_log_machdep_query(&vm, PAGE_SIZE, &leaf), 0);
	KHX_CHECK(!leaf.dirty);
	khx_host_case("failed-writable-alias");
	insert_error = KERN_RESOURCE_SHORTAGE;
	KHX_EQ(vm_gpa_map_alias(&vcpu, &secondary, 0, PAGE_SIZE,
	    PAGE_SIZE, VM_PROT_RW, VM_PROT_WRITE, NULL), ENOMEM);
	KHX_EQ(vmm_dirty_log_machdep_query(&vm, PAGE_SIZE, &leaf), 0);
	KHX_CHECK(!leaf.dirty);
	KHX_EQ(refs, 1);
	insert_error = 0;
	vm.mem.mem_maps[0].prot = VM_PROT_READ;
	KHX_EQ(vm_gpa_map_alias(&vcpu, &secondary, 0, PAGE_SIZE,
	    PAGE_SIZE, VM_PROT_RW, VM_PROT_READ, &prot), 0);
	KHX_EQ(prot, VM_PROT_READ);
	KHX_EQ(vmm_dirty_log_machdep_query(&vm, PAGE_SIZE, &leaf), 0);
	KHX_CHECK(!leaf.dirty);
	vm.mem.mem_maps[0].prot = VM_PROT_ALL;
	khx_host_case("writable-alias-dirty");
	KHX_EQ(vm_gpa_map_alias(&vcpu, &secondary, 0, PAGE_SIZE * 2,
	    PAGE_SIZE, VM_PROT_RW, VM_PROT_WRITE, NULL), 0);
	KHX_EQ(vmm_dirty_log_machdep_query(&vm, PAGE_SIZE * 2, &leaf), 0);
	KHX_CHECK(leaf.dirty);
	KHX_EQ(leaf.range.gpa, PAGE_SIZE);
	KHX_EQ(leaf.range.length, PAGE_SIZE * 4);
	KHX_EQ(pmap_queries, 4);
	KHX_EQ(vm_mem_dirty_log_enable(&vm, &range, false), 0);
	/* Two generations and a partial-range clear cannot forget aliases. */
	for (int i = 0; i < 3; i++) {
		if (i == 1) { range.gpa = PAGE_SIZE * 2; range.length = PAGE_SIZE; }
		if (i == 2) { range.gpa = PAGE_SIZE; range.length = PAGE_SIZE * 4; }
		KHX_EQ(vm_mem_dirty_log_begin(&vm, &range,
		    VMM_DIRTY_LOG_COLLECT_CLEAR, &ticket), 0);
		staging = bitmap = 0;
		KHX_EQ(vm_mem_dirty_log_collect(&vm, &ticket,
		    &vmm_dirty_log_machdep_collector, &vm, &staging, 1, &bitmap, 1), 0);
		KHX_EQ(bitmap, i == 1 ? 1 : 15);
		KHX_EQ(vm_mem_dirty_log_clear(&vm, &ticket,
		    &vmm_dirty_log_machdep_collector, &vm), 0);
		KHX_EQ(vm_mem_dirty_log_finish(&vm, &ticket), 0);
	}
	khx_host_case("shared-segment-mapping");
	KHX_EQ(vm_mmap_memseg(&vm, PAGE_SIZE * 8, 0, 0,
	    PAGE_SIZE * 2, VM_PROT_ALL, 0), 0);
	KHX_EQ(vmm_dirty_log_machdep_query(&vm, PAGE_SIZE * 8, &leaf), 0);
	KHX_CHECK(leaf.dirty);
	KHX_EQ(leaf.range.gpa, PAGE_SIZE * 8);
	KHX_EQ(leaf.range.length, PAGE_SIZE * 2);
	khx_host_case("source-unmap-revokes-alias");
	KHX_EQ(vm_munmap_memseg(&vm, PAGE_SIZE, PAGE_SIZE * 4), 0);
	KHX_EQ(invalidations, 1);
	KHX_EQ(vmm_dirty_log_machdep_query(&vm, PAGE_SIZE, &leaf), 0);
	KHX_CHECK(!leaf.dirty);
	KHX_EQ(vmm_dirty_log_machdep_query(&vm, PAGE_SIZE, &leaf), 0);
	KHX_CHECK(!leaf.dirty);
	KHX_EQ(vmm_dirty_log_machdep_query(&vm, PAGE_SIZE * 8, &leaf), 0);
	KHX_CHECK(leaf.dirty);
	vm_unlock_memsegs(&vm);
	return (khx_host_finish("vmm_mem_dirty"));
}
