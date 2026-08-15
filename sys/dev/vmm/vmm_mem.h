/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 */

#ifndef _DEV_VMM_MEM_H_
#define	_DEV_VMM_MEM_H_

/* Maximum number of NUMA domains in a guest. */
#define VM_MAXMEMDOM 8
#define VM_MAXSYSMEM VM_MAXMEMDOM

/*
 * Identifiers for memory segments.
 * Each guest NUMA domain is represented by a single system
 * memory segment from [VM_SYSMEM, VM_MAXSYSMEM).
 * The remaining identifiers can be used to create devmem segments.
 */
enum {
        VM_SYSMEM = 0,
        VM_BOOTROM = VM_MAXSYSMEM,
        VM_FRAMEBUFFER,
        VM_PCIROM,
        /*
         * Generic device-memory segments.  Keep the fixed identifiers
         * above stable: they are part of the userspace/kernel VMM ABI.
         * Consumers of this range must allocate an unused identifier
         * instead of assigning a device-specific singleton.
         */
        VM_DEVMEM_START,
        VM_DEVMEM_END = VM_DEVMEM_START + 64,
        VM_MEMSEG_END = VM_DEVMEM_END
};

#define	VM_MAX_MEMSEGS	VM_MEMSEG_END
#define	VM_MAX_MEMMAPS	(VM_MAX_MEMSEGS * 2)

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/_sx.h>

#include <dev/vmm/vmm_dirty_log_owner.h>

struct domainset;
struct vcpu;
struct vm;
struct vm_guest_paging;
struct vm_object;
struct vmspace;
struct vmm_dirty_log_collector;

struct vm_mem_seg {
	size_t	len;
	bool	sysmem;
	struct vm_object *object;
};

struct vm_mem_map {
	vm_paddr_t	gpa;
	size_t		len;
	vm_ooffset_t	segoff;
	int		segid;
	int		prot;
	int		flags;
};

struct vm_mem {
	struct vm_mem_map	mem_maps[VM_MAX_MEMMAPS];
	struct vm_mem_seg	mem_segs[VM_MAX_MEMSEGS];
	struct sx		mem_segs_lock;
	struct vmspace		*mem_vmspace;
	/* Nonzero while a dirty-log transaction can bind this map identity. */
	uint64_t		mem_map_generation;
	/* Private common owner; no dirty-log ABI is exposed through vm_mem. */
	struct vmm_dirty_log_owner mem_dirty_log_owner;
};

int	vm_mem_init(struct vm_mem *mem, vm_offset_t lo, vm_offset_t hi);
void	vm_mem_cleanup(struct vm *vm);
void	vm_mem_destroy(struct vm *vm);

struct vmspace *vm_vmspace(struct vm *vm);

/*
 * APIs that modify the guest memory map require all vcpus to be frozen.
 */
void vm_slock_memsegs(struct vm *vm);
void vm_xlock_memsegs(struct vm *vm);
void vm_unlock_memsegs(struct vm *vm);
void vm_assert_memseg_locked(struct vm *vm);
void vm_assert_memseg_xlocked(struct vm *vm);
int vm_mmap_memseg(struct vm *vm, vm_paddr_t gpa, int segid, vm_ooffset_t off,
    size_t len, int prot, int flags);
int vm_munmap_memseg(struct vm *vm, vm_paddr_t gpa, size_t len);
int vm_alloc_memseg(struct vm *vm, int ident, size_t len, bool sysmem,
    struct domainset *obj_domainset);
void vm_free_memseg(struct vm *vm, int ident);

/*
 * APIs that inspect the guest memory map require only a *single* vcpu to
 * be frozen. This acts like a read lock on the guest memory map since any
 * modification requires *all* vcpus to be frozen.
 */
int vm_mmap_getnext(struct vm *vm, vm_paddr_t *gpa, int *segid,
    vm_ooffset_t *segoff, size_t *len, int *prot, int *flags);
/*
 * Caller holds mem_segs_lock.  A collector also freezes the vCPU set before
 * retaining this generation, so that the by-value map and its generation are
 * one logical dirty-log transaction.
 */
int vm_mem_dirty_log_map_snapshot(struct vm *,
    struct vmm_dirty_log_map_entry *, size_t, size_t *, uint64_t *);
/*
 * Owner operations mutate one VM-wide transaction and require exclusive
 * mem_segs_lock.  They remain kernel-internal.
 */
int vm_mem_dirty_log_enable(struct vm *,
    const struct vmm_dirty_log_range *);
int vm_mem_dirty_log_begin(struct vm *,
    const struct vmm_dirty_log_range *, enum vmm_dirty_log_collect_mode,
    struct vmm_dirty_log_ticket *);
/* Read-only backend fence; caller holds exclusive mem_segs_lock. */
int vm_mem_dirty_log_ticket_check(struct vm *,
    const struct vmm_dirty_log_ticket *);
int vm_mem_dirty_log_collect(struct vm *, const struct vmm_dirty_log_ticket *,
    const struct vmm_dirty_log_collector *, void *, uint8_t *, size_t,
    uint8_t *, size_t);
int vm_mem_dirty_log_clear(struct vm *, const struct vmm_dirty_log_ticket *,
    const struct vmm_dirty_log_collector *, void *);
int vm_mem_dirty_log_finish(struct vm *, const struct vmm_dirty_log_ticket *);
int vm_mem_dirty_log_abort(struct vm *, const struct vmm_dirty_log_ticket *);
int vm_mem_dirty_log_invalidate(struct vm *);
bool vm_memseg_sysmem(struct vm *vm, int ident);
int vm_get_memseg(struct vm *vm, int ident, size_t *len, bool *sysmem,
    struct vm_object **objptr);
vm_paddr_t vmm_sysmem_maxaddr(struct vm *vm);
void *vm_gpa_hold(struct vcpu *vcpu, vm_paddr_t gpa, size_t len,
    int prot, void **cookie);
void *vm_gpa_hold_global(struct vm *vm, vm_paddr_t gpa, size_t len,
    int prot, void **cookie);
void vm_gpa_release(void *cookie);
int vm_gpa_map_alias(struct vcpu *vcpu, struct vmspace *dst_vmspace,
    vm_paddr_t dst_gpa, vm_paddr_t src_gpa, size_t len, int prot);
bool vm_mem_allocated(struct vcpu *vcpu, vm_paddr_t gpa);

int vm_gla2gpa_nofault(struct vcpu *vcpu, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *is_fault);

#endif /* _KERNEL */

#endif /* !_DEV_VMM_MEM_H_ */
