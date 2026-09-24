/*-
 * Copyright (c) 2004 Tim J. Robbins
 * Copyright (c) 2002 Doug Rabson
 * Copyright (c) 2000 Marcel Moolenaar
 * Copyright (c) 1994-1995 Søren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/rwlock.h>
#include <sys/syscallsubr.h>
#include <sys/sdt.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>

#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_mmap.h>
#include <compat/linux/linux_persona.h>
#include <compat/linux/linux_util.h>

#define STACK_SIZE  (2 * 1024 * 1024)
#define GUARD_SIZE  (4 * PAGE_SIZE)

#if defined(__amd64__)
static void linux_fixup_prot(struct thread *td, int *prot);
#endif

static int
linux_mmap_check_fp(struct file *fp, int flags, int prot, int maxprot)
{

	/* Linux mmap() just fails for O_WRONLY files */
	if ((fp->f_flag & FREAD) == 0)
		return (EACCES);

	return (0);
}

/*
 * Is any part of [addr, addr + len) mapped?  Used to turn the ENOMEM a
 * MAP_EXCL collision produces into the EEXIST Linux gives for
 * MAP_FIXED_NOREPLACE.
 */
#define	LINUX_POPULATE_CHUNK	32

void
linux_mmap_populate(struct thread *td, vm_offset_t addr, size_t len, int prot)
{
	vm_page_t pages[LINUX_POPULATE_CHUNK];
	vm_map_t map;
	vm_offset_t va, end;
	vm_prot_t fprot;
	int n;

	map = &td->td_proc->p_vmspace->vm_map;
	fprot = (prot & PROT_WRITE) != 0 ? VM_PROT_WRITE : VM_PROT_READ;
	end = addr + round_page(len);
	for (va = addr; va < end; va += LINUX_POPULATE_CHUNK * PAGE_SIZE) {
		size_t chunk;

		chunk = MIN(end - va, LINUX_POPULATE_CHUNK * PAGE_SIZE);
		n = vm_fault_quick_hold_pages(map, va, chunk, fprot, pages,
		    LINUX_POPULATE_CHUNK);
		if (n < 0)
			break;
		vm_page_unhold_pages(pages, n);
	}
}

SDT_PROVIDER_DECLARE(linuxulator);
/* mseal(2) events: a range recorded, and a sealed range refusing a change. */
SDT_PROBE_DEFINE2(linuxulator, mmap, linux_mseal_common, sealed,
    "uintptr_t", "size_t");
SDT_PROBE_DEFINE2(linuxulator, mmap, linux_range_sealed, denied,
    "uintptr_t", "size_t");

/*
 * mseal(2): sealed ranges are recorded per process; every emulated call
 * that would unmap, remap, change the protection of, or destructively
 * advise a sealed page is refused with EPERM.  Native syscalls cannot be
 * issued by a Linux image, so the emulator's entry points are the only
 * way in.  Ranges are inherited by fork (they belong to the mappings) and
 * dropped by exec.
 */
bool
linux_range_sealed(struct thread *td, uintptr_t addr, size_t len)
{
	struct linux_pemuldata *pem;
	uintptr_t end;
	int i;
	bool sealed;

	pem = pem_find(td->td_proc);
	if (pem == NULL || pem->nseals == 0)
		return (false);
	end = addr + len;
	if (end < addr)
		end = ~(uintptr_t)0;
	sealed = false;
	LINUX_PEM_SLOCK(pem);
	for (i = 0; i < pem->nseals; i++) {
		if (pem->seals[i].start < end && addr < pem->seals[i].end) {
			sealed = true;
			break;
		}
	}
	LINUX_PEM_SUNLOCK(pem);
	if (sealed)
		SDT_PROBE2(linuxulator, mmap, linux_range_sealed, denied, addr, len);
	return (sealed);
}

/* Is [start, end) entirely covered by mappings? (Linux: ENOMEM otherwise.) */
static bool
linux_range_all_mapped(struct vmspace *vms, uintptr_t start, uintptr_t end)
{
	vm_map_t map;
	vm_map_entry_t entry;
	uintptr_t cur;

	map = &vms->vm_map;
	cur = start;
	vm_map_lock_read(map);
	if (!vm_map_lookup_entry(map, start, &entry)) {
		vm_map_unlock_read(map);
		return (false);
	}
	for (; entry != &map->header && cur < end;
	    entry = vm_map_entry_succ(entry)) {
		if (entry->start > cur)
			break;
		cur = entry->end;
	}
	vm_map_unlock_read(map);
	return (cur >= end);
}

int
linux_mseal_common(struct thread *td, uintptr_t addr, size_t len,
    unsigned long flags)
{
	struct linux_pemuldata *pem;
	struct linux_seal *ns;
	uintptr_t start, end;
	int i;

	if (flags != 0)
		return (EINVAL);
	if ((addr & PAGE_MASK) != 0)
		return (EINVAL);
	start = addr;
	end = start + round_page(len);
	if (end < start || end > VM_MAXUSER_ADDRESS)
		return (EINVAL);
	if (end == start)
		return (0);
	if (!linux_range_all_mapped(td->td_proc->p_vmspace, start, end))
		return (ENOMEM);

	pem = pem_find(td->td_proc);
	LINUX_PEM_XLOCK(pem);
	/* Merge with an existing range when they touch or overlap. */
	for (i = 0; i < pem->nseals; i++) {
		if (pem->seals[i].start <= end && start <= pem->seals[i].end) {
			if (start < pem->seals[i].start)
				pem->seals[i].start = start;
			if (end > pem->seals[i].end)
				pem->seals[i].end = end;
			LINUX_PEM_XUNLOCK(pem);
			SDT_PROBE2(linuxulator, mmap, linux_mseal_common, sealed,
			    start, end - start);
			return (0);
		}
	}
	if (pem->nseals == pem->maxseals) {
		int nmax = pem->maxseals == 0 ? 8 : pem->maxseals * 2;

		if (nmax > LINUX_MSEAL_MAX) {
			LINUX_PEM_XUNLOCK(pem);
			return (ENOMEM);
		}
		LINUX_PEM_XUNLOCK(pem);
		ns = malloc(nmax * sizeof(*ns), M_LINUX, M_WAITOK);
		LINUX_PEM_XLOCK(pem);
		if (pem->nseals == pem->maxseals) {
			if (pem->nseals > 0)
				memcpy(ns, pem->seals,
				    pem->nseals * sizeof(*ns));
			free(pem->seals, M_LINUX);
			pem->seals = ns;
			pem->maxseals = nmax;
		} else
			free(ns, M_LINUX);
	}
	pem->seals[pem->nseals].start = start;
	pem->seals[pem->nseals].end = end;
	pem->nseals++;
	LINUX_PEM_XUNLOCK(pem);
	SDT_PROBE2(linuxulator, mmap, linux_mseal_common, sealed, start,
	    end - start);
	return (0);
}

/* munmap(2): sealed pages are EPERM; otherwise native semantics. */
int
linux_munmap_common(struct thread *td, uintptr_t addr, size_t len)
{

	if (linux_range_sealed(td, addr, len))
		return (EPERM);
	return (kern_munmap(td, addr, len));
}

static bool
linux_mdwe_enabled(struct thread *td)
{
	struct linux_pemuldata *pem;

	pem = pem_find(td->td_proc);
	return (pem != NULL &&
	    (pem->mdwe & LINUX_PR_MDWE_REFUSE_EXEC_GAIN) != 0);
}

/*
 * PR_SET_MDWE for mprotect(2): besides W+X, a mapping that is not
 * executable may not gain PROT_EXEC.
 */
static bool
linux_range_lacks_exec(struct vmspace *vms, uintptr_t addr, size_t len)
{
	vm_map_t map;
	vm_map_entry_t entry;
	vm_offset_t start, end;
	bool lacks;

	start = trunc_page(addr);
	end = round_page(addr + len);
	map = &vms->vm_map;
	lacks = false;
	vm_map_lock_read(map);
	if (!vm_map_lookup_entry(map, start, &entry))
		entry = vm_map_entry_succ(entry);
	for (; entry != &map->header && entry->start < end;
	    entry = vm_map_entry_succ(entry)) {
		if ((entry->protection & VM_PROT_EXECUTE) == 0) {
			lacks = true;
			break;
		}
	}
	vm_map_unlock_read(map);
	return (lacks);
}

static bool
linux_range_mapped(struct vmspace *vms, uintptr_t addr, size_t len)
{
	vm_map_t map;
	vm_map_entry_t entry;
	vm_offset_t start, end;
	bool mapped;

	start = trunc_page(addr);
	end = round_page(addr + len);
	if (end < start)
		return (false);
	map = &vms->vm_map;
	vm_map_lock_read(map);
	if (vm_map_lookup_entry(map, start, &entry)) {
		mapped = true;
	} else {
		entry = vm_map_entry_succ(entry);
		mapped = entry != &map->header && entry->start < end;
	}
	vm_map_unlock_read(map);
	return (mapped);
}

int
linux_mmap_common(struct thread *td, uintptr_t addr, size_t len, int prot,
    int flags, int fd, off_t pos)
{
	struct mmap_req mr, mr_fixed;
	struct proc *p = td->td_proc;
	struct vmspace *vms = td->td_proc->p_vmspace;
	int bsd_flags, error;

	LINUX_CTR6(mmap2, "0x%lx, %ld, %ld, 0x%08lx, %ld, 0x%lx",
	    addr, len, prot, flags, fd, pos);

	error = 0;
	bsd_flags = 0;

	/*
	 * Linux mmap(2):
	 * You must specify exactly one of MAP_SHARED and MAP_PRIVATE
	 */
	/* Linux: a zero length is EINVAL (FreeBSD would accept it). */
	if (len == 0)
		return (EINVAL);
	/* MAP_FIXED replaces whatever is there: not over a sealed page. */
	if ((flags & LINUX_MAP_FIXED) != 0 &&
	    linux_range_sealed(td, addr, len))
		return (EPERM);

	/* PR_SET_MDWE: a mapping may not be writable and executable. */
	if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC) &&
	    linux_mdwe_enabled(td))
		return (EACCES);

	if ((flags & LINUX_MAP_SHARED_VALIDATE) == LINUX_MAP_SHARED_VALIDATE) {
		/*
		 * MAP_SHARED that rejects unknown flag bits with EOPNOTSUPP
		 * instead of ignoring them (Linux 4.15).
		 */
		if ((flags & ~LINUX_MAP_KNOWN_FLAGS) != 0)
			return (EOPNOTSUPP);
		/* MAP_SYNC is only valid on DAX; elsewhere EOPNOTSUPP. */
		if ((flags & LINUX_MAP_SYNC) != 0)
			return (EOPNOTSUPP);
		flags = (flags & ~LINUX_MAP_SHARED_VALIDATE) | LINUX_MAP_SHARED;
	}
	if (!((flags & LINUX_MAP_SHARED) ^ (flags & LINUX_MAP_PRIVATE)))
		return (EINVAL);

	if (flags & LINUX_MAP_SHARED)
		bsd_flags |= MAP_SHARED;
	if (flags & LINUX_MAP_PRIVATE)
		bsd_flags |= MAP_PRIVATE;
	if (flags & LINUX_MAP_FIXED)
		bsd_flags |= MAP_FIXED;
	/* Linux: the offset must be page aligned, anonymous or not. */
	if ((pos & PAGE_MASK) != 0)
		return (EINVAL);
	if (flags & LINUX_MAP_ANON) {
		pos = 0;
		bsd_flags |= MAP_ANON;
	} else
		bsd_flags |= MAP_NOSYNC;
	if (flags & LINUX_MAP_GROWSDOWN)
		bsd_flags |= MAP_STACK;

	/*
	 * MAP_HUGETLB demands pages from the hugetlbfs pool, which does not
	 * exist here; Linux with vm.nr_hugepages = 0 fails the same way and
	 * every caller (allocators, QEMU, databases) falls back on ENOMEM.
	 * MAP_SYNC is honoured only with MAP_SHARED_VALIDATE (above) and,
	 * as on Linux, silently ignored with plain MAP_SHARED/MAP_PRIVATE.
	 * MAP_FIXED_NOREPLACE is MAP_FIXED that fails with EEXIST instead
	 * of replacing; MAP_FIXED wins when both are given, as on Linux.
	 * MAP_POPULATE and MAP_LOCKED are honoured below; MAP_NORESERVE,
	 * MAP_NONBLOCK, MAP_STACK, MAP_DENYWRITE, MAP_EXECUTABLE and
	 * MAP_UNINITIALIZED are no-ops on Linux/x86-64 too.
	 */
	if (flags & LINUX_MAP_HUGETLB)
		return (ENOMEM);
	if ((flags & (LINUX_MAP_FIXED_NOREPLACE | LINUX_MAP_FIXED)) ==
	    LINUX_MAP_FIXED_NOREPLACE)
		bsd_flags |= MAP_FIXED | MAP_EXCL;
	if (flags & LINUX_MAP_POPULATE)
		bsd_flags |= MAP_PREFAULT_READ;	/* file-backed pages */

#if defined(__amd64__)
	/*
	 * According to the Linux mmap(2) man page, "MAP_32BIT flag
	 * is ignored when MAP_FIXED is set."
	 */
	if ((flags & LINUX_MAP_32BIT) && (flags & LINUX_MAP_FIXED) == 0)
		bsd_flags |= MAP_32BIT;

	/*
	 * PROT_READ, PROT_WRITE, or PROT_EXEC implies PROT_READ and PROT_EXEC
	 * on Linux/i386 if the binary requires executable stack.
	 * We do this only for IA32 emulation as on native i386 this is does not
	 * make sense without PAE.
	 *
	 * XXX. Linux checks that the file system is not mounted with noexec.
	 */
	linux_fixup_prot(td, &prot);
#endif

	/* Linux does not check file descriptor when MAP_ANONYMOUS is set. */
	fd = (bsd_flags & MAP_ANON) ? -1 : fd;
	if (flags & LINUX_MAP_GROWSDOWN) {
		/*
		 * The Linux MAP_GROWSDOWN option does not limit auto
		 * growth of the region.  Linux mmap with this option
		 * takes as addr the initial BOS, and as len, the initial
		 * region size.  It can then grow down from addr without
		 * limit.  However, Linux threads has an implicit internal
		 * limit to stack size of STACK_SIZE.  Its just not
		 * enforced explicitly in Linux.  But, here we impose
		 * a limit of (STACK_SIZE - GUARD_SIZE) on the stack
		 * region, since we can do this with our mmap.
		 *
		 * Our mmap with MAP_STACK takes addr as the maximum
		 * downsize limit on BOS, and as len the max size of
		 * the region.  It then maps the top SGROWSIZ bytes,
		 * and auto grows the region down, up to the limit
		 * in addr.
		 *
		 * If we don't use the MAP_STACK option, the effect
		 * of this code is to allocate a stack region of a
		 * fixed size of (STACK_SIZE - GUARD_SIZE).
		 */

		if ((caddr_t)addr + len > vms->vm_maxsaddr) {
			/*
			 * Some Linux apps will attempt to mmap
			 * thread stacks near the top of their
			 * address space.  If their TOS is greater
			 * than vm_maxsaddr, vm_map_growstack()
			 * will confuse the thread stack with the
			 * process stack and deliver a SEGV if they
			 * attempt to grow the thread stack past their
			 * current stacksize rlimit.  To avoid this,
			 * adjust vm_maxsaddr upwards to reflect
			 * the current stacksize rlimit rather
			 * than the maximum possible stacksize.
			 * It would be better to adjust the
			 * mmap'ed region, but some apps do not check
			 * mmap's return value.
			 */
			PROC_LOCK(p);
			vms->vm_maxsaddr = (char *)round_page(vms->vm_stacktop) -
			    lim_cur_proc(p, RLIMIT_STACK);
			PROC_UNLOCK(p);
		}

		/*
		 * This gives us our maximum stack size and a new BOS.
		 * If we're using VM_STACK, then mmap will just map
		 * the top SGROWSIZ bytes, and let the stack grow down
		 * to the limit at BOS.  If we're not using VM_STACK
		 * we map the full stack, since we don't have a way
		 * to autogrow it.
		 */
		if (len <= STACK_SIZE - GUARD_SIZE) {
			addr = addr - (STACK_SIZE - GUARD_SIZE - len);
			len = STACK_SIZE - GUARD_SIZE;
		}
	}

	/*
	 * FreeBSD is free to ignore the address hint if MAP_FIXED wasn't
	 * passed.  However, some Linux applications, like the ART runtime,
	 * depend on the hint.  If the MAP_FIXED wasn't passed, but the
	 * address is not zero, try with MAP_FIXED and MAP_EXCL first,
	 * and fall back to the normal behaviour if that fails.
	 */
	mr = (struct mmap_req) {
		.mr_hint = addr,
		.mr_len = len,
		.mr_prot = prot,
		.mr_flags = bsd_flags,
		.mr_fd = fd,
		.mr_pos = pos,
		.mr_check_fp_fn = linux_mmap_check_fp,
	};
	if (addr != 0 && (bsd_flags & MAP_FIXED) == 0 &&
	    (bsd_flags & MAP_EXCL) == 0) {
		mr_fixed = mr;
		mr_fixed.mr_flags |= MAP_FIXED | MAP_EXCL;
		error = kern_mmap(td, &mr_fixed);
		if (error == 0)
			goto out;
	}

	error = kern_mmap(td, &mr);
out:
	if (error == ENOMEM && (bsd_flags & MAP_EXCL) != 0 &&
	    linux_range_mapped(vms, addr, len))
		error = EEXIST;
	if (error == 0 && (flags & LINUX_MAP_POPULATE) != 0) {
		/*
		 * MAP_POPULATE faults every page in, allocating zero pages
		 * for anonymous memory and breaking COW on writable private
		 * mappings (Linux uses FOLL_WRITE there).  MAP_PREFAULT_READ
		 * above only covers pages already present in the object.
		 * Failures are ignored, as on Linux.
		 */
		linux_mmap_populate(td, td->td_retval[0], len, prot);
	}
	if (error == 0 && (flags & LINUX_MAP_LOCKED) != 0) {
		/*
		 * Linux wires MAP_LOCKED mappings after the fact and ignores
		 * a wiring failure (the mapping stays, unlocked).
		 */
		(void)kern_mlock(p, td->td_ucred, td->td_retval[0], len);
	}
	LINUX_CTR2(mmap2, "return: %d (%p)", error, td->td_retval[0]);

	return (error);
}

int
linux_mprotect_common(struct thread *td, uintptr_t addr, size_t len, int prot)
{
	int flags = 0;

	/*
	 * PROT_GROWSUP is only meaningful on architectures with upward
	 * growing stacks; x86 Linux rejects it (EINVAL), as it does both
	 * GROWS flags together.
	 */
	if ((prot & ~(LINUX_PROT_GROWSDOWN | PROT_READ | PROT_WRITE |
	    PROT_EXEC)) != 0)
		return (EINVAL);
	if ((prot & LINUX_PROT_GROWSDOWN) != 0) {
		prot &= ~LINUX_PROT_GROWSDOWN;
		flags |= VM_MAP_PROTECT_GROWSDOWN;
	}
	/* Linux: the start must be page aligned (FreeBSD would round). */
	if ((addr & PAGE_MASK) != 0)
		return (EINVAL);
	if (linux_range_sealed(td, addr, len))
		return (EPERM);
	/* Linux mprotect(): a hole anywhere in the range is ENOMEM. */
	if (!linux_range_all_mapped(td->td_proc->p_vmspace, addr,
	    round_page(addr + len)))
		return (ENOMEM);
	if ((prot & PROT_EXEC) != 0 && linux_mdwe_enabled(td)) {
		if ((prot & PROT_WRITE) != 0)
			return (EACCES);
		if (linux_range_lacks_exec(td->td_proc->p_vmspace, addr, len))
			return (EACCES);
	}

#if defined(__amd64__)
	linux_fixup_prot(td, &prot);
#endif
	return (kern_mprotect(td, addr, len, prot, flags));
}

/*
 * Implement Linux madvise(MADV_DONTNEED), which has unusual semantics: for
 * anonymous memory, pages in the range are immediately discarded.
 */
static int
linux_madvise_dontneed(struct thread *td, vm_offset_t start, vm_offset_t end)
{
	vm_map_t map;
	vm_map_entry_t entry;
	vm_object_t backing_object, object;
	vm_offset_t estart, eend;
	vm_pindex_t pstart, pend;
	int error;

	map = &td->td_proc->p_vmspace->vm_map;

	if (!vm_map_range_valid(map, start, end))
		return (EINVAL);
	start = trunc_page(start);
	end = round_page(end);

	error = 0;
	vm_map_lock_read(map);
	if (!vm_map_lookup_entry(map, start, &entry))
		entry = vm_map_entry_succ(entry);
	for (; entry->start < end; entry = vm_map_entry_succ(entry)) {
		if ((entry->eflags & MAP_ENTRY_IS_SUB_MAP) != 0)
			continue;

		if (entry->wired_count != 0) {
			error = EINVAL;
			break;
		}

		object = entry->object.vm_object;
		if (object == NULL)
			continue;
		if ((object->flags & (OBJ_UNMANAGED | OBJ_FICTITIOUS)) != 0)
			continue;

		pstart = OFF_TO_IDX(entry->offset);
		if (start > entry->start) {
			pstart += atop(start - entry->start);
			estart = start;
		} else {
			estart = entry->start;
		}
		pend = OFF_TO_IDX(entry->offset) +
		    atop(entry->end - entry->start);
		if (entry->end > end) {
			pend -= atop(entry->end - end);
			eend = end;
		} else {
			eend = entry->end;
		}

		if ((object->flags & (OBJ_ANON | OBJ_ONEMAPPING)) ==
		    (OBJ_ANON | OBJ_ONEMAPPING)) {
			/*
			 * Singly-mapped anonymous memory is discarded.  This
			 * does not match Linux's semantics when the object
			 * belongs to a shadow chain of length > 1, since
			 * subsequent faults may retrieve pages from an
			 * intermediate anonymous object.  However, handling
			 * this case correctly introduces a fair bit of
			 * complexity.
			 */
			VM_OBJECT_WLOCK(object);
			if ((object->flags & OBJ_ONEMAPPING) != 0) {
				vm_object_collapse(object);
				vm_object_page_remove(object, pstart, pend, 0);
				backing_object = object->backing_object;
				if (backing_object != NULL &&
				    (backing_object->flags & OBJ_ANON) != 0)
					linux_msg(td,
					    "possibly incorrect MADV_DONTNEED");
				VM_OBJECT_WUNLOCK(object);
				continue;
			}
			VM_OBJECT_WUNLOCK(object);
		}

		/*
		 * Handle shared mappings.  Remove them outright instead of
		 * calling pmap_advise(), for consistency with Linux.
		 */
		pmap_remove(map->pmap, estart, eend);
		vm_object_madvise(object, pstart, pend, MADV_DONTNEED);
	}
	vm_map_unlock_read(map);

	return (error);
}

int
linux_madvise_common(struct thread *td, uintptr_t addr, size_t len, int behav)
{

	/*
	 * Linux do_madvise(): the start must be page aligned and the range
	 * must not wrap, for every advice.  FreeBSD's kern_madvise() would
	 * silently round the start down instead.
	 */
	if ((addr & PAGE_MASK) != 0 || addr + len < addr)
		return (EINVAL);
	/* Advice that discards or alters contents is refused on sealed pages. */
	switch (behav) {
	case LINUX_MADV_DONTNEED:
	case LINUX_MADV_DONTNEED_LOCKED:
	case LINUX_MADV_FREE:
	case LINUX_MADV_REMOVE:
	case LINUX_MADV_WIPEONFORK:
	case LINUX_MADV_DONTFORK:
	case LINUX_MADV_POPULATE_WRITE:
	case LINUX_MADV_GUARD_INSTALL:
	case LINUX_MADV_GUARD_REMOVE:
		if (linux_range_sealed(td, addr, len))
			return (EPERM);
		break;
	}

	switch (behav) {
	case LINUX_MADV_NORMAL:
		return (kern_madvise(td, addr, len, MADV_NORMAL));
	case LINUX_MADV_RANDOM:
		return (kern_madvise(td, addr, len, MADV_RANDOM));
	case LINUX_MADV_SEQUENTIAL:
		return (kern_madvise(td, addr, len, MADV_SEQUENTIAL));
	case LINUX_MADV_WILLNEED:
		return (kern_madvise(td, addr, len, MADV_WILLNEED));
	case LINUX_MADV_DONTNEED:
		return (linux_madvise_dontneed(td, addr, addr + len));
	case LINUX_MADV_FREE:
		return (kern_madvise(td, addr, len, MADV_FREE));
	case LINUX_MADV_COLD:
	case LINUX_MADV_PAGEOUT:
		/*
		 * Reclaim hints that must preserve contents.  FreeBSD's
		 * MADV_DONTNEED is exactly that: it deactivates clean pages
		 * and launders dirty ones without discarding anything, so
		 * later accesses fault the same data back in.  (Linux's
		 * MADV_DONTNEED, which discards, is handled above.)
		 */
		return (kern_madvise(td, addr, len, MADV_DONTNEED));
	case LINUX_MADV_DONTNEED_LOCKED:
		/*
		 * DONTNEED that is additionally permitted on locked pages.
		 * Our DONTNEED rejects wired ranges with EINVAL, which is
		 * merely stricter than Linux; the unlocked case is identical.
		 */
		return (linux_madvise_dontneed(td, addr, addr + len));
	case LINUX_MADV_REMOVE:
		/*
		 * Punch a hole (zero-fill on next access) in a shared
		 * mapping.  FreeBSD has no page-range deallocation that
		 * guarantees zero-fill for swap objects or tmpfs vnodes from
		 * madvise, and MADV_FREE does not guarantee zeros, so report
		 * what Linux reports for an object that cannot do it.
		 */
		return (EOPNOTSUPP);
	case LINUX_MADV_DONTFORK:
		return (kern_minherit(td, addr, len, INHERIT_NONE));
	case LINUX_MADV_DOFORK:
		return (kern_minherit(td, addr, len, INHERIT_COPY));
	case LINUX_MADV_MERGEABLE:
	case LINUX_MADV_UNMERGEABLE:
		/* KSM hints; we never merge, so both are honoured as no-ops. */
		return (0);
	case LINUX_MADV_HUGEPAGE:
		/* Ignored; on FreeBSD huge pages are always on. */
		return (0);
	case LINUX_MADV_NOHUGEPAGE:
	case LINUX_MADV_COLLAPSE:
		/*
		 * Cannot be honoured: superpage promotion is not controllable
		 * per range and there is no synchronous collapse.  Linux
		 * without THP support returns EINVAL for both.  Not logged:
		 * Firefox and jemalloc probe NOHUGEPAGE routinely.
		 */
		return (EINVAL);
	case LINUX_MADV_POPULATE_READ:
	case LINUX_MADV_POPULATE_WRITE:
	case LINUX_MADV_GUARD_INSTALL:
	case LINUX_MADV_GUARD_REMOVE:
		/*
		 * Guaranteed prefaulting and guard regions have no FreeBSD
		 * equivalent (MADV_WILLNEED is only a hint); a pre-5.14 /
		 * pre-6.13 Linux kernel returns EINVAL for these as well.
		 */
		return (EINVAL);
	case LINUX_MADV_DONTDUMP:
		return (kern_madvise(td, addr, len, MADV_NOCORE));
	case LINUX_MADV_DODUMP:
		return (kern_madvise(td, addr, len, MADV_CORE));
	case LINUX_MADV_WIPEONFORK:
		return (kern_minherit(td, addr, len, INHERIT_ZERO));
	case LINUX_MADV_KEEPONFORK:
		return (kern_minherit(td, addr, len, INHERIT_COPY));
	case LINUX_MADV_HWPOISON:
	case LINUX_MADV_SOFT_OFFLINE:
		/*
		 * Memory-failure injection requires CAP_SYS_ADMIN on Linux
		 * and is not supported here at all: EPERM for the
		 * unprivileged, EINVAL for the privileged.
		 */
		if (priv_check(td, PRIV_VM_MADV_PROTECT) != 0)
			return (EPERM);
		return (EINVAL);
	case -1:
		/*
		 * -1 is sometimes used as a dummy value to detect simplistic
		 * madvise(2) stub implementations.  This safeguard is used by
		 * BoringSSL, for example, before assuming MADV_WIPEONFORK is
		 * safe to use.  Don't produce an "unsupported" error message
		 * for this special dummy value, which is unlikely to be used
		 * by any new advisory behavior feature.
		 */
		return (EINVAL);
	default:
		linux_msg(curthread, "unsupported madvise behav %d", behav);
		return (EINVAL);
	}
}

#if defined(__amd64__)
static void
linux_fixup_prot(struct thread *td, int *prot)
{
	struct linux_pemuldata *pem;

	if (SV_PROC_FLAG(td->td_proc, SV_ILP32) && *prot & PROT_READ) {
		pem = pem_find(td->td_proc);
		if (pem->persona & LINUX_READ_IMPLIES_EXEC)
			*prot |= PROT_EXEC;
	}

}
#endif
