/*-
 * Copyright (c) 2018 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/lock.h>
#include <sys/mutex.h>
#include <machine/vmparam.h>
#include <vm/vm_page.h>
#include <machine/pmap.h>
#include <vm/pmap.h>

/*
 * The DTrace alternative to PHYS_TO_DMAP.
 *
 * This is necessary because the kernel's PHYS_TO_DMAP has an assertion
 * that we can not guarantee in the DTrace probe context when an address
 * from the wrong address space has been given to the nested page table
 * walk. Instead, we simply return 0 if it's an invalid address and handle
 * the error in the caller.
 */
static uintptr_t
DTRACE_PHYS_TO_DMAP(uintptr_t x)
{
	if (dmaplimit != 0 && x < dmaplimit)
		return (x + kva_layout.dmap_low);

	return (0);
}

static __inline boolean_t
dtrace_emulate_ad_bits(pmap_t pmap)
{

	return ((pmap->pm_flags & PMAP_EMULATE_AD_BITS) != 0);
}

static __inline pt_entry_t
dtrace_valid_bit(pmap_t pmap)
{
	pt_entry_t mask;

	/* The only caller (dtrace_get_page()) accepts EPT and RVI pmaps. */
	KASSERT(pmap->pm_type == PT_EPT || pmap->pm_type == PT_RVI,
	    ("%s: pm_type %d", __func__, pmap->pm_type));
	if (pmap->pm_type == PT_RVI)
		mask = X86_PG_V;
	else if (dtrace_emulate_ad_bits(pmap))
		mask = EPT_PG_EMUL_V;
	else
		mask = EPT_PG_READ;

	return (mask);
}

/*
 * DTRACE_PHYS_TO_VM_PAGE is similar to PHYS_TO_VM_PAGE with a gotcha.
 * It is not safe to acquire any kind of lock in the DTrace probe
 * context, therefore we are not able to walk the red-black tree of VM
 * mappings that is present for sparse mappings. Hence, this function
 * only works on architectures with dense mappings.
 */
static vm_page_t
DTRACE_PHYS_TO_VM_PAGE(vm_paddr_t pa)
{
#ifndef VM_PHYSSEG_DENSE
#error "Need dense paging."
#endif
	vm_page_t m;
	long pi;

	pi = atop(pa);
	if (pi < first_page || pi - first_page >= vm_page_array_size)
		return (NULL);
	m = &vm_page_array[pi - first_page];
	return (m);
}

/*
 * A helper function that returns the host VM page.
 */
static vm_page_t
dtrace_get_page(pmap_t pmap, vm_offset_t va, int prot, bool checked)
{
	volatile pt_entry_t *table;
	pt_entry_t entry, valid, writable;
	vm_paddr_t pa;
	uintptr_t next;
	int level, shift;

	/* dtrace_gla2hva(), the only caller, refuses a NULL pmap. */
	KASSERT(pmap != NULL, ("%s: pmap != NULL", __func__));
	if (pmap->pm_pmltop == NULL ||
	    (pmap->pm_type != PT_EPT && pmap->pm_type != PT_RVI))
		return (NULL);
	level = pmap->pm_type == PT_RVI && la57 ? 4 : 3;
	if ((va >> (PAGE_SHIFT + (level + 1) * 9)) != 0)
		return (NULL);
	valid = dtrace_valid_bit(pmap);
	writable = pmap->pm_type == PT_RVI ? X86_PG_RW :
	    dtrace_emulate_ad_bits(pmap) ? EPT_PG_EMUL_RW : EPT_PG_WRITE;
	table = pmap->pm_pmltop;
	/* Every level returns: level 0 always ends the walk. */
	for (;; level--) {
		KASSERT(level >= 0, ("%s: level >= 0", __func__));
		shift = PAGE_SHIFT + level * 9;
		entry = table[(va >> shift) & 0x1ff];
		if ((entry & valid) == 0 || (checked &&
		    (prot & VM_PROT_WRITE) != 0 && (entry & writable) == 0))
			return (NULL);
		if (level == 0 || (entry & PG_PS) != 0) {
			if (level > 2 || (checked && (entry & PG_MANAGED) == 0))
				return (NULL);
			pa = (entry & PG_FRAME & ~((1UL << shift) - 1)) |
			    (va & ((1UL << shift) - 1));
			return (DTRACE_PHYS_TO_VM_PAGE(pa));
		}
		next = DTRACE_PHYS_TO_DMAP(entry & PG_FRAME);
		if (next == 0)
			return (NULL);
		table = (volatile pt_entry_t *)next;
	}
}

/*
 * This is the main function of this file. It performs a nested page table
 * walk in order to translate a guest virtual address to a host virtual
 * address. It has two fundamental failure modes:
 *
 *  1) A part of the translation has failed.
 *  2) The resulting address is not mapped and therefore causes a fault.
 *
 * The former manifests inside this function and the result is that hva is
 * set to 0, while the latter manifests in the caller. Because this is
 * intended to be called in the probe context, the usual DTrace error
 * handling code ought to take care of problem (2).
 */
static int
dtrace_gla2hva_impl(struct vm_guest_paging *paging, uint64_t gla, uint64_t *hva,
    int prot, bool checked, vm_page_t *page)
{
	volatile uint64_t *table;
	volatile uint32_t *table32;
	uint64_t pte, gpa, mask, pgsize;
	uintptr_t base;
	vm_page_t m;
	pmap_t pmap;
	int level, shift, width;

	*hva = 0;
	if (paging == NULL || paging->pmap == NULL || (!checked && paging->cpl == 3))
		return (EINVAL);
	pmap = paging->pmap;
	gpa = gla;
	if (paging->paging_mode == PAGING_MODE_32) {
		if (gla > UINT32_MAX)
			return (EINVAL);
		gpa = paging->cr3 & 0xfffff000UL;
		/* Level 0 always breaks out. */
		for (level = 1;; level--) {
			KASSERT(level >= 0, ("%s: level >= 0", __func__));
			m = dtrace_get_page(pmap, gpa, VM_PROT_READ, checked);
			if (m == NULL)
				return (EINVAL);
			base = DTRACE_PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
			if (base == 0)
				return (EINVAL);
			table32 = (volatile uint32_t *)base;
			shift = PAGE_SHIFT + level * 10;
			pgsize = 1UL << shift;
			pte = table32[(gla >> shift) & 0x3ff];
			if ((pte & X86_PG_V) == 0 || (checked &&
			    ((paging->cpl == 3 && (pte & X86_PG_U) == 0) ||
			    ((prot & VM_PROT_WRITE) != 0 && (pte & X86_PG_RW) == 0))))
				return (EINVAL);
			if (level == 0 || (pte & PG_PS) != 0) {
				/* Do not alias unsupported PSE-36 frames below 4 GiB. */
				if (level == 1 && (pte & 0x003fe000UL) != 0)
					return (EINVAL);
				gpa = (pte & ~(pgsize - 1)) | (gla & (pgsize - 1));
				break;
			}
			gpa = pte & 0xfffff000UL;
		}
	} else if (paging->paging_mode != PAGING_MODE_FLAT) {
		if (paging->paging_mode == PAGING_MODE_PAE) {
			if (gla > UINT32_MAX)
				return (EINVAL);
			/* PAE's four-entry root can start at any 32-byte boundary. */
			gpa = paging->cr3 & 0xffffffe0UL;
			m = dtrace_get_page(pmap, trunc_page(gpa), VM_PROT_READ, checked);
			if (m == NULL)
				return (EINVAL);
			base = DTRACE_PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
			if (base == 0)
				return (EINVAL);
			table = (volatile uint64_t *)(base + (gpa & PAGE_MASK));
			pte = table[(gla >> 30) & 3];
			if ((pte & X86_PG_V) == 0 || (pte & PG_PS) != 0)
				return (EINVAL);
			gpa = pte & PG_FRAME;
			level = 1;
		} else {
			if (paging->paging_mode != PAGING_MODE_64 &&
			    paging->paging_mode != PAGING_MODE_64_LA57)
				return (EINVAL);
			level = paging->paging_mode == PAGING_MODE_64_LA57 ? 4 : 3;
			width = PAGE_SHIFT + (level + 1) * 9;
			mask = ~((1UL << width) - 1);
			if ((gla & mask) !=
			    ((gla & (1UL << (width - 1))) ? mask : 0))
				return (EINVAL);
			gpa = paging->cr3 & PG_FRAME;
		}
		/* Level 0 always breaks out. */
		for (;; level--) {
			KASSERT(level >= 0, ("%s: level >= 0", __func__));
			m = dtrace_get_page(pmap, gpa, VM_PROT_READ, checked);
			if (m == NULL)
				return (EINVAL);
			base = DTRACE_PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
			if (base == 0)
				return (EINVAL);
			table = (volatile uint64_t *)base;
			shift = PAGE_SHIFT + level * 9;
			pgsize = 1UL << shift;
			pte = table[(gla >> shift) & 0x1ff];
			if ((pte & X86_PG_V) == 0 || (checked &&
			    ((paging->cpl == 3 && (pte & X86_PG_U) == 0) ||
			    ((prot & VM_PROT_WRITE) != 0 && (pte & X86_PG_RW) == 0))))
				return (EINVAL);
			/* Tracing observes the tables; it never updates A/D bits. */
			if (level == 0 || (pte & PG_PS) != 0) {
				if (level > 2)
					return (EINVAL);
				gpa = (pte & PG_FRAME & ~(pgsize - 1)) |
				    (gla & (pgsize - 1));
				break;
			}
			gpa = pte & PG_FRAME;
		}
	}
	m = dtrace_get_page(pmap, trunc_page(gpa), prot, checked);
	if (m == NULL)
		return (EINVAL);
	base = DTRACE_PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
	if (base == 0)
		return (EINVAL);
	*hva = base + (gpa & PAGE_MASK);
	if (page != NULL)
		*page = m;
	return (0);
}

/* Legacy pointer interface; callers retain its existing lifetime contract. */
int
dtrace_gla2hva(struct vm_guest_paging *paging, uint64_t gla, uint64_t *hva)
{

	return (dtrace_gla2hva_impl(paging, gla, hva, VM_PROT_READ, false, NULL));
}

/*
 * HyperTrace runs with interrupts disabled.  Its memory access must neither
 * fault in a host page nor acquire an instrumented VM lock.  The VMM holds
 * the pmap lock across probe execution, keeping managed mappings and their
 * pages stable.  Read only resident RAM, including guest page-table pages.
 *
 * The VMM supplies the L1 pmap for an L1 hypercall.  L2 hypercalls belong to
 * L1 and must not be admitted with L0's L1 paging context.
 */
int
dtrace_guest_copy(struct vm_guest_paging *paging, uint64_t gla, void *buffer,
    size_t length, int prot)
{
	vm_page_t pages[2];
	uint64_t addresses[2];
	size_t chunks[2], done;
	pmap_t pmap;
	int error, i, count;

	if (paging == NULL || paging->pmap == NULL || buffer == NULL ||
	    length == 0 || length > PAGE_SIZE ||
	    gla > UINT64_MAX - (length - 1) ||
	    (prot != VM_PROT_READ && prot != VM_PROT_WRITE) ||
	    (paging->cpl == 3 && paging->paging_mode == PAGING_MODE_FLAT))
		return (EINVAL);
	pmap = paging->pmap;
	if (!PMAP_LOCKED(pmap))
		return (EFAULT);
	/* Resolve both pages first: failure must not publish a partial copy. */
	for (done = 0, count = 0; done < length; count++) {
		error = dtrace_gla2hva_impl(paging, gla + done,
		    &addresses[count], prot, true, &pages[count]);
		if (error != 0) {
			return (EFAULT);
		}
		chunks[count] = MIN(length - done,
		    PAGE_SIZE - ((gla + done) & PAGE_MASK));
		done += chunks[count];
	}
	for (done = 0, i = 0; i < count; i++) {
		if (prot == VM_PROT_WRITE) {
			/* Direct-map writes bypass the pmap's hardware dirty bit. */
			/* Avoid the instrumentable vm_page_dirty_KBI() call. */
			pages[i]->dirty = VM_PAGE_BITS_ALL;
			memcpy((void *)(uintptr_t)addresses[i],
			    (const char *)buffer + done, chunks[i]);
		} else {
			memcpy((char *)buffer + done,
			    (const void *)(uintptr_t)addresses[i], chunks[i]);
		}
		done += chunks[i];
	}
	return (0);
}
