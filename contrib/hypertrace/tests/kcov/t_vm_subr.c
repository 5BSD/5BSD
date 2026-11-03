/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for sys/cddl/dev/dtrace/amd64/dtrace_vm_subr.c compiled unmodified
 * as a kernel translation unit: dtrace_gla2hva(), the nested page-table walk
 * that turns a guest linear address into a host virtual address in DTrace
 * probe context.
 *
 * "Host physical memory" is a page-aligned arena; the direct map is that
 * arena (kva_layout.dmap_low = arena, dmaplimit = its size) and vm_page_array
 * describes its pages densely.  Each case builds the guest's own page tables
 * (32-bit, PAE, 4- or 5-level long mode) inside guest-physical pages, and a
 * nested EPT or RVI table that maps guest-physical to host-physical pages.
 * The oracle is the mapping each case constructs by hand: the expected host
 * virtual address is arena + host page + offset, per the Intel SDM and AMD
 * APM table formats, never recomputed by walking tables in the test.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/hypertrace.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <machine/pmap.h>
#include <machine/vmm.h>
#include <machine/md_var.h>

#include "khx_kern.h"

int dtrace_gla2hva(struct vm_guest_paging *, uint64_t, uint64_t *);

#define	NPAGES	96
static char arena[NPAGES * PAGE_SIZE] __aligned(PAGE_SIZE);
static struct vm_page pages[NPAGES];

/* The kernel globals the walker reads. */
vm_paddr_t dmaplimit;
struct kva_layout_s kva_layout;
int la57;
long first_page;
vm_page_t vm_page_array;
long vm_page_array_size;

static int next_hpage;		/* host page bump allocator */
static bool pmap_initialized;
static struct pmap npmap;	/* the nested (EPT/RVI) pmap */
static uint64_t nvalid;		/* valid bit for nested entries */

static void
reset(int type, int flags)
{
	memset(arena, 0, sizeof(arena));
	dmaplimit = sizeof(arena);
	kva_layout.dmap_low = (vm_offset_t)arena;
	kva_layout.dmap_high = (vm_offset_t)arena + sizeof(arena);
	for (int i = 0; i < NPAGES; i++)
		pages[i].phys_addr = (vm_paddr_t)i * PAGE_SIZE;
	vm_page_array = pages;
	vm_page_array_size = NPAGES;
	first_page = 0;
	if (pmap_initialized)
		mtx_destroy(&npmap.pm_mtx);
	pmap_initialized = true;
	memset(&npmap, 0, sizeof(npmap));
	mtx_init(&npmap.pm_mtx, "test pmap", NULL, MTX_DEF);
	npmap.pm_type = type;
	npmap.pm_flags = flags;
	nvalid = type == PT_EPT ?
	    ((flags & PMAP_EMULATE_AD_BITS) ? EPT_PG_EMUL_V : EPT_PG_READ) :
	    X86_PG_V;
	next_hpage = 0;
	npmap.pm_pmltop = (pml4_entry_t *)(void *)arena;	/* host page 0 */
	next_hpage = 1;
}

static uint64_t
hpage(void)
{
	KHX_CHECK(next_hpage < NPAGES);
	return ((uint64_t)next_hpage++ * PAGE_SIZE);
}

static uint64_t *
hva_of(uint64_t hpa)
{
	return ((uint64_t *)(void *)(arena + hpa));
}

/*
 * Map guest-physical gpa to host-physical hpa in the nested table with a
 * leaf at `leaf' (0 = 4 KiB, 1 = 2 MiB, 2 = 1 GiB).  `top' is the root
 * level (3 for 4-level, 4 for 5-level RVI).
 */
static void
nmap(uint64_t gpa, uint64_t hpa, int top, int leaf)
{
	uint64_t *table = hva_of(0);

	for (int level = top; level > leaf; level--) {
		int idx = (gpa >> (PAGE_SHIFT + 9 * level)) & 0x1ff;

		if ((table[idx] & nvalid) == 0)
			table[idx] = hpage() | nvalid | (npmap.pm_type == PT_RVI ?
			    X86_PG_RW : EPT_PG_WRITE | EPT_PG_EMUL_RW);
		table = hva_of(table[idx] & PG_FRAME);
	}
	table[(gpa >> (PAGE_SHIFT + 9 * leaf)) & 0x1ff] = hpa | nvalid | PG_MANAGED |
	    (npmap.pm_type == PT_RVI ? X86_PG_RW :
	    EPT_PG_WRITE | EPT_PG_EMUL_RW) |
	    (leaf != 0 ? PG_PS : 0);
}

/* Identity-map guest-physical pages [0, n) onto fresh host pages; returns
 * the host page of guest page 0, so guest page g is at base + g * 4K. */
static uint64_t
nmap_guest_ram(int n, int top)
{
	uint64_t base = (uint64_t)next_hpage * PAGE_SIZE;

	/* Build the nested tables for the low 2 MiB first (all of guest RAM
	 * shares them), then reserve guest RAM contiguously above them and
	 * map it page by page. */
	nmap(0, 0, top, 0);
	base = (uint64_t)next_hpage * PAGE_SIZE;
	next_hpage += n;
	KHX_CHECK(next_hpage < NPAGES);
	for (int g = 0; g < n; g++)
		nmap((uint64_t)g * PAGE_SIZE, base + (uint64_t)g * PAGE_SIZE,
		    top, 0);
	return (base);
}

/* Guest RAM layout (guest-physical page numbers). */
#define	G_ROOT	1
#define	G_L3	2
#define	G_L2	3
#define	G_L1	4
#define	G_L0	5
#define	G_DATA	6
#define	G_RAM	12

static uint64_t gram;		/* host physical address of guest page 0 */

static uint64_t *
gtable(int gpage)
{
	return (hva_of(gram + (uint64_t)gpage * PAGE_SIZE));
}

static uint64_t
expect_hva(uint64_t gpa)
{
	return ((uint64_t)(uintptr_t)arena + gram + gpa);
}

static int
walk(uint64_t cr3, int mode, uint64_t gla, uint64_t *hva)
{
	struct vm_guest_paging p = {
		.cr3 = cr3, .cpl = 0, .pmap = &npmap,
		.cpu_mode = CPU_MODE_64BIT, .paging_mode = mode,
	};

	return (dtrace_gla2hva(&p, gla, hva));
}

/* ---- long mode -------------------------------------------------------- */
static void
case_long_mode(int type, int flags)
{
	uint64_t hva, gla = 0x00007f8040201234ULL;	/* indices 255/1/1/1 */

	khx_host_case(type == PT_EPT ? "long-mode-ept" : "long-mode-rvi");
	reset(type, flags);
	gram = nmap_guest_ram(G_RAM, 3);
	/* 4 KiB guest page: PML4[255] -> PDPT[1] -> PD[1] -> PT[1]. */
	gtable(G_ROOT)[255] = (G_L2 * PAGE_SIZE) | X86_PG_V;
	gtable(G_L2)[1] = (G_L1 * PAGE_SIZE) | X86_PG_V;
	gtable(G_L1)[1] = (G_L0 * PAGE_SIZE) | X86_PG_V;
	gtable(G_L0)[1] = (G_DATA * PAGE_SIZE) | X86_PG_V;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64, gla, &hva), 0);
	KHX_EQ(hva, expect_hva(G_DATA * PAGE_SIZE + 0x234));

	/* The CR3 low bits (PCID/flags) are ignored. */
	KHX_EQ(walk(G_ROOT * PAGE_SIZE | 0xfff, PAGING_MODE_64, gla, &hva), 0);
	KHX_EQ(hva, expect_hva(G_DATA * PAGE_SIZE + 0x234));

	/* Not present at each guest level. */
	gtable(G_L0)[1] = 0;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64, gla, &hva), EINVAL);
	KHX_EQ(hva, 0);
	gtable(G_L0)[1] = (G_DATA * PAGE_SIZE) | X86_PG_V;
	gtable(G_L1)[1] = 0;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64, gla, &hva), EINVAL);

	/* A 2 MiB guest page in the PD: guest-physical 0x200000-aligned
	 * frame plus the low 21 bits of the address; frame 0 maps guest
	 * page 0 onward. */
	gtable(G_L1)[1] = 0 | X86_PG_V | PG_PS;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64,
	    0x00007f8040200000ULL + 0x6123, &hva), 0);
	KHX_EQ(hva, expect_hva(0x6123));
	/* A 1 GiB guest page in the PDPT. */
	gtable(G_L2)[1] = 0 | X86_PG_V | PG_PS;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64,
	    0x00007f8040000000ULL + 0x7456, &hva), 0);
	KHX_EQ(hva, expect_hva(0x7456));
	/* PS is reserved in a PML4 entry. */
	gtable(G_ROOT)[255] = (G_L2 * PAGE_SIZE) | X86_PG_V | PG_PS;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64, gla, &hva), EINVAL);
	gtable(G_ROOT)[255] = (G_L2 * PAGE_SIZE) | X86_PG_V;

	/* Non-canonical addresses never walk. */
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64,
	    0x0000800000000000ULL, &hva), EINVAL);
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64,
	    0xffff7fffffffffffULL, &hva), EINVAL);

	/* A canonical upper-half address: PML4[511]. */
	gtable(G_ROOT)[511] = (G_L3 * PAGE_SIZE) | X86_PG_V;
	gtable(G_L3)[511] = 0 | X86_PG_V | PG_PS;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64,
	    0xffffffffc0000000ULL + 0x5010, &hva), 0);
	KHX_EQ(hva, expect_hva(0x5010));

	/* A guest table outside guest RAM: the nested walk fails. */
	gtable(G_ROOT)[255] = (0x40000000ULL) | X86_PG_V;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64, gla, &hva), EINVAL);
	/* A final guest frame outside guest RAM. */
	gtable(G_ROOT)[255] = (G_L2 * PAGE_SIZE) | X86_PG_V;
	gtable(G_L2)[1] = 0x40000000ULL | X86_PG_V | PG_PS;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64, gla, &hva), EINVAL);
}

static void
case_la57(void)
{
	uint64_t hva, gla = 0x00ff000000000000ULL | 0x321;

	khx_host_case("la57");
	reset(PT_RVI, 0);
	la57 = 1;
	gram = nmap_guest_ram(G_RAM, 4);
	/* PML5[1] -> PML4[0x1fe] ... using 1 GiB leaf in the PDPT. */
	gtable(G_ROOT)[(gla >> 48) & 0x1ff] = (G_L3 * PAGE_SIZE) | X86_PG_V;
	gtable(G_L3)[(gla >> 39) & 0x1ff] = (G_L2 * PAGE_SIZE) | X86_PG_V;
	gtable(G_L2)[(gla >> 30) & 0x1ff] = 0 | X86_PG_V | PG_PS;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64_LA57, gla, &hva), 0);
	KHX_EQ(hva, expect_hva(0x321));
	/* 57-bit canonical form. */
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64_LA57,
	    0x0100000000000000ULL, &hva), EINVAL);
	/* PS in a PML4 entry (level 3) is reserved. */
	gtable(G_L3)[(gla >> 39) & 0x1ff] = (G_L2 * PAGE_SIZE) | X86_PG_V |
	    PG_PS;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_64_LA57, gla, &hva),
	    EINVAL);
	la57 = 0;
}

/* ---- legacy modes ----------------------------------------------------- */
static void
case_32bit(void)
{
	uint32_t *pd, *pt;
	uint64_t hva;

	khx_host_case("paging-32");
	reset(PT_EPT, 0);
	gram = nmap_guest_ram(G_RAM, 3);
	pd = (uint32_t *)gtable(G_ROOT);
	pt = (uint32_t *)gtable(G_L0);
	/* gla 0x00401abc: PD[1] -> PT[1] -> page G_DATA, offset 0xabc. */
	pd[1] = (G_L0 * PAGE_SIZE) | X86_PG_V;
	pt[1] = (G_DATA * PAGE_SIZE) | X86_PG_V;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_32, 0x00401abc, &hva), 0);
	KHX_EQ(hva, expect_hva(G_DATA * PAGE_SIZE + 0xabc));
	/* A 4 MiB page (PSE): frame bits 31:22. */
	pd[2] = 0 | X86_PG_V | PG_PS;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_32, 0x00805678, &hva), 0);
	KHX_EQ(hva, expect_hva(0x5678));
	/* PSE-36 high frame bits (20:13) are not supported. */
	pd[2] = 0 | X86_PG_V | PG_PS | (1u << 13);
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_32, 0x00805678, &hva),
	    EINVAL);
	/* Not present PDE / PTE, and the root outside guest RAM. */
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_32, 0x00c00000, &hva),
	    EINVAL);
	pt[1] = 0;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_32, 0x00401abc, &hva),
	    EINVAL);
	KHX_EQ(walk(0x40000000, PAGING_MODE_32, 0x00401abc, &hva), EINVAL);
	/* 32-bit linear addresses only. */
	KHX_EQ(walk(G_ROOT * PAGE_SIZE, PAGING_MODE_32, 0x100000000ULL, &hva),
	    EINVAL);
}

static void
case_pae(void)
{
	uint64_t *pdpt, hva;

	khx_host_case("paging-pae");
	reset(PT_EPT, PMAP_EMULATE_AD_BITS);
	gram = nmap_guest_ram(G_RAM, 3);
	/* The four-entry PDPT may sit at any 32-byte boundary. */
	pdpt = (uint64_t *)(void *)((char *)gtable(G_ROOT) + 0x60);
	pdpt[1] = (G_L1 * PAGE_SIZE) | X86_PG_V;		/* 1-2 GiB */
	gtable(G_L1)[2] = (G_L0 * PAGE_SIZE) | X86_PG_V;	/* +4 MiB */
	gtable(G_L0)[3] = (G_DATA * PAGE_SIZE) | X86_PG_V;	/* +12 KiB */
	KHX_EQ(walk(G_ROOT * PAGE_SIZE + 0x60, PAGING_MODE_PAE,
	    0x40000000 + 0x400000 + 0x3000 + 0x111, &hva), 0);
	KHX_EQ(hva, expect_hva(G_DATA * PAGE_SIZE + 0x111));
	/* A 2 MiB PAE page. */
	gtable(G_L1)[3] = 0 | X86_PG_V | PG_PS;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE + 0x60, PAGING_MODE_PAE,
	    0x40000000 + 0x600000 + 0x4222, &hva), 0);
	KHX_EQ(hva, expect_hva(0x4222));
	/* PDPTEs have no PS bit; not-present PDPTE; root outside RAM. */
	pdpt[2] = (G_L1 * PAGE_SIZE) | X86_PG_V | PG_PS;
	KHX_EQ(walk(G_ROOT * PAGE_SIZE + 0x60, PAGING_MODE_PAE, 0x80000000,
	    &hva), EINVAL);
	KHX_EQ(walk(G_ROOT * PAGE_SIZE + 0x60, PAGING_MODE_PAE, 0xc0000000,
	    &hva), EINVAL);
	KHX_EQ(walk(0x40000000, PAGING_MODE_PAE, 0x40000000, &hva), EINVAL);
	KHX_EQ(walk(G_ROOT * PAGE_SIZE + 0x60, PAGING_MODE_PAE,
	    0x100000000ULL, &hva), EINVAL);
}

/* A guest table page that has a vm_page but lies beyond the direct map. */
static void
case_table_outside_dmap(void)
{
	uint64_t hva;
	static const int modes[] = { PAGING_MODE_32, PAGING_MODE_PAE,
	    PAGING_MODE_64 };

	khx_host_case("table-outside-dmap");
	/* No direct map at all. */
	reset(PT_RVI, 0);
	gram = nmap_guest_ram(G_RAM, 3);
	dmaplimit = 0;
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0x1000, &hva), EINVAL);
	for (size_t i = 0; i < nitems(modes); i++) {
		reset(PT_RVI, 0);
		gram = nmap_guest_ram(G_RAM, 3);
		dmaplimit = gram + G_ROOT * PAGE_SIZE;
		KHX_EQ(walk(G_ROOT * PAGE_SIZE, modes[i], 0x1000, &hva),
		    EINVAL);
		KHX_EQ(hva, 0);
	}
}

static void
case_flat_and_args(void)
{
	struct vm_guest_paging p;
	uint64_t hva = 1;

	khx_host_case("flat-and-arguments");
	reset(PT_RVI, 0);
	gram = nmap_guest_ram(G_RAM, 3);
	/* Paging disabled: linear == guest-physical. */
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 3 * PAGE_SIZE + 0x42, &hva), 0);
	KHX_EQ(hva, expect_hva(3 * PAGE_SIZE + 0x42));
	KHX_EQ(walk(0, PAGING_MODE_FLAT, G_RAM * PAGE_SIZE, &hva), EINVAL);
	/* Unknown paging mode. */
	KHX_EQ(walk(0, 77, 0, &hva), EINVAL);
	/* No paging description, no nested pmap, or a user-mode (CPL 3)
	 * caller: refused, *hva cleared. */
	hva = 1;
	KHX_EQ(dtrace_gla2hva(NULL, 0, &hva), EINVAL);
	KHX_EQ(hva, 0);
	memset(&p, 0, sizeof(p));
	p.paging_mode = PAGING_MODE_FLAT;
	KHX_EQ(dtrace_gla2hva(&p, 0, &hva), EINVAL);
	p.pmap = &npmap;
	p.cpl = 3;
	KHX_EQ(dtrace_gla2hva(&p, 0, &hva), EINVAL);
}

static void
case_nested(void)
{
	uint64_t hva;

	khx_host_case("nested-tables");
	/* Nested 2 MiB and 1 GiB leaves. */
	reset(PT_EPT, 0);
	gram = (uint64_t)next_hpage * PAGE_SIZE;
	gram = roundup2(gram, PAGE_SIZE);
	nmap(0, 32 * PAGE_SIZE, 3, 0);
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0x10, &hva), 0);
	KHX_EQ(hva, (uint64_t)(uintptr_t)arena + 32 * PAGE_SIZE + 0x10);
	/* A 2 MiB nested leaf whose frame is page 0: the walker returns the
	 * vm_page of the 4K page within it. */
	reset(PT_EPT, 0);
	nmap(0x200000, 0, 3, 1);
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0x200000 + 5 * PAGE_SIZE + 7, &hva),
	    0);
	KHX_EQ(hva, (uint64_t)(uintptr_t)arena + 5 * PAGE_SIZE + 7);
	reset(PT_RVI, 0);
	nmap(0x40000000, 0, 3, 2);
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0x40000000 + 9 * PAGE_SIZE, &hva), 0);
	KHX_EQ(hva, (uint64_t)(uintptr_t)arena + 9 * PAGE_SIZE);
	/* A host frame beyond the dense vm_page array. */
	reset(PT_RVI, 0);
	nmap(0, (uint64_t)NPAGES * PAGE_SIZE, 3, 0);
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0, &hva), EINVAL);
	/* A frame below first_page. */
	reset(PT_RVI, 0);
	nmap(0, 2 * PAGE_SIZE, 3, 0);
	first_page = 4;
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0, &hva), EINVAL);
	first_page = 0;
	/* A nested table frame outside the direct map. */
	reset(PT_RVI, 0);
	hva_of(0)[0] = (uint64_t)sizeof(arena) | X86_PG_V;
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0, &hva), EINVAL);
	/* A data page outside the direct map (dmaplimit shrinks after the
	 * vm_page lookup succeeds). */
	reset(PT_RVI, 0);
	nmap(0, 40 * PAGE_SIZE, 3, 0);
	dmaplimit = 40 * PAGE_SIZE;
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0, &hva), EINVAL);
	/* PS at the nested root is reserved. */
	reset(PT_EPT, 0);
	hva_of(0)[0] = 0 | nvalid | PG_PS;
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0, &hva), EINVAL);
	/* Not present nested entry; guest-physical beyond the nested width. */
	reset(PT_EPT, 0);
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0, &hva), EINVAL);
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 1ULL << 48, &hva), EINVAL);
	/* Host page tables (PT_X86) and missing roots are not nested pmaps. */
	reset(PT_X86, 0);
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0, &hva), EINVAL);
	reset(PT_RVI, 0);
	npmap.pm_pmltop = NULL;
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0, &hva), EINVAL);
	/* EPT with emulated A/D bits uses its own valid bit: an entry with
	 * only the hardware read bit is not present. */
	reset(PT_EPT, PMAP_EMULATE_AD_BITS);
	hva_of(0)[0] = hpage() | EPT_PG_READ;
	KHX_EQ(walk(0, PAGING_MODE_FLAT, 0, &hva), EINVAL);
}

static void
case_resident_copy(int type, int flags)
{
	struct vm_guest_paging p;
	char b[8];
	uint64_t bits = X86_PG_V | X86_PG_U | X86_PG_RW;

	khx_host_case("resident-copy");
	reset(type, flags);
	gram = nmap_guest_ram(G_RAM, 3);
	p = (struct vm_guest_paging){ .cr3 = G_ROOT * PAGE_SIZE,
	    .cpl = 3, .pmap = &npmap, .cpu_mode = CPU_MODE_64BIT,
	    .paging_mode = PAGING_MODE_64 };
	gtable(G_ROOT)[0] = G_L2 * PAGE_SIZE | bits;
	gtable(G_L2)[0] = G_L1 * PAGE_SIZE | bits;
	gtable(G_L1)[0] = G_L0 * PAGE_SIZE | bits;
	gtable(G_L0)[0] = G_DATA * PAGE_SIZE | bits;
	gtable(G_L0)[1] = (G_DATA + 1) * PAGE_SIZE | bits;
	memcpy((char *)gtable(G_DATA) + PAGE_SIZE - 4, "ABCDEFGH", 8);
	PMAP_LOCK(&npmap);
	KHX_EQ(dtrace_guest_copy(&p, PAGE_SIZE - 4, b, 8, VM_PROT_READ), 0);
	KHX_EQ(memcmp(b, "ABCDEFGH", 8), 0);
	KHX_EQ(dtrace_guest_copy(&p, PAGE_SIZE - 4, "12345678", 8,
	    VM_PROT_WRITE), 0);
	KHX_EQ(memcmp((char *)gtable(G_DATA) + PAGE_SIZE - 4, "12345678", 8), 0);
	KHX_EQ(pages[gram / PAGE_SIZE + G_DATA].dirty, VM_PAGE_BITS_ALL);
	KHX_EQ(pages[gram / PAGE_SIZE + G_DATA + 1].dirty, VM_PAGE_BITS_ALL);
	/* Permission failure on the second page cannot modify the first. */
	gtable(G_L0)[1] &= ~X86_PG_RW;
	KHX_EQ(dtrace_guest_copy(&p, PAGE_SIZE - 4, "XXXXXXXX", 8,
	    VM_PROT_WRITE), EFAULT);
	KHX_EQ(memcmp((char *)gtable(G_DATA) + PAGE_SIZE - 4, "12345678", 8), 0);
	gtable(G_L0)[1] &= ~X86_PG_U;
	memset(b, 'Z', sizeof(b));
	KHX_EQ(dtrace_guest_copy(&p, PAGE_SIZE - 4, b, 8, VM_PROT_READ), EFAULT);
	KHX_EQ(memcmp(b, "ZZZZZZZZ", 8), 0);
	gtable(G_L0)[1] |= bits;
	gtable(G_ROOT)[0] &= ~X86_PG_U;
	KHX_EQ(dtrace_guest_copy(&p, 0, b, 8, VM_PROT_READ), EFAULT);
	gtable(G_ROOT)[0] |= bits;
	/* Unmanaged host RAM and absent mappings must not be faulted in. */
	nmap(G_DATA * PAGE_SIZE, gram + G_DATA * PAGE_SIZE, 3, 0);
	uint64_t *t = hva_of(0);
	for (int level = 3; level > 0; level--)
		t = hva_of(t[0] & PG_FRAME);
	t[G_DATA] &= ~PG_MANAGED;
	KHX_EQ(dtrace_guest_copy(&p, 0, b, 8, VM_PROT_READ), EFAULT);
	t[G_DATA] |= PG_MANAGED;
	t[G_DATA] &= ~(type == PT_RVI ? X86_PG_RW :
	    flags ? EPT_PG_EMUL_RW : EPT_PG_WRITE);
	KHX_EQ(dtrace_guest_copy(&p, 0, b, 8, VM_PROT_WRITE), EFAULT);
	KHX_EQ(dtrace_guest_copy(&p, 0, b, 8, VM_PROT_READ), 0);
	KHX_EQ(dtrace_guest_copy(&p, UINT64_MAX - 2, b, 8, VM_PROT_READ), EINVAL);
	KHX_EQ(dtrace_guest_copy(&p, 0, b, PAGE_SIZE + 1, VM_PROT_READ), EINVAL);
	PMAP_UNLOCK(&npmap);
	/* A competing owner must cause an immediate failure, with no mutation. */
	struct thread *other = khx_thread_new("pmap owner", 0);
	struct thread *saved = khx_set_curthread(other);
	PMAP_LOCK(&npmap);
	khx_set_curthread(saved);
	memset(b, 'Q', sizeof(b));
	KHX_EQ(dtrace_guest_copy(&p, 0, b, 8, VM_PROT_READ), EFAULT);
	KHX_EQ(memcmp(b, "QQQQQQQQ", 8), 0);
	khx_set_curthread(other);
	PMAP_UNLOCK(&npmap);
	khx_set_curthread(saved);
	khx_thread_free(other);
}

int
khx_test_main(void)
{
	khx_kern_boot();
	case_long_mode(PT_EPT, 0);
	case_long_mode(PT_RVI, 0);
	case_la57();
	case_32bit();
	case_pae();
	case_table_outside_dmap();
	case_flat_and_args();
	case_nested();
	case_resident_copy(PT_RVI, 0);
	case_resident_copy(PT_EPT, 0);
	case_resident_copy(PT_EPT, PMAP_EMULATE_AD_BITS);
	mtx_destroy(&npmap.pm_mtx);
	return (khx_host_finish("dtrace_vm_subr"));
}
