/* SPDX-License-Identifier: BSD-2-Clause */
/* Synthetic page tables exercise the actual kernel walker functions. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE - 1)
#define PG_FRAME 0x000ffffffffff000UL
#define PG_PS 0x80
#define X86_PG_V 1
#define EPT_PG_READ 1
#define EPT_PG_EMUL_V 0x200
#define PMAP_EMULATE_AD_BITS 0x200
#define VM_PHYSSEG_DENSE 1
#define atop(pa) ((pa) >> PAGE_SHIFT)
#define trunc_page(pa) ((pa) & ~PAGE_MASK)
#define VM_PAGE_TO_PHYS(m) ((m)->pa)
typedef uintptr_t vm_paddr_t;
typedef uintptr_t vm_offset_t;
typedef uint64_t pt_entry_t;
typedef bool boolean_t;
struct vm_page { vm_paddr_t pa; } pages[64];
typedef struct vm_page *vm_page_t;
static vm_page_t vm_page_array = pages;
static long first_page, vm_page_array_size = 64;
static uintptr_t dmaplimit = 64 * PAGE_SIZE;
static struct { uintptr_t dmap_low; } kva_layout;
static bool la57;
enum { PT_X86, PT_RVI, PT_EPT };
struct pmap { uint64_t *pm_pmltop; int pm_type, pm_flags; };
typedef struct pmap *pmap_t;
enum { PAGING_MODE_FLAT, PAGING_MODE_32, PAGING_MODE_PAE,
    PAGING_MODE_64, PAGING_MODE_64_LA57 };
struct vm_guest_paging { uint64_t cr3; int cpl; void *pmap; int paging_mode; };
#define panic(...) abort()
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define CPU_DTRACE_NOFAULT 1
#define CPU_DTRACE_BADADDR 2
#define CPU_DTRACE_FAULT 2
#define curcpu 0
static struct { volatile uint16_t cpuc_dtrace_flags; uintptr_t cpuc_dtrace_illval; } cpu_core[1];
static struct vm_guest_paging *dtrace_get_paging(const void *h) { return (struct vm_guest_paging *)h; }
/* This fixture exercises the legacy translation fallback. The separate
 * guest-scalar-read fixture supplies the VMM's held-page callback. */
static int (*hypertrace_guest_copyin)(const void *, uint64_t, void *, size_t);
/* The runner inserts the selected unmodified kernel functions here. */
#include "walker.inc"
static uint8_t dtrace_load8(const void *h, uintptr_t addr) { return h ? dtrace_guest_load(h, addr, 1) : *(const uint8_t *)addr; }
#include "strings.inc"
static uint64_t *pt(unsigned page) { return (uint64_t *)(kva_layout.dmap_low + page * PAGE_SIZE); }
int main(void)
{
    void *arena = aligned_alloc(PAGE_SIZE, dmaplimit);
    assert(arena != NULL); memset(arena, 0, dmaplimit);
    kva_layout.dmap_low = (uintptr_t)arena;
    for (unsigned i = 0; i < 64; i++) pages[i].pa = i * PAGE_SIZE;
    uintptr_t mapped_limit = dmaplimit;
    dmaplimit = 0;
    assert(DTRACE_PHYS_TO_DMAP(0) == 0);
    dmaplimit = mapped_limit;
    struct pmap pm = { pt(0), PT_EPT, 0 };
    struct vm_guest_paging pg = { 3 * PAGE_SIZE, 0, &pm, PAGING_MODE_64 };
    pt(0)[0] = PAGE_SIZE | 1; pt(1)[0] = 2 * PAGE_SIZE | 1;
    pt(2)[0] = PG_PS | 1; /* identity nested mapping, 2 MiB */
    pt(3)[0] = 4 * PAGE_SIZE | 1; pt(4)[0] = 5 * PAGE_SIZE | 1;
    pt(5)[0] = 6 * PAGE_SIZE | 1; pt(6)[0] = 7 * PAGE_SIZE | 1;
    uint64_t hva;
    unsigned char before[64 * PAGE_SIZE]; memcpy(before, arena, sizeof(before));
    assert(dtrace_gla2hva(&pg, 25, &hva) == 0 && hva == (uintptr_t)pt(7) + 25);
    assert(memcmp(before, arena, sizeof(before)) == 0); /* no A/D updates */
    pt(6)[0] = 0;
    assert(dtrace_gla2hva(&pg, 25, &hva) == EINVAL && hva == 0);
    pt(6)[0] = 7 * PAGE_SIZE | 1;
    pt(2)[0] = 0;
    assert(dtrace_gla2hva(&pg, 25, &hva) == EINVAL && hva == 0);
    pt(2)[0] = PG_PS | 1;
    assert(dtrace_gla2hva(&pg, 1UL << 48, &hva) == EINVAL);
    pg.cr3 = 64 * PAGE_SIZE;
    assert(dtrace_gla2hva(&pg, 25, &hva) == EINVAL);
    pg.cr3 = 8 * PAGE_SIZE; pg.paging_mode = PAGING_MODE_64_LA57;
    pt(8)[0] = 3 * PAGE_SIZE | 1;
    assert(dtrace_gla2hva(&pg, 25, &hva) == 0 && hva == (uintptr_t)pt(7) + 25);
    assert(dtrace_gla2hva(&pg, 1UL << 57, &hva) == EINVAL);
    pm.pm_type = PT_RVI; la57 = true; pm.pm_pmltop = pt(9);
    pt(9)[0] = 1; /* fifth nested level points to page zero */
    assert(dtrace_gla2hva(&pg, 25, &hva) == 0 && hva == (uintptr_t)pt(7) + 25);
    pt(6)[1] = 11 * PAGE_SIZE | 1;
    memcpy((char *)pt(7) + PAGE_SIZE - 4, "ABCD", 4);
    memcpy(pt(11), "EFGH", 4);
    uint64_t value = dtrace_guest_load(&pg, PAGE_SIZE - 4, 8);
    assert(memcmp(&value, "ABCDEFGH", 8) == 0);
    assert(cpu_core[0].cpuc_dtrace_flags == 0);
    char copied[9] = { 0 };
    const char *guest_string = (const char *)(PAGE_SIZE - 4);
    /* The live bounded comparison (dtrace_strcmp was removed). */
    assert(dtrace_strncmp(&pg, NULL, (char *)guest_string, "ABCDEFGH", 8) == 0);
    assert(dtrace_strncmp(&pg, NULL, (char *)guest_string, "ABCDEFGI", 8) < 0);
    assert(dtrace_strncmp(NULL, &pg, "ABCDEFGI", (char *)guest_string, 8) > 0);
    assert(dtrace_bcmp(&pg, guest_string, "ABCDEFGH", 8) == 0);
    assert(dtrace_bcmp(&pg, guest_string, "ABCDEFXH", 8) != 0);
    dtrace_bcopy(&pg, guest_string, copied, 8);
    assert(memcmp(copied, "ABCDEFGH", 8) == 0);
    memset(copied, 0xff, sizeof(copied));
    dtrace_strcpy(&pg, guest_string, copied, sizeof(copied));
    assert(memcmp(copied, "ABCDEFGH", 9) == 0);
    pt(6)[1] = 0;
    assert(dtrace_guest_load(&pg, PAGE_SIZE - 4, 8) == 0);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR);
    cpu_core[0].cpuc_dtrace_flags = 0;
    assert(dtrace_guest_load(&pg, UINTPTR_MAX - 1, 8) == 0);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR);
    pg.paging_mode = PAGING_MODE_FLAT;
    assert(dtrace_gla2hva(&pg, 7 * PAGE_SIZE + 25, &hva) == 0);
    /* PAE root at the last 32 bytes of a page, fourth PDPT entry. */
    pg.paging_mode = PAGING_MODE_PAE; pg.cr3 = 12 * PAGE_SIZE + PAGE_SIZE - 32;
    pt(12)[511] = 13 * PAGE_SIZE | 1;
    pt(13)[0] = 14 * PAGE_SIZE | 1; pt(14)[1] = 15 * PAGE_SIZE | 1;
    uint64_t pae_address = (3UL << 30) + PAGE_SIZE + 25;
    memcpy(before, arena, sizeof(before));
    assert(dtrace_gla2hva(&pg, pae_address, &hva) == 0 && hva == (uintptr_t)pt(15) + 25);
    assert(memcmp(before, arena, sizeof(before)) == 0);
    pm.pm_type = PT_EPT; pm.pm_pmltop = pt(0); la57 = false;
    assert(dtrace_gla2hva(&pg, pae_address, &hva) == 0 && hva == (uintptr_t)pt(15) + 25);
    pt(14)[2] = 16 * PAGE_SIZE | 1;
    memcpy((char *)pt(15) + PAGE_SIZE - 4, "PAE1", 4);
    memcpy(pt(16), "PAE2", 4);
    cpu_core[0].cpuc_dtrace_flags = 0;
    value = dtrace_guest_load(&pg, (3UL << 30) + 2 * PAGE_SIZE - 4, 8);
    assert(memcmp(&value, "PAE1PAE2", 8) == 0 && cpu_core[0].cpuc_dtrace_flags == 0);
    pt(13)[0] = PG_PS | 1; /* 2 MiB guest page */
    assert(dtrace_gla2hva(&pg, pae_address, &hva) == 0 && hva == (uintptr_t)pt(1) + 25);
    pt(12)[511] |= PG_PS; /* Large pages are reserved at the PAE root. */
    assert(dtrace_gla2hva(&pg, pae_address, &hva) == EINVAL && hva == 0);
    pt(12)[511] = 0;
    assert(dtrace_gla2hva(&pg, pae_address, &hva) == EINVAL && hva == 0);
    pt(12)[511] = 13 * PAGE_SIZE | 1; pt(13)[0] = 14 * PAGE_SIZE | 1;
    pt(14)[1] = 0;
    assert(dtrace_gla2hva(&pg, pae_address, &hva) == EINVAL && hva == 0);
    assert(dtrace_gla2hva(&pg, UINT64_C(1) << 32, &hva) == EINVAL);
    pg.cpl = 3; assert(dtrace_gla2hva(&pg, pae_address, &hva) == EINVAL);
    pg.cpl = 0;
    pg.paging_mode = PAGING_MODE_32; pg.cr3 = 17 * PAGE_SIZE;
    uint32_t *pd32 = (uint32_t *)pt(17), *pt32 = (uint32_t *)pt(18);
    pd32[1023] = 18 * PAGE_SIZE | 1; pt32[1023] = 19 * PAGE_SIZE | 1;
    uint64_t va32 = UINT32_MAX - 24;
    memcpy(before, arena, sizeof(before));
    assert(dtrace_gla2hva(&pg, va32, &hva) == 0 && hva == (uintptr_t)pt(19) + PAGE_SIZE - 25);
    assert(memcmp(before, arena, sizeof(before)) == 0);
    pt32[1023] = 0;
    assert(dtrace_gla2hva(&pg, va32, &hva) == EINVAL && hva == 0);
    pd32[1023] = 0;
    assert(dtrace_gla2hva(&pg, va32, &hva) == EINVAL && hva == 0);
    pd32[0] = PG_PS | 1; /* 4 MiB identity mapping */
    assert(dtrace_gla2hva(&pg, PAGE_SIZE + 25, &hva) == 0 && hva == (uintptr_t)pt(1) + 25);
    pd32[0] |= 0x2000; /* PSE-36 must fail instead of silently truncating. */
    assert(dtrace_gla2hva(&pg, PAGE_SIZE + 25, &hva) == EINVAL && hva == 0);
    assert(dtrace_gla2hva(&pg, UINT64_C(1) << 32, &hva) == EINVAL);
    pg.pmap = NULL; assert(dtrace_gla2hva(&pg, 25, &hva) == EINVAL);
    assert(dtrace_gla2hva(NULL, 25, &hva) == EINVAL);
    free(arena); return (0);
}
