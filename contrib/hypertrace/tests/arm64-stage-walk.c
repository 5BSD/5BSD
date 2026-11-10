/* SPDX-License-Identifier: BSD-2-Clause */
/* A 16K guest table crosses 4K host holds at entry 512. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#define PAGE_SIZE 4096
#define PAGE_SHIFT_4K 12
#define PAGE_SHIFT_16K 14
#define PAGE_SHIFT_64K 16
#define VM_PROT_RW 3
#define PROT_WRITE 2
#define PROT_EXEC 4
#define VM_GP_MMU_ENABLED 0x20
#define PSR_M_MASK 15
#define PSR_M_EL0t 0
#define ADDR_IS_KERNEL(x) (((x) & (UINT64_C(1) << 55)) != 0)
#define TCR_EPD0 (UINT64_C(1) << 7)
#define TCR_EPD1 (UINT64_C(1) << 23)
#define TCR_E0PD0 (UINT64_C(1) << 55)
#define TCR_E0PD1 (UINT64_C(1) << 56)
#define TCR_TBI0 (UINT64_C(1) << 37)
#define TCR_TBI1 (UINT64_C(1) << 38)
#define TCR_T0SZ_MASK 0x3f
#define TCR_T0SZ_SHIFT 0
#define TCR_T1SZ_MASK (UINT64_C(0x3f) << 16)
#define TCR_T1SZ_SHIFT 16
#define TCR_TG0_MASK (UINT64_C(3) << 14)
#define TCR_TG0_4K 0
#define TCR_TG0_16K (UINT64_C(2) << 14)
#define TCR_TG0_64K (UINT64_C(1) << 14)
#define TCR_TG1_MASK (UINT64_C(3) << 30)
#define TCR_TG1_4K (UINT64_C(2) << 30)
#define TCR_TG1_16K (UINT64_C(1) << 30)
#define TCR_TG1_64K (UINT64_C(3) << 30)
#define ATTR_MASK (UINT64_C(0xfffc000000000000) | UINT64_C(0xfff))
#define ATTR_DESCR_MASK 3
#define L0_TABLE 3
#define L1_TABLE 3
#define L1_BLOCK 1
#define L3_PAGE 3
#define TATTR_AP_TABLE_NO_EL0 (UINT64_C(1) << 61)
#define TATTR_AP_TABLE_RO (UINT64_C(1) << 62)
#define TATTR_UXN_TABLE (UINT64_C(1) << 60)
#define TATTR_PXN_TABLE (UINT64_C(1) << 59)
#define ATTR_S1_AP(x) ((x) << 6)
#define ATTR_S1_AP_USER 1
#define ATTR_S1_AP_RW_BIT (1 << 7)
#define ATTR_S1_UXN (UINT64_C(1) << 54)
#define ATTR_S1_PXN (UINT64_C(1) << 53)
#define howmany(x, y) (((x) + (y) - 1) / (y))

typedef uint64_t vm_paddr_t;
typedef int vm_prot_t;
#define VM_PROT_READ 1
typedef struct pmap *pmap_t;
/* vmmops_gla2gpa() walks with held pages; the locked walk is never taken. */
static void *
dtrace_vmm_s2_map(pmap_t pmap, uint64_t ipa, vm_prot_t prot)
{
    (void)pmap; (void)ipa; (void)prot;
    abort();
}
struct vcpu { int unused; };
struct hypctx { struct vcpu *vcpu; };
struct vm_guest_paging {
    uint64_t tcr_el1, ttbr0_addr, ttbr1_addr;
    int flags;
};
static uint8_t *pages[32];
static int holds, releases;

static void *
vm_gpa_hold(struct vcpu *vcpu, uint64_t gpa, size_t len, int prot,
    void **cookie)
{
    assert(vcpu != NULL && len == PAGE_SIZE && prot == VM_PROT_RW);
    if ((gpa & (PAGE_SIZE - 1)) != 0 || gpa / PAGE_SIZE >= 32 ||
        pages[gpa / PAGE_SIZE] == NULL)
        return (NULL);
    *cookie = pages[gpa / PAGE_SIZE];
    holds++;
    return (*cookie);
}

static void
vm_gpa_release(void *cookie)
{
    assert(cookie != NULL);
    releases++;
}

/* FUNCTION */

static void
putpte(unsigned page, unsigned index, uint64_t value)
{
    assert(page < 32 && index < PAGE_SIZE / sizeof(uint64_t));
    ((uint64_t *)pages[page])[index] = value;
}

int
main(void)
{
    struct vcpu vcpu = {0};
    struct hypctx ctx = { .vcpu = &vcpu };
    struct vm_guest_paging paging = {
        .tcr_el1 = 16 | TCR_TG0_16K,
        .ttbr0_addr = 0,
        .flags = VM_GP_MMU_ENABLED,
    };
    const uint64_t gla = (UINT64_C(512) << 36) | 0x1234;
    uint64_t gpa = UINT64_MAX;
    int fault = -1;

    for (size_t i = 0; i < 32; i++) {
        pages[i] = calloc(1, PAGE_SIZE);
        assert(pages[i] != NULL);
    }
    putpte(0, 0, 0x4000 | L0_TABLE);
    putpte(5, 0, 0x8000 | L1_TABLE);
    putpte(8, 0, 0xc000 | L1_TABLE);
    putpte(12, 0, 0x10000 | L3_PAGE | ATTR_S1_AP(ATTR_S1_AP_USER));
    assert(vmmops_gla2gpa(&ctx, &paging, gla, 1, &gpa, &fault) == 0);
    assert(fault == 0 && gpa == 0x11234);
    assert(holds == 4 && releases == 4);
    fault = -1;
    assert(vmmops_gla2gpa(&ctx, &paging, gla | (UINT64_C(1) << 50),
        1, &gpa, &fault) == 0);
    assert(fault == 1 && holds == releases);
    fault = -1;
    assert(vmmops_gla2gpa(&ctx, &paging, gla | (UINT64_C(0xa5) << 56),
        1, &gpa, &fault) == 0);
    assert(fault == 1 && holds == releases);
    paging.tcr_el1 |= TCR_TBI0;
    fault = -1;
    assert(vmmops_gla2gpa(&ctx, &paging, gla | (UINT64_C(0xa5) << 56),
        1, &gpa, &fault) == 0);
    assert(fault == 0 && gpa == 0x11234 && holds == releases);
    paging.tcr_el1 &= ~TCR_TBI0;
    putpte(5, 0, 0);
    gpa = UINT64_MAX;
    fault = -1;
    assert(vmmops_gla2gpa(&ctx, &paging, gla, 1, &gpa, &fault) == 0);
    assert(fault == 1);
    assert(holds == releases);
    for (size_t i = 0; i < 32; i++)
        free(pages[i]);
    puts("PASS: Arm64 16K table boundary, canonical address, and missing mapping");
    return (0);
}
