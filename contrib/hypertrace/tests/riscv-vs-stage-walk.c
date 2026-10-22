/* SPDX-License-Identifier: BSD-2-Clause */
/* Native fixture: the runner inserts the production VMM walk below. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>

#define PAGE_SHIFT 12
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define SATP_PPN_M UINT64_C(0xfffffffffff)
#define SATP_MODE_M (UINT64_C(15) << 60)
#define SATP_MODE_SV39 (UINT64_C(8) << 60)
#define SATP_MODE_SV48 (UINT64_C(9) << 60)
#define SSTATUS_SUM (UINT64_C(1) << 18)
#define SSTATUS_MXR (UINT64_C(1) << 19)
#define HSTATUS_SPVP (UINT64_C(1) << 8)
#define VM_GP_HYPERTRACE_USER (1 << 6)
#define PTE_V 1
#define PTE_R 2
#define PTE_W 4
#define PTE_X 8
#define PTE_U 16
#define PTE_A 64
#define PTE_D 128
#define PTE_RWX (PTE_R | PTE_W | PTE_X)
#define PTE_PPN0_S 10
#define PTE_HI_MASK UINT64_C(0xffc0000000000000)

struct vcpu { int unused; };
struct vm_guest_paging { int flags, padding; };
struct hypctx {
	struct vcpu *vcpu;
	struct { uint64_t vsatp, vsstatus; } guest_csrs;
	struct { uint64_t hyp_hstatus; } guest_regs;
};
static struct { uint64_t addr, value; } entries[8];
static size_t nentries, holds, releases;

static void *
vm_gpa_hold(struct vcpu *vcpu, uint64_t addr, size_t len, int prot,
    void **cookie)
{
	assert(vcpu != NULL && len == sizeof(uint64_t) &&
	    prot == VM_PROT_READ);
	for (size_t i = 0; i < nentries; i++) {
		if (entries[i].addr == addr) {
			*cookie = &entries[i];
			holds++;
			return (&entries[i].value);
		}
	}
	return (NULL);
}

static void
vm_gpa_release(void *cookie)
{
	assert(cookie != NULL);
	releases++;
}

/* FUNCTION */

static void
putpte(uint64_t addr, uint64_t ppn, uint64_t flags)
{
	assert(nentries < sizeof(entries) / sizeof(entries[0]));
	entries[nentries].addr = addr;
	entries[nentries++].value = (ppn << 10) | flags;
}

static void
expect(struct hypctx *ctx, uint64_t gla, int prot, int fault,
    uint64_t expected)
{
	struct vm_guest_paging paging = {0};
	uint64_t gpa = UINT64_MAX;
	int is_fault = -1;
	assert(vmmops_gla2gpa(ctx, &paging, gla, prot, &gpa,
	    &is_fault) == 0);
	assert(is_fault == fault);
	assert(gpa == expected);
	assert(holds == releases);
}

static void
expect_user(struct hypctx *ctx, uint64_t gla, int fault,
    uint64_t expected)
{
	struct vm_guest_paging paging = { .flags = VM_GP_HYPERTRACE_USER };
	uint64_t gpa = UINT64_MAX;
	int is_fault = -1;
	assert(vmmops_gla2gpa(ctx, &paging, gla, VM_PROT_READ, &gpa,
	    &is_fault) == 0);
	assert(is_fault == fault);
	assert(gpa == expected);
	assert(holds == releases);
}

int
main(void)
{
	struct vcpu vcpu = {0};
	struct hypctx ctx = { .vcpu = &vcpu };
	const uint64_t va = UINT64_C(0x40001234);
	const uint64_t leaf = PTE_V | PTE_R | PTE_W | PTE_A | PTE_D;

	ctx.guest_regs.hyp_hstatus = HSTATUS_SPVP;
	ctx.guest_csrs.vsatp = SATP_MODE_SV39 | 0x100;
	{
		struct vm_guest_paging paging = {0};
		uint64_t gpa = UINT64_MAX;
		int fault = -1;
		assert(vmmops_gla2gpa(&ctx, &paging, va, 0, &gpa,
		    &fault) == EFAULT && fault == 1 && gpa == 0);
	}
	putpte(0x100000 + 8, 0x200, PTE_V);
	putpte(0x100000 + 0x800, 0x200, PTE_V);
	putpte(0x200000, 0x300, PTE_V);
	putpte(0x300000 + 8, 0x400, leaf);
	expect(&ctx, va, VM_PROT_READ, 0, 0x400234);
	expect_user(&ctx, va, 1, 0);
	expect(&ctx, UINT64_C(0xffffffc000001234), VM_PROT_READ,
	    0, 0x400234);
	expect(&ctx, va, VM_PROT_WRITE, 0, 0x400234);
	entries[3].value &= ~PTE_D;
	expect(&ctx, va, VM_PROT_WRITE, 1, 0);
	entries[3].value |= PTE_D;
	expect(&ctx, UINT64_C(1) << 39, VM_PROT_READ, 1, 0);
	entries[3].value &= ~PTE_A;
	expect(&ctx, va, VM_PROT_READ, 1, 0);
	entries[3].value |= PTE_A | PTE_U;
	expect(&ctx, va, VM_PROT_READ, 1, 0);
	expect_user(&ctx, va, 0, 0x400234);
	ctx.guest_csrs.vsstatus = SSTATUS_SUM;
	expect(&ctx, va, VM_PROT_READ, 0, 0x400234);
	expect(&ctx, va, VM_PROT_EXECUTE, 1, 0);
	ctx.guest_csrs.vsstatus = 0;
	entries[3].value = (UINT64_C(0x400) << 10) |
	    PTE_V | PTE_X | PTE_A;
	expect(&ctx, va, VM_PROT_READ, 1, 0);
	ctx.guest_csrs.vsstatus = SSTATUS_MXR;
	expect(&ctx, va, VM_PROT_READ, 0, 0x400234);
	ctx.guest_csrs.vsstatus = 0;
	entries[3].value = (UINT64_C(0x400) << 10) | PTE_V | PTE_W | PTE_A;
	expect(&ctx, va, VM_PROT_READ, 1, 0);
	entries[3].value = (UINT64_C(0x400) << 10) | leaf | PTE_HI_MASK;
	expect(&ctx, va, VM_PROT_READ, 1, 0);

	/* Aligned and misaligned 1 GiB leaves exercise superpage offsets. */
	nentries = 0;
	putpte(0x100000 + 8, 0x40000, leaf);
	expect(&ctx, va, VM_PROT_READ, 0, UINT64_C(0x40001234));
	entries[0].value += UINT64_C(1) << 10;
	expect(&ctx, va, VM_PROT_READ, 1, 0);
	entries[0].value = (UINT64_C(0x200) << 10) | PTE_V | PTE_U;
	expect(&ctx, va, VM_PROT_READ, 1, 0);
	ctx.guest_csrs.vsatp = SATP_MODE_SV48 | 0x100;
	nentries = 0;
	putpte(0x100000, 0x200, PTE_V);
	putpte(0x200000 + 8, 0x300, PTE_V);
	putpte(0x300000, 0x400, PTE_V);
	putpte(0x400000 + 8, 0x500, leaf);
	expect(&ctx, va, VM_PROT_READ, 0, 0x500234);
	ctx.guest_csrs.vsatp = UINT64_C(10) << 60;
	expect(&ctx, va, VM_PROT_READ, 1, 0);
	ctx.guest_csrs.vsatp = 0;
	expect(&ctx, va, VM_PROT_READ, 0, va);
	expect_user(&ctx, va, 1, 0);
	puts("PASS: production RISC-V VS-stage walk");
	return (0);
}
