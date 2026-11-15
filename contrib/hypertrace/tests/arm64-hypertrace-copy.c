/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define PAGE_SIZE 4096
#define PAGE_MASK (PAGE_SIZE - 1)
#define PAGE_SIZE_4K 4096
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_GP_M_MASK 0x1f
#define VM_GP_MMU_ENABLED 0x20
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* 4K granule geometry, as in sys/arm64/include/pte.h. */
#define L0_SHIFT 39
#define L0_ENTRIES_SHIFT 9
#define Ln_ENTRIES_SHIFT 9
#define L0_ADDR_MASK ((1 << L0_ENTRIES_SHIFT) - 1)
#define Ln_ADDR_MASK ((1 << Ln_ENTRIES_SHIFT) - 1)
/* PTE */
#define PTE_TO_PHYS(pte) ((pte) & UINT64_C(0x0000fffffffff000))

typedef uint64_t vm_paddr_t;
typedef int vm_prot_t;
typedef uint64_t pd_entry_t;
typedef uint64_t pt_entry_t;
typedef struct { unsigned char bytes[192]; } hypertrace_args_t;
struct trapframe { unsigned char bytes[256]; };
struct vcpu { void *cookie; };
struct vm_guest_paging { int flags; };
struct pmap { pd_entry_t *pm_l0; bool owned; };
typedef struct pmap *pmap_t;
struct vm_hdl {
	struct vcpu *vcpu;
	struct vm_guest_paging *paging;
	struct pmap *pmap;
	uint64_t tid;
};
#define PMAP_OWNED(pmap) ((pmap)->owned)

/*
 * Host physical memory for the probe-context walk.  RAM is [0, 0x30000);
 * [0x30000, 0x40000) is in the direct map but is not RAM, like device memory.
 */
static uint64_t physical_words[0x40000 / 8];
#define physical ((unsigned char *)physical_words)
#define PHYS_IN_DMAP_RANGE(pa) ((pa) < sizeof(physical_words))
#define PHYS_TO_DMAP(pa) ((void *)&physical[(pa)])
static struct { vm_paddr_t start, end; } vm_phys_segs[] = { { 0, 0x30000 } };
static int vm_phys_nsegs = 1;

/* Guest memory for the frozen envelope copy (vm_gpa_hold()). */
static unsigned char envelope_memory[0x5000];
static size_t holds, releases;
static int deny_second, deny_translate_second;

static int
vm_gla2gpa_nofault(struct vcpu *vcpu, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *fault)
{
	assert(vcpu != NULL && paging != NULL && prot == VM_PROT_READ);
	*fault = 0;
	if (gla >= 0x1000 && gla < 0x2000)
		*gpa = 0x2000 + (gla & PAGE_MASK);
	else if (gla >= 0x2000 && gla < 0x3000)
		*gpa = 0x4000 + (gla & PAGE_MASK);
	else
		*fault = 1;
	if (*fault == 0 && deny_translate_second && *gpa >= 0x4000)
		*fault = 1;
	return (0);
}

static void *
vm_gpa_hold(struct vcpu *vcpu, uint64_t gpa, size_t len, int prot,
    void **cookie)
{
	assert(vcpu != NULL && prot == VM_PROT_READ && len > 0 &&
	    len <= PAGE_SIZE - (gpa & PAGE_MASK));
	if (gpa + len > sizeof(envelope_memory) ||
	    (deny_second && gpa >= 0x4000))
		return (NULL);
	*cookie = vcpu;
	holds++;
	return (&envelope_memory[gpa]);
}

static void
vm_gpa_release(void *cookie)
{
	assert(cookie != NULL);
	releases++;
}

/* ENVELOPE */

/*
 * Stage 1 is the identity below 4 MiB, where the stage 2 tables below
 * apply; gpa_override hands back an arbitrary IPA instead.
 */
static int require_user, translate_error;
static uint64_t gpa_override;

static int
dtrace_vmm_gla2gpa(void *vcpui, struct vm_guest_paging *paging, uint64_t gla,
    int prot, uint64_t *gpa, int *is_fault, pmap_t locked)
{
	assert(vcpui != NULL && locked != NULL && PMAP_OWNED(locked));
	assert(prot == VM_PROT_READ || prot == VM_PROT_WRITE);
	if (require_user)
		assert((paging->flags & VM_GP_M_MASK) == 0);
	if (translate_error)
		return (EFAULT);
	*is_fault = gla >= 0x400000 && gpa_override == 0;
	*gpa = gpa_override != 0 ? gpa_override : gla;
	return (0);
}

/* WALK */

/* HOOKS */

/* Stage 2 tables of one VM, in host RAM. */
#define	S2_RW	(ATTR_S2_S2AP(ATTR_S2_S2AP_READ) | \
		    ATTR_S2_S2AP(ATTR_S2_S2AP_WRITE))
#define	S2_RO	ATTR_S2_S2AP(ATTR_S2_S2AP_READ)
static pd_entry_t *
table(vm_paddr_t pa)
{
	return ((pd_entry_t *)PHYS_TO_DMAP(pa));
}

static void
build_stage2(struct pmap *pmap)
{
	memset(physical_words, 0, sizeof(physical_words));
	pmap->pm_l0 = table(0x1000);
	table(0x1000)[0] = 0x2000 | L0_TABLE;
	table(0x2000)[0] = 0x3000 | L1_TABLE;
	table(0x3000)[0] = 0x4000 | L1_TABLE;
	/* IPA 2 MiB block onto PA 0; only its first 192 KiB is RAM. */
	table(0x3000)[1] = 0x0 | L1_BLOCK | S2_RW;
	table(0x4000)[0x10] = 0x8000 | L3_PAGE | S2_RW;	/* IPA 0x10000 */
	table(0x4000)[0x11] = 0xa000 | L3_PAGE | S2_RW;	/* IPA 0x11000 */
	table(0x4000)[0x12] = 0xb000 | L3_PAGE | S2_RO;	/* IPA 0x12000 */
	table(0x4000)[0x13] = 0x30000 | L3_PAGE | S2_RW;	/* not RAM */
	table(0x4000)[0x15] = 0xc000 | 0x1 | S2_RW;	/* L3 with block type */
}

int
main(void)
{
	struct vcpu vcpu = { .cookie = &vcpu };
	struct vm_guest_paging paging = { .flags = VM_GP_MMU_ENABLED | 1 };
	struct pmap pmap = { .owned = true };
	struct vm_hdl handle = { &vcpu, &paging, &pmap, 0 };
	unsigned char result[32], data[32];

	/* The frozen envelope copy, across discontiguous guest pages. */
	memset(envelope_memory + 0x2ff0, 0x5a, 16);
	memset(envelope_memory + 0x4000, 0xa5, 16);
	assert(vm_hypertrace_copyin(&vcpu, &paging, 0x1ff0, result,
	    sizeof(result)) == 0);
	for (size_t i = 0; i < sizeof(result); i++)
		assert(result[i] == (i < 16 ? 0x5a : 0xa5));
	assert(holds == 2 && releases == 2);
	assert(vm_hypertrace_copyin(&vcpu, &paging, 0, result, 1) == EFAULT);
	assert(vm_hypertrace_copyin(&vcpu, &paging, UINT64_MAX,
	    result, 2) == EFAULT);
	assert(vm_hypertrace_copyin(&vcpu, &paging, 0x3000,
	    result, 1) == EFAULT);
	assert(vm_hypertrace_copyin(&vcpu, &paging, 0x1000,
	    result, MAX(sizeof(hypertrace_args_t),
	    sizeof(struct trapframe)) + 1) == EFAULT);
	deny_second = 1;
	memset(result, 0x7e, sizeof(result));
	assert(vm_hypertrace_copyin(&vcpu, &paging, 0x1ff0, result,
	    sizeof(result)) == EFAULT);
	for (size_t i = 0; i < sizeof(result); i++)
		assert(result[i] == 0x7e);
	deny_second = 0;
	deny_translate_second = 1;
	assert(vm_hypertrace_copyin(&vcpu, &paging, 0x1ff0, result,
	    sizeof(result)) == EFAULT);
	for (size_t i = 0; i < sizeof(result); i++)
		assert(result[i] == 0x7e);
	deny_translate_second = 0;
	assert(holds == releases);

	/* Probe context: the stage 2 walk, across two L3 pages. */
	build_stage2(&pmap);
	memset(physical + 0x8ff0, 0x11, 16);
	memset(physical + 0xa000, 0x22, 16);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x10ff0, result,
	    sizeof(result), VM_PROT_READ) == 0);
	for (size_t i = 0; i < sizeof(result); i++)
		assert(result[i] == (i < 16 ? 0x11 : 0x22));
	memset(data, 0x33, sizeof(data));
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x10ff0, data,
	    sizeof(data), VM_PROT_WRITE) == 0);
	assert(physical[0x8ff0] == 0x33 && physical[0x8fff] == 0x33 &&
	    physical[0xa000] == 0x33 && physical[0xa00f] == 0x33 &&
	    physical[0xa010] == 0);
	/* Read-only stage 2: readable, and a write leaves no partial copy. */
	physical[0xb000] = 0x44;
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x12000, result,
	    1, VM_PROT_READ) == 0 && result[0] == 0x44);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x12000, data,
	    1, VM_PROT_WRITE) == EFAULT && physical[0xb000] == 0x44);
	memset(physical + 0xaff8, 0x55, 8);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x11ff8, data,
	    16, VM_PROT_WRITE) == EFAULT);
	for (size_t i = 0; i < 8; i++)
		assert(physical[0xaff8 + i] == 0x55);
	/* Not RAM, unmapped, a block descriptor at L3, beyond the IPA range. */
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x13000, result,
	    1, VM_PROT_READ) == EFAULT);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x14000, result,
	    1, VM_PROT_READ) == EFAULT);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x15000, result,
	    1, VM_PROT_READ) == EFAULT);
	gpa_override = UINT64_C(1) << (L0_SHIFT + L0_ENTRIES_SHIFT);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x10000, result,
	    1, VM_PROT_READ) == EFAULT);
	gpa_override = 0;
	/* An L2 block: RAM inside it is reachable, the rest is not. */
	physical[0x9123] = 0x66;
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x209123, result,
	    1, VM_PROT_READ) == 0 && result[0] == 0x66);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x240000, result,
	    1, VM_PROT_READ) == EFAULT);
	/* Arguments and the caller's lock. */
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0, result,
	    1, VM_PROT_READ) == EFAULT);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x10000, result,
	    0, VM_PROT_READ) == EFAULT);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x10000, result,
	    PAGE_SIZE_4K + 1, VM_PROT_READ) == EFAULT);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, UINT64_MAX,
	    result, 2, VM_PROT_READ) == EFAULT);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x10000, result,
	    1, VM_PROT_READ | VM_PROT_WRITE) == EFAULT);
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, NULL, 0x10000, result,
	    1, VM_PROT_READ) == EFAULT);
	translate_error = 1;
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x10000, result,
	    1, VM_PROT_READ) == EFAULT);
	translate_error = 0;
	pmap.owned = false;
	assert(dtrace_vmm_guest_copy(&vcpu, &paging, &pmap, 0x10000, result,
	    1, VM_PROT_READ) == EFAULT);
	pmap.owned = true;

	/* The hooks forward to the walk with the VM's locked pmap. */
	assert(dtrace_vmm_guest_copyin(&handle, 0x10ff0, result, 32) == 0 &&
	    result[0] == 0x33 && result[31] == 0x33);
	assert(dtrace_vmm_guest_copyin(&handle, 0x10000, result,
	    sizeof(struct trapframe) + 1) == EINVAL);
	require_user = 1;
	assert(dtrace_vmm_guest_user_copyin(&handle, 0x10ff8, result, 8) == 0 &&
	    result[0] == 0x33);
	assert(paging.flags == (VM_GP_MMU_ENABLED | 1));
	assert(dtrace_vmm_guest_user_copyin(&handle, 0x10ff8, result, 9) ==
	    EINVAL);
	memset(data, 0x77, 8);
	assert(dtrace_vmm_guest_user_copyout(&handle, 0x10ffc, data, 8) == 0 &&
	    physical[0x8ffc] == 0x77 && physical[0xa003] == 0x77);
	assert(dtrace_vmm_guest_user_copyout(&handle, 0x12000, data, 1) ==
	    EFAULT);
	assert(dtrace_vmm_guest_user_copyout(&handle, 0x10000, data, 9) ==
	    EINVAL);
	paging.flags = 1;
	assert(dtrace_vmm_guest_user_copyin(&handle, 0x10000, result, 1) ==
	    EOPNOTSUPP);
	assert(dtrace_vmm_guest_user_copyout(&handle, 0x10000, data, 1) ==
	    EOPNOTSUPP);
	puts("PASS: production Arm64 frozen guest copy and probe-context "
	    "stage 2 walk");
	return (0);
}
