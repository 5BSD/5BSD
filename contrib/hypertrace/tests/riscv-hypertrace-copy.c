/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define PAGE_SIZE 4096
#define PAGE_MASK (PAGE_SIZE - 1)
#define VM_PROT_READ 1
#define VM_GP_HYPERTRACE_USER (1 << 6)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

typedef struct { unsigned char bytes[192]; } hypertrace_args_t;
struct trapframe { unsigned char bytes[256]; };
struct vcpu { int unused; };
struct vm_guest_paging { int flags, padding; };
struct vm_hdl { struct vcpu *vcpu; struct vm_guest_paging *paging; };
static unsigned char physical[0x5000];
static size_t holds, releases;
static int deny_second, deny_translate_second, require_user;

static int
vm_gla2gpa_nofault(struct vcpu *vcpu, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *fault)
{
	assert(vcpu != NULL && paging != NULL && prot == VM_PROT_READ);
	if (require_user)
		assert((paging->flags & VM_GP_HYPERTRACE_USER) != 0);
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
	if (gpa + len > sizeof(physical) || (deny_second && gpa >= 0x4000))
		return (NULL);
	*cookie = vcpu;
	holds++;
	return (&physical[gpa]);
}

static void
vm_gpa_release(void *cookie)
{
	assert(cookie != NULL);
	releases++;
}

/* FUNCTION */

int
main(void)
{
	struct vcpu vcpu = { 0 };
	struct vm_guest_paging paging = { 0 };
	struct vm_hdl handle = { &vcpu, &paging };
	unsigned char result[32];

	memset(physical + 0x2ff0, 0x5a, 16);
	memset(physical + 0x4000, 0xa5, 16);
	assert(vm_hypertrace_copyin(&vcpu, &paging, 0x1ff0, result,
	    sizeof(result)) == 0);
	for (size_t i = 0; i < sizeof(result); i++)
		assert(result[i] == (i < 16 ? 0x5a : 0xa5));
	assert(holds == 2 && releases == 2);
	assert(vm_hypertrace_copyin(&vcpu, &paging, 0, result, 1) == EFAULT);
	assert(vm_hypertrace_copyin(&vcpu, &paging, UINT64_MAX, result, 2) == EFAULT);
	assert(vm_hypertrace_copyin(&vcpu, &paging, 0x3000, result, 1) == EFAULT);
	assert(vm_hypertrace_copyin(&vcpu, &paging, 0x1000, result,
	    sizeof(struct trapframe) + 1) == EFAULT);
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
	require_user = 1;
	assert(vmm_priv_guest_user_copyin(&handle, 0x1ff8, result, 8) == 0);
	for (size_t i = 0; i < 8; i++)
		assert(result[i] == 0x5a);
	assert(paging.flags == 0);
	assert(vmm_priv_guest_user_copyin(&handle, 0x1ff8, result, 9) == EINVAL);
	assert(holds == releases);
	puts("PASS: production RISC-V frozen guest copy");
	return (0);
}
