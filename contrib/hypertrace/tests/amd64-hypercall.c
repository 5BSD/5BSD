/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#define HYPERCALL_RET_SUCCESS 0
#define HYPERCALL_RET_ERROR -1
#define HYPERTRACE_ARGS_WALLTIME_VALID 1ULL
#define HYPERTRACE_STACK_MAX_FRAMES 64U
#define KASSERT(condition, message) assert(condition)

typedef int hypertrace_id_t;
typedef struct { uint64_t value; unsigned htr_curcpu;
    unsigned htr_entry; uint64_t htr_stackdepth, htr_caller, htr_vtimestamp;
    uint64_t htr_timestamp, htr_walltimestamp, htr_present;
    uintptr_t *htr_pcstack; uint32_t htr_pcstack_count;
    uint32_t htr_pcstack_reserved;
} hypertrace_args_t;
/* HELPER */
struct vm { int unused; };
struct vcpu { struct vm *vm; unsigned id; };
struct vm_guest_paging { void *pmap; };
typedef unsigned int u_int;
#define nitems(x) (sizeof((x)) / sizeof((x)[0]))
enum {
	VM_REG_GUEST_RAX, VM_REG_GUEST_RBX, VM_REG_GUEST_RCX, VM_REG_GUEST_RDX,
	VM_REG_GUEST_RSI, VM_REG_GUEST_RDI, VM_REG_GUEST_RBP, VM_REG_GUEST_R8,
	VM_REG_GUEST_R9, VM_REG_GUEST_R10, VM_REG_GUEST_R11, VM_REG_GUEST_R12,
	VM_REG_GUEST_R13, VM_REG_GUEST_R14, VM_REG_GUEST_R15, VM_REG_GUEST_CR0,
	VM_REG_GUEST_CR3, VM_REG_GUEST_CR4, VM_REG_GUEST_DR7, VM_REG_GUEST_RSP,
	VM_REG_GUEST_RIP, VM_REG_GUEST_RFLAGS, VM_REG_GUEST_ES, VM_REG_GUEST_CS,
	VM_REG_GUEST_SS, VM_REG_GUEST_DS, VM_REG_GUEST_FS, VM_REG_GUEST_GS,
	VM_REG_LAST
};
struct vm_hdl {
	struct vcpu *vcpu;
	struct vm_guest_paging *paging;
	uint64_t tid;
	uint64_t regs_valid;
	uint64_t regs[VM_REG_LAST];
};
struct seg_desc { uintptr_t base; };

static int copies, firings, copy_error, probe_error;
static unsigned supplied_entry = 1;
static uint64_t supplied_present = HYPERTRACE_ARGS_WALLTIME_VALID;
static uintptr_t *supplied_stack;
static uint32_t supplied_stack_count, supplied_stack_reserved;
static uint64_t observed_tid;
static unsigned
vcpu_vcpuid(struct vcpu *vcpu)
{
	return (vcpu->id);
}
static struct vm *
vm_vmspace(struct vm *vm)
{
	return (vm);
}
static void *
vmspace_pmap(struct vm *vm)
{
	return (vm);
}
typedef void *pmap_t;
static int pmap_locked, pmap_contended;
static int
PMAP_TRYLOCK(pmap_t pmap)
{
	assert(pmap != NULL && !pmap_locked);
	if (pmap_contended)
		return (0);
	pmap_locked = 1;
	return (1);
}
static void
PMAP_UNLOCK(pmap_t pmap)
{
	assert(pmap != NULL && pmap_locked);
	pmap_locked = 0;
}
/* The guest register file; FS cannot be read. */
static int register_reads;
static int
vm_get_register(struct vcpu *vcpu, int reg, uint64_t *value)
{
	assert(vcpu != NULL && !pmap_locked);
	register_reads++;
	if (reg == VM_REG_GUEST_FS)
		return (EINVAL);
	*value = 0x1000 + reg;
	return (0);
}
/* REGS */
static int
vm_get_seg_desc(struct vcpu *vcpu, int reg, struct seg_desc *desc)
{
	assert(vcpu != NULL && reg == VM_REG_GUEST_DS);
	desc->base = 0;
	return (0);
}
static int
hypercall_copy_arg(struct vcpu *vcpu, uintptr_t base, uintptr_t address,
    size_t size, struct vm_guest_paging *paging, hypertrace_args_t *out)
{
	assert(vcpu != NULL && base == 0 && address == 0x1000 &&
	    size == sizeof(*out) && paging != NULL);
	copies++;
	if (copy_error)
		return (HYPERCALL_RET_ERROR);
	out->value = 42;
	out->htr_curcpu = 999; /* A forged guest value must not survive. */
	out->htr_entry = supplied_entry;
	out->htr_stackdepth = 0x77;
	out->htr_caller = 0xbeef;
	out->htr_vtimestamp = 0x12345678;
	out->htr_timestamp = 0x23456789;
	out->htr_walltimestamp = 0x3456789a;
	out->htr_present = supplied_present;
	out->htr_pcstack = supplied_stack;
	out->htr_pcstack_count = supplied_stack_count;
	out->htr_pcstack_reserved = supplied_stack_reserved;
	return (HYPERCALL_RET_SUCCESS);
}
static int
hypertrace_probe(const void *handle, hypertrace_id_t id,
    hypertrace_args_t *args)
{
	const struct vm_hdl *vmhdl = handle;
	assert(id == 7 && args->value == 42 && args->htr_curcpu == 3 &&
	    args->htr_entry == 1 && args->htr_stackdepth == 0x77 &&
	    args->htr_caller == 0xbeef &&
	    args->htr_vtimestamp == 0x12345678 &&
	    args->htr_timestamp == 0x23456789 &&
	    args->htr_walltimestamp == 0x3456789a &&
	    args->htr_present == HYPERTRACE_ARGS_WALLTIME_VALID);
	assert(vmhdl->paging != NULL && vmhdl->paging->pmap != NULL);
	assert(pmap_locked);
	/* Registers were read before the probe; DIF reads only the copy. */
	{
		uint64_t value;
		int reads = register_reads;

		assert(dtrace_vmm_getreg(handle, VM_REG_GUEST_RIP, &value) == 0 &&
		    value == 0x1000 + VM_REG_GUEST_RIP);
		assert(dtrace_vmm_getreg(handle, VM_REG_GUEST_GS, &value) == 0 &&
		    value == 0x1000 + VM_REG_GUEST_GS);
		assert(dtrace_vmm_getreg(handle, VM_REG_GUEST_FS, &value) ==
		    EINVAL);
		assert(dtrace_vmm_getreg(handle, VM_REG_GUEST_CR3, &value) ==
		    EINVAL);
		assert(dtrace_vmm_getreg(handle, -1, &value) == EINVAL &&
		    dtrace_vmm_getreg(handle, VM_REG_LAST, &value) == EINVAL);
		assert(register_reads == reads);
	}
	observed_tid = vmhdl->tid;
	firings++;
	return (probe_error);
}

/* FUNCTION */

int
main(void)
{
	struct vm vm = { 0 };
	struct vcpu vcpu = { .vm = &vm, .id = 3 };
	struct vm_guest_paging paging = { 0 };
	uintptr_t args[3] = { 0, 0x1000, 4 };

	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 0);
	args[0] = (uintptr_t)INT_MAX + 1;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 0);
	args[0] = 7;
	args[2] = (uintptr_t)INT_MAX + 1;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 0);
	args[2] = 4;
	copy_error = 1;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 1 && firings == 0);
	copy_error = 0;
	supplied_entry = 2;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 2 && firings == 0);
	supplied_entry = 1;
	supplied_present = 2;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 3 && firings == 0);
	supplied_present = HYPERTRACE_ARGS_WALLTIME_VALID;
	supplied_stack_count = HYPERTRACE_STACK_MAX_FRAMES + 1;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 4 && firings == 0);
	supplied_stack_count = 0;
	supplied_stack_reserved = 1;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 5 && firings == 0);
	supplied_stack_reserved = 0;
	supplied_stack = (uintptr_t *)0x1001;
	supplied_stack_count = 1;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 6 && firings == 0);
	supplied_stack = (uintptr_t *)(UINTPTR_MAX - 7);
	supplied_stack_count = 2;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 7 && firings == 0);
	supplied_stack = NULL;
	supplied_stack_count = 0;
	/* A contended pmap lock drops the event without firing. */
	pmap_contended = 1;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 8 && firings == 0);
	pmap_contended = 0;
	probe_error = 13;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 9 && firings == 1 && !pmap_locked);
	probe_error = 0;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_SUCCESS && copies == 10 && firings == 2 &&
	    observed_tid == 4 && !pmap_locked);
	puts("PASS: amd64 call bounds, guest entry context, attested vCPU ID, "
	    "and probe under the pmap lock");
	return (0);
}
