/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#define HYPERCALL_RET_SUCCESS 0
#define HYPERCALL_RET_ERROR -1
#define HYPERTRACE_ARGS_WALLTIME_VALID 1ULL
#define HYPERTRACE_STACK_MAX_FRAMES 64U
#define VM_REG_GUEST_DS 1
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
struct vm_hdl {
	struct vcpu *vcpu;
	struct vm_guest_paging *paging;
	uint64_t tid;
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
	probe_error = 13;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_ERROR && copies == 8 && firings == 1);
	probe_error = 0;
	assert(hc_handle_dtrace_probe(&vcpu, args, &paging) ==
	    HYPERCALL_RET_SUCCESS && copies == 9 && firings == 2 &&
	    observed_tid == 4);
	puts("PASS: amd64 call bounds, guest entry context, and attested vCPU ID");
	return (0);
}
