/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The arm64 guest probe entry, vm_hypertrace_probe(), with the production
 * register table, snapshot and accessor.  The registers are read while the
 * stage 2 pmap is not yet locked, once for each firing; the probe then runs
 * with the pmap locked and reads only the handle.
 */
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define nitems(x) (sizeof((x)) / sizeof((x)[0]))
#define NAMED_REGISTERS 33	/* X0-X29, LR, SP and PC */
typedef int hypertrace_id_t;
typedef struct { int unused; } hypertrace_args_t;
typedef int32_t lwpid_t;
struct pmap { int locked; };
typedef struct pmap *pmap_t;
struct vmspace { struct pmap pmap; };
struct vm { struct vmspace space; };
struct vcpu { struct vm *vm; };
struct vm_guest_paging { int unused; };
#define vm_vmspace(vm) (&(vm)->space)
#define vmspace_pmap(space) (&(space)->pmap)

/* ENUM */
/* HANDLE */

static struct vm vm;
static struct vcpu vcpu = { &vm };
static struct vm_guest_paging paging;
static hypertrace_args_t args;
static uint64_t base;		/* what the guest's registers hold now */
static int backend_reads, contended, firings, probe_error, unreadable = -1;

static int
PMAP_TRYLOCK(pmap_t pmap)
{
	assert(pmap == &vm.space.pmap && !pmap->locked);
	if (contended)
		return (0);
	pmap->locked = 1;
	return (1);
}

static void
PMAP_UNLOCK(pmap_t pmap)
{
	assert(pmap == &vm.space.pmap && pmap->locked);
	pmap->locked = 0;
}

/* The backend is not probe-context safe, and is not called under the lock. */
static int
vm_get_register(struct vcpu *v, int reg, uint64_t *value)
{
	assert(v == &vcpu && reg >= 0 && reg < VM_REG_LAST);
	assert(!vm.space.pmap.locked);
	backend_reads++;
	if (reg == unreadable)
		return (EINVAL);
	*value = base + (uint64_t)reg;
	return (0);
}

/* SNAPSHOT */

/* DTrace: every register it reads comes from the handle. */
static int
hypertrace_probe(const void *handle, hypertrace_id_t id,
    hypertrace_args_t *probe_args)
{
	const struct vm_hdl *vhdl = handle;
	uint64_t value;
	int before, reg, valid;

	assert(id == 7 && probe_args == &args);
	assert(vhdl->vcpu == &vcpu && vhdl->paging == &paging &&
	    vhdl->tid == 42);
	assert(vhdl->pmap == &vm.space.pmap && vhdl->pmap->locked);
	before = backend_reads;
	valid = 0;
	for (reg = 0; reg < VM_REG_LAST; reg++) {
		value = 0;
		if (dtrace_vmm_getreg(handle, reg, &value) != 0)
			continue;
		assert(reg != unreadable && value == base + (uint64_t)reg);
		valid++;
	}
	assert(valid == NAMED_REGISTERS - (unreadable != -1));
	assert(dtrace_vmm_getreg(handle, VM_REG_GUEST_X0, &value) == 0);
	assert(dtrace_vmm_getreg(handle, VM_REG_GUEST_SP, &value) == 0);
	assert(dtrace_vmm_getreg(handle, VM_REG_GUEST_PC, &value) ==
	    (unreadable == VM_REG_GUEST_PC ? EINVAL : 0));
	assert(dtrace_vmm_getreg(handle, VM_REG_GUEST_CPSR, &value) == EINVAL);
	assert(backend_reads == before);
	firings++;
	return (probe_error);
}

/* ENTRY */

/* The handle as vm_handle_smccc_call() passes it: stack, three fields set. */
static void
prepare(struct vm_hdl *handle)
{
	memset(handle, 0xa5, sizeof(*handle));
	handle->vcpu = &vcpu;
	handle->paging = &paging;
	handle->tid = 42;
}

int
main(void)
{
	struct vm_hdl handle;

	base = 0x7000;
	prepare(&handle);
	assert(vm_hypertrace_probe(&vcpu, &handle, 7, &args) == 0);
	assert(firings == 1 && backend_reads == NAMED_REGISTERS);
	assert(!vm.space.pmap.locked && handle.pmap == NULL);

	/* The next firing sees the registers as they are then. */
	base = 0x9000;
	assert(vm_hypertrace_probe(&vcpu, &handle, 7, &args) == 0);
	assert(firings == 2 && backend_reads == 2 * NAMED_REGISTERS);

	/* A register that cannot be read is missing; the probe still fires. */
	unreadable = VM_REG_GUEST_PC;
	prepare(&handle);
	assert(vm_hypertrace_probe(&vcpu, &handle, 7, &args) == 0);
	assert(firings == 3 && !vm.space.pmap.locked);
	unreadable = -1;

	/* A probe that fails is reported, with the lock released. */
	probe_error = EINVAL;
	prepare(&handle);
	assert(vm_hypertrace_probe(&vcpu, &handle, 7, &args) == (uint64_t)-2);
	assert(firings == 4 && !vm.space.pmap.locked && handle.pmap == NULL);
	probe_error = 0;

	/* A contended pmap drops the event: no probe, nothing to unlock. */
	contended = 1;
	prepare(&handle);
	assert(vm_hypertrace_probe(&vcpu, &handle, 7, &args) == (uint64_t)-2);
	assert(firings == 4 && !vm.space.pmap.locked);

	puts("PASS: arm64 guest probe entry reads the registers before the "
	    "pmap lock and the probe reads only the handle");
	return (0);
}
