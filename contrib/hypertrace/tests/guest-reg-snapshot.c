/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The guest registers a HyperTrace probe can read.  The VMM reads them into
 * the probe's handle before entering DTrace; in probe context DTrace reads
 * only that copy.  Built once for each architecture from its own enum
 * vm_reg_name, struct vm_hdl, register table, snapshot and accessor, and from
 * its branch of dtrace_guest_reg_name(), which turns the register index of a
 * D program into a VMM register.
 */
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Select the dtrace_guest_reg_name() branch under test, not the host's. */
#undef __amd64__
#undef __aarch64__
#undef __riscv
#if defined(FIXTURE_AMD64)
#define __amd64__ 1
#elif defined(FIXTURE_ARM64)
#define __aarch64__ 1
#else
#error "no architecture selected"
#endif

typedef unsigned int uint_t;
#define nitems(x) (sizeof((x)) / sizeof((x)[0]))
struct vcpu { int unused; };
struct vm_guest_paging;
struct pmap;

/* REGSET */
/* ENUM */
/* HANDLE */

#define REGISTER_VALUE(reg) (0x1000000000000000ULL + (uint64_t)(reg))

static int backend_reads, unreadable = -1;

static int
vm_get_register(struct vcpu *vcpu, int reg, uint64_t *value)
{
	assert(vcpu != NULL && reg >= 0 && reg < VM_REG_LAST);
	backend_reads++;
	if (reg == unreadable)
		return (EINVAL);
	*value = REGISTER_VALUE(reg);
	return (0);
}

/* SNAPSHOT */
/* NAME */

static struct vcpu vcpu;
static uint64_t named;		/* a bit for each register D can name */

/* A handle whose every register looks valid and holds something else. */
static void
poison(struct vm_hdl *handle)
{
	memset(handle, 0xa5, sizeof(*handle));
	handle->regs_valid = ~(uint64_t)0;
}

/* The handle answers for exactly the registers in valid, without the VMM. */
static void
check(const struct vm_hdl *handle, uint64_t valid)
{
	uint64_t value;
	int reads = backend_reads, reg;

	for (reg = -2; reg < 2 * VM_REG_LAST + 66; reg++) {
		value = 0x5a5a;
		if (reg >= 0 && reg < VM_REG_LAST &&
		    (valid & ((uint64_t)1 << reg)) != 0) {
			assert(dtrace_vmm_getreg(handle, reg, &value) == 0);
			assert(value == REGISTER_VALUE(reg));
		} else {
			assert(dtrace_vmm_getreg(handle, reg, &value) ==
			    EINVAL);
			assert(value == 0x5a5a);
		}
	}
	assert(backend_reads == reads);
}

int
main(void)
{
	struct vm_hdl handle;
	uint64_t value;
	uint_t ndx;
	int count = 0, reads, reg;

	/* Every register index a D program can use, and some it cannot. */
	for (ndx = 0; ndx < 4096; ndx++) {
		reg = dtrace_guest_reg_name(ndx);
		if (reg == -1)
			continue;
		assert(reg >= 0 && reg < VM_REG_LAST);
		named |= (uint64_t)1 << reg;
	}
	assert(dtrace_guest_reg_name(UINT32_MAX) == -1);
	for (reg = 0; reg < VM_REG_LAST; reg++)
		count += (named >> reg) & 1;
	assert(count == NAMED_REGISTERS);

	/*
	 * The snapshot holds every register D can name and no other, whatever
	 * the handle held before, for one backend read each.
	 */
	poison(&handle);
	reads = backend_reads;
	vm_hypertrace_snapshot_regs(&vcpu, &handle);
	assert(handle.regs_valid == named);
	assert(backend_reads == reads + count);
	check(&handle, named);

	/* A register the backend cannot read is the only one missing. */
	for (reg = 0; reg < VM_REG_LAST; reg++) {
		if ((named & ((uint64_t)1 << reg)) == 0)
			continue;
		unreadable = reg;
		poison(&handle);
		vm_hypertrace_snapshot_regs(&vcpu, &handle);
		check(&handle, named & ~((uint64_t)1 << reg));
	}
	unreadable = -1;

	/* Nothing was read: nothing is valid. */
	memset(&handle, 0, sizeof(handle));
	check(&handle, 0);

	/* Only the registers of the handle exist, whatever the valid bits. */
	poison(&handle);
	for (reg = 0; reg < VM_REG_LAST; reg++)
		handle.regs[reg] = REGISTER_VALUE(reg);
	check(&handle, VM_REG_LAST < 64 ?
	    ((uint64_t)1 << VM_REG_LAST) - 1 : UINT64_MAX);
	memset(&handle, 0, sizeof(handle));

	vm_hypertrace_snapshot_regs(&vcpu, &handle);
	reg = dtrace_guest_reg_name(0);
	assert(reg != -1);
	assert(dtrace_vmm_getreg(NULL, reg, &value) == EINVAL);
	assert(dtrace_vmm_getreg(&handle, reg, NULL) == EINVAL);

	printf("PASS: %s guest probe sees a snapshot of the %d registers D can "
	    "name\n", ARCHITECTURE, count);
	return (0);
}
