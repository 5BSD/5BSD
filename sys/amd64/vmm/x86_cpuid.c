/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/errno.h>

#include <machine/specialreg.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

#include "x86_cpuid.h"

#define	CPUID_TOPOLOGY_LEGACY	0x0000000bU
#define	CPUID_TOPOLOGY_V2	0x0000001fU
#define	CPUID_TOPOLOGY_SMT	1U
#define	CPUID_TOPOLOGY_CORE	2U

uint32_t
x86_cpuid_guest_stdext2(uint32_t host_stdext2)
{

	return (host_stdext2 & (CPUID_STDEXT2_VAES |
	    CPUID_STDEXT2_VPCLMULQDQ | CPUID_STDEXT2_AVX512VBMI |
	    CPUID_STDEXT2_AVX512VBMI2 | CPUID_STDEXT2_AVX512VNNI |
	    CPUID_STDEXT2_AVX512BITALG | CPUID_STDEXT2_AVX512VPOPCNTDQ));
}

/*
 * Leaves whose host values describe the logical processor executing CPUID
 * rather than the package: Intel 1AH (hybrid core type and native model) and
 * AMD 8000_0026H (extended topology, EDX = extended APIC ID).  bhyve does not
 * virtualize either, so passing them through reports whichever host thread
 * the vCPU or the querying thread happened to run on.  That is wrong for the
 * guest (it changes when the vCPU moves between host CPUs and contradicts the
 * virtual APIC IDs) and makes the checkpoint CPU contract differ between two
 * queries on the same host.  Report the leaves as absent instead; guests then
 * use the virtualized 0BH/1FH and 8000_001EH topology.
 */
bool
x86_cpuid_leaf_host_cpu_local(uint32_t leaf)
{

	switch (leaf) {
	case 0x0000001aU:
	case 0x80000026U:
		return (true);
	default:
		return (false);
	}
}

uint8_t
x86_cpuid_linear_address_width(uint32_t guest_stdext2)
{

	return ((guest_stdext2 & CPUID_STDEXT2_LA57) != 0 ? 57 : 48);
}

static uint32_t
topology_width(uint32_t count)
{
	uint32_t width;

	if (count <= 1)
		return (0);
	count--;
	for (width = 0; count != 0; width++)
		count >>= 1;
	return (width);
}

int
x86_cpuid_topology(uint32_t leaf, uint32_t subleaf, uint16_t cores,
    uint16_t threads, uint32_t vcpuid, bool leaf_b_available,
    uint32_t values[4])
{
	uint32_t count, level, width;

	if (values == 0 || cores == 0 || threads == 0 ||
	    (leaf != CPUID_TOPOLOGY_LEGACY && leaf != CPUID_TOPOLOGY_V2))
		return (EINVAL);
	count = 0;
	level = 0;
	width = 0;
	if ((leaf != CPUID_TOPOLOGY_LEGACY || leaf_b_available) &&
	    subleaf < 2) {
		if (subleaf == 0) {
			count = threads;
			level = CPUID_TOPOLOGY_SMT;
		} else {
			count = (uint32_t)threads * cores;
			level = CPUID_TOPOLOGY_CORE;
		}
		width = topology_width(count);
	}
	values[0] = width & 0x1fU;
	values[1] = count & 0xffffU;
	values[2] = (level << 8) | (subleaf & 0xffU);
	values[3] = level == 0 ? 0 : vcpuid;
	return (0);
}
