/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _VMM_X86_CPUID_H_
#define	_VMM_X86_CPUID_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

int	x86_cpuid_topology(uint32_t leaf, uint32_t subleaf, uint16_t cores,
	    uint16_t threads, uint32_t vcpuid, bool leaf_b_available,
	    uint32_t values[4]);
uint32_t x86_cpuid_guest_stdext2(uint32_t host_stdext2);
uint8_t	x86_cpuid_linear_address_width(uint32_t guest_stdext2);

#endif /* _VMM_X86_CPUID_H_ */
