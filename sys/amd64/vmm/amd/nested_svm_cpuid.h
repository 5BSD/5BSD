/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_CPUID_H_
#define _VMM_AMD_NESTED_SVM_CPUID_H_

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdint.h>
#endif

/* The SVM backend implements one nested level only. */
static inline void
svm_nested_l2_cpuid_filter(uint32_t leaf, uint32_t regs[4])
{

	if (leaf == 1)
		regs[2] &= ~(1U << 31); /* L0 hypervisor interface */
	else if (leaf >= 0x40000000 && leaf < 0x50000000)
		regs[0] = regs[1] = regs[2] = regs[3] = 0;
	else if (leaf == 0x80000001)
		regs[2] &= ~(1U << 2);	/* SVM */
	else if (leaf == 0x8000000a)
		regs[0] = regs[1] = regs[2] = regs[3] = 0;
}

#endif /* _VMM_AMD_NESTED_SVM_CPUID_H_ */
