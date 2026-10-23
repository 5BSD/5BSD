/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_COMPOSE_H_
#define _VMM_AMD_NESTED_SVM_COMPOSE_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdint.h>
#endif

#include "vmcb.h"

struct vmcb;

/* Every L0-owned control exit retained in VMCB02 has an L2 handler. */
#define SVM_NESTED_L0_CR_HANDLED \
	((0xffffU & ~(BIT(0) | BIT(2) | BIT(3) | BIT(4) | BIT(8))) * \
	(1U | (1U << 16)))
#define SVM_NESTED_L0_CTRL1_HANDLED (VMCB_INTCPT_INTR | \
	VMCB_INTCPT_NMI | VMCB_INTCPT_SMI | VMCB_INTCPT_INIT | \
	VMCB_INTCPT_CPUID | VMCB_INTCPT_INVD | VMCB_INTCPT_PAUSE | \
	VMCB_INTCPT_HLT | VMCB_INTCPT_INVLPGA | VMCB_INTCPT_IO | \
	VMCB_INTCPT_MSR | VMCB_INTCPT_FERR_FREEZE | \
	VMCB_INTCPT_SHUTDOWN)
#define SVM_NESTED_L0_CTRL2_HANDLED (VMCB_INTCPT_VMRUN | \
	VMCB_INTCPT_VMLOAD | VMCB_INTCPT_VMSAVE | VMCB_INTCPT_STGI | \
	VMCB_INTCPT_CLGI | VMCB_INTCPT_SKINIT | VMCB_INTCPT_ICEBP | \
	VMCB_INTCPT_WBINVD | VMCB_INTCPT_MONITOR | VMCB_INTCPT_MWAIT)
#define SVM_NESTED_L0_CTRL1_LOCAL (VMCB_INTCPT_VINTR | \
	VMCB_INTCPT_IRET | VMCB_INTCPT_PUSHF | VMCB_INTCPT_POPF)

static inline bool
svm_nested_l0_intercepts_supported(unsigned int index, uint32_t bits)
{

	switch (index) {
	case VMCB_CR_INTCPT:
		/* Reserved CR accesses receive #UD; CR8 has its own path. */
		return ((bits & ~SVM_NESTED_L0_CR_HANDLED) == 0);
	case VMCB_DR_INTCPT:
		return (bits == 0);
	case VMCB_EXC_INTCPT:
		/* L0 tracing may request vectors beyond the guest profile. */
		return (true);
	case VMCB_CTRL1_INTCPT:
		return ((bits & ~(SVM_NESTED_L0_CTRL1_HANDLED |
		    SVM_NESTED_L0_CTRL1_LOCAL)) == 0);
	case VMCB_CTRL2_INTCPT:
		return ((bits & ~SVM_NESTED_L0_CTRL2_HANDLED) == 0);
	default:
		return (false);
	}
}

/* L0 exceptions with a defined L2 replay path, plus its #BP/#MC exits. */
#define SVM_NESTED_L0_EXCEPTION_MASK	(BIT(0) | BIT(1) | BIT(3) | BIT(4) | \
	BIT(5) | BIT(6) | BIT(7) | BIT(8) | BIT(10) | BIT(11) | \
	BIT(12) | BIT(13) | BIT(14) | BIT(16) | BIT(17) | \
	BIT(18) | BIT(19))

static inline uint32_t
svm_nested_l0_intercepts_for_l2(unsigned int index, uint32_t bits)
{

	/* L0's L1 single-step and NMI controls are not L2 controls. */
	if (index == VMCB_CTRL1_INTCPT)
		bits &= ~SVM_NESTED_L0_CTRL1_LOCAL;
	/* Retain only exceptions that L0 can handle or replay into L2. */
	if (index == VMCB_EXC_INTCPT)
		bits &= SVM_NESTED_L0_EXCEPTION_MASK;
	return (bits);
}

int svm_nested_vmcb02_compose(struct vmcb *, const struct vmcb *,
    const struct vmcb *, uint64_t, uint64_t, uint64_t, uint32_t);

#endif /* _VMM_AMD_NESTED_SVM_COMPOSE_H_ */
