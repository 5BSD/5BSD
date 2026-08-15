/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTINFO_H_
#define	_VMM_INTINFO_H_

#include <sys/types.h>

/*
 * Value-only x86 event-folding result.  This is shared by the Intel and AMD
 * entry paths and deliberately has no vCPU ownership or publication state.
 */
struct vm_intinfo_plan {
	uint64_t	entry;
	bool		valid;
	bool		triple_fault;
};

int	vm_intinfo_plan(uint64_t, uint64_t, struct vm_intinfo_plan *);

#endif /* _VMM_INTINFO_H_ */
