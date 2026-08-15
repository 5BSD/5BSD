/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <machine/vmm.h>
struct trapframe;
#include <x86/reg.h>

#include "vmm_exception.h"

enum vm_exception_class
vm_debug_exception_class(uint64_t cause, uint64_t dr7)
{
	int i;

	/* A task-switch debug exception has distinct instruction-boundary rules. */
	if ((cause & DBREG_DR6_BT) != 0)
		return (VM_EXCEPTION_TASK_SWITCH);

	/* Debug-register access with GD set and execution breakpoints are faults. */
	if ((cause & DBREG_DR6_BD) != 0)
		return (VM_EXCEPTION_FAULT);
	for (i = 0; i != 4; i++) {
		if ((cause & DBREG_DR6_B(i)) != 0 &&
		    DBREG_DR7_ENABLED(dr7, i) &&
		    DBREG_DR7_ACCESS(dr7, i) == DBREG_DR7_EXEC)
			return (VM_EXCEPTION_FAULT);
	}

	/* Data breakpoints, single-step, and architecturally combined traps. */
	return (VM_EXCEPTION_TRAP);
}
