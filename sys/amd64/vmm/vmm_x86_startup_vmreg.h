/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AMD64_VMM_VMM_X86_STARTUP_VMREG_H_
#define	_AMD64_VMM_VMM_X86_STARTUP_VMREG_H_

#include <sys/param.h>
#include <sys/types.h>

#include <machine/vmm.h>

#include "vmm_x86_startup_machine.h"

/* Private transient adapters, not a userspace ABI or save-state encoding. */
int	vmm_x86_startup_register_vmreg(enum vmm_x86_startup_register,
	    enum vm_reg_name *);
int	vmm_x86_startup_descriptor_vmreg(enum vmm_x86_startup_descriptor,
	    enum vm_reg_name *);

#endif /* _AMD64_VMM_VMM_X86_STARTUP_VMREG_H_ */
