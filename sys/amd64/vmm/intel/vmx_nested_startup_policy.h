/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_STARTUP_POLICY_H_
#define	_VMM_INTEL_VMX_NESTED_STARTUP_POLICY_H_

#include <sys/types.h>

#include "../vmm_x86_startup_transaction.h"

/*
 * Private value-only policy for composing the common x86 machine transaction
 * inside Intel's durable INIT/SIPI owner.  This is not architectural state,
 * save state, a userspace ABI, or an activation switch.
 */
enum vmx_nested_startup_machine_disposition {
	VMX_NESTED_STARTUP_MACHINE_FAIL_STOP = 0,
	VMX_NESTED_STARTUP_MACHINE_COMMITTED,
	VMX_NESTED_STARTUP_MACHINE_RETRY,
};

enum vmx_nested_startup_machine_disposition
	vmx_nested_startup_machine_disposition(int,
	    const struct vmm_x86_startup_transaction_result *);

#endif /* _VMM_INTEL_VMX_NESTED_STARTUP_POLICY_H_ */
