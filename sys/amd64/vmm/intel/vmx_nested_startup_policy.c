/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include "vmx_nested_startup_policy.h"

enum vmx_nested_startup_machine_disposition
vmx_nested_startup_machine_disposition(int error,
    const struct vmm_x86_startup_transaction_result *result)
{

	switch (vmm_x86_startup_transaction_result_classify(error, result)) {
	case VMM_X86_STARTUP_TRANSACTION_OUTCOME_COMMITTED:
		return (VMX_NESTED_STARTUP_MACHINE_COMMITTED);
	case VMM_X86_STARTUP_TRANSACTION_OUTCOME_ROLLED_BACK:
		return (VMX_NESTED_STARTUP_MACHINE_RETRY);
	case VMM_X86_STARTUP_TRANSACTION_OUTCOME_POISONED:
	case VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID:
	default:
		return (VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
	}
}
