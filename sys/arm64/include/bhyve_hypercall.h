/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Guest-side 5BSD HyperTrace HVC ABI.  These vendor hypervisor service calls
 * are private to a matched 5BSD guest and bhyve host.
 */
#ifndef _ARM64_BHYVE_HYPERCALL_H_
#define _ARM64_BHYVE_HYPERCALL_H_

#include <sys/systm.h>
#include <sys/types.h>
#include <dev/psci/psci.h>
#include <dev/psci/smccc.h>

#define BHYVE_HYPERTRACE_SIGNATURE 0x48545243U
/* Version 5 carries bounded raw guest kernel PCs for stack(). */
#define BHYVE_HYPERTRACE_VERSION 5U
#define BHYVE_HYPERTRACE_QUERY \
    SMCCC_FUNC_ID(SMCCC_FAST_CALL, SMCCC_64BIT_CALL, \
    SMCCC_VENDOR_HYP_SERVICE_CALLS, 0x4854)
/* Functions 0x4855 through 0x4857 carried shorter probe blocks. */
#define BHYVE_HYPERTRACE_PROBE \
    SMCCC_FUNC_ID(SMCCC_FAST_CALL, SMCCC_64BIT_CALL, \
    SMCCC_VENDOR_HYP_SERVICE_CALLS, 0x4858)
#define HYPERCALL_RET_SUCCESS 0

static __inline int
bhyve_hypercalls_enabled(void)
{
	struct arm_smccc_res res;

	/*
	 * Never execute HVC on a bare-metal kernel.  A PSCI conduit of HVC
	 * means a hypervisor takes the call, and any other returns an error.
	 */
	if (!psci_present || psci_callfn != arm_smccc_hvc)
		return (0);
	arm_smccc_invoke_1(arm_smccc_hvc, BHYVE_HYPERTRACE_QUERY, &res);
	return (res.a0 == BHYVE_HYPERTRACE_VERSION &&
	    res.a1 == BHYVE_HYPERTRACE_SIGNATURE);
}

static __inline int
hypercall_dtrace_probe(int id, uintptr_t args, lwpid_t tid)
{
	struct arm_smccc_res res;

	arm_smccc_invoke_4(arm_smccc_hvc, BHYVE_HYPERTRACE_PROBE,
	    id, args, tid, &res);
	return (res.a0 == 0 ? HYPERCALL_RET_SUCCESS : -1);
}

#endif /* _ARM64_BHYVE_HYPERCALL_H_ */
