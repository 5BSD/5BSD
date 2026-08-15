/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <stdint.h>

#include <atf-c.h>

/* Use the source ABI so this test cannot silently use stale installed enums. */
#include "../../../sys/amd64/include/vmm.h"
#include "../../../sys/amd64/vmm/vmm_exception.c"

ATF_TC_WITHOUT_HEAD(debug_classification);
ATF_TC_BODY(debug_classification, tc)
{
	uint64_t dr7;

	(void)tc;
	ATF_CHECK_EQ(vm_debug_exception_class(DBREG_DR6_BT, 0),
	    VM_EXCEPTION_TASK_SWITCH);
	ATF_CHECK_EQ(vm_debug_exception_class(DBREG_DR6_BD, 0),
	    VM_EXCEPTION_FAULT);
	ATF_CHECK_EQ(vm_debug_exception_class(DBREG_DR6_BS, 0),
	    VM_EXCEPTION_TRAP);
	ATF_CHECK_EQ(vm_debug_exception_class(0, 0), VM_EXCEPTION_TRAP);

	dr7 = DBREG_DR7_SET(2, DBREG_DR7_LEN_1, DBREG_DR7_EXEC,
	    DBREG_DR7_LOCAL_ENABLE);
	ATF_CHECK_EQ(vm_debug_exception_class(DBREG_DR6_B(2), dr7),
	    VM_EXCEPTION_FAULT);
	dr7 = DBREG_DR7_SET(2, DBREG_DR7_LEN_4, DBREG_DR7_RDWR,
	    DBREG_DR7_GLOBAL_ENABLE);
	ATF_CHECK_EQ(vm_debug_exception_class(DBREG_DR6_B(2), dr7),
	    VM_EXCEPTION_TRAP);

	/* Fault-like causes win when hardware reports combined causes. */
	ATF_CHECK_EQ(vm_debug_exception_class(DBREG_DR6_BS | DBREG_DR6_BD,
	    0), VM_EXCEPTION_FAULT);
	ATF_CHECK_EQ(vm_debug_exception_class(DBREG_DR6_BT | DBREG_DR6_BD,
	    0), VM_EXCEPTION_TASK_SWITCH);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, debug_classification);
	return (atf_no_error());
}
