/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <sys/limits.h>

#include <atf-c.h>

#include "../../../sys/amd64/include/vmm_snapshot.h"

ATF_TC(kernel_snapshot_operation_boundary);
ATF_TC_HEAD(kernel_snapshot_operation_boundary, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "Only save and restore cross the kernel snapshot ioctl boundary");
}
ATF_TC_BODY(kernel_snapshot_operation_boundary, tc)
{

	ATF_CHECK(vm_snapshot_op_is_kernel(VM_SNAPSHOT_SAVE));
	ATF_CHECK(vm_snapshot_op_is_kernel(VM_SNAPSHOT_RESTORE));
	ATF_CHECK(!vm_snapshot_op_is_kernel(VM_SNAPSHOT_VALIDATE));
	ATF_CHECK(!vm_snapshot_op_is_kernel((enum vm_snapshot_op)-1));
	ATF_CHECK(!vm_snapshot_op_is_kernel((enum vm_snapshot_op)3));
	ATF_CHECK(!vm_snapshot_op_is_kernel((enum vm_snapshot_op)INT_MAX));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, kernel_snapshot_operation_boundary);
	return (atf_no_error());
}
