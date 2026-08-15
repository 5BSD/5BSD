/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioccom.h>

#include <vmm.h>
#include <vmm_snapshot.h>
#include <vmm_dev.h>

#include <atf-c.h>
#include <stddef.h>
#include <stdint.h>

ATF_TC_WITHOUT_HEAD(layout);
ATF_TC_BODY(layout, tc)
{
	struct vm_snapshot_session session;

	(void)tc;
	ATF_REQUIRE_EQ(sizeof(session), 40);
	ATF_REQUIRE_EQ(offsetof(struct vm_snapshot_session, version), 0);
	ATF_REQUIRE_EQ(offsetof(struct vm_snapshot_session, op), 4);
	ATF_REQUIRE_EQ(offsetof(struct vm_snapshot_session, session_id), 8);
	ATF_REQUIRE_EQ(offsetof(struct vm_snapshot_session, flags), 16);
	ATF_REQUIRE_EQ(offsetof(struct vm_snapshot_session, reserved), 24);
	ATF_REQUIRE_EQ(sizeof(session.reserved), 16);
}

ATF_TC_WITHOUT_HEAD(constants);
ATF_TC_BODY(constants, tc)
{

	(void)tc;
	ATF_REQUIRE_EQ(VM_SNAPSHOT_SESSION_VERSION, 1U);
	ATF_REQUIRE_EQ(VM_SNAPSHOT_SESSION_BEGIN, 1);
	ATF_REQUIRE_EQ(VM_SNAPSHOT_SESSION_COMMIT, 2);
	ATF_REQUIRE_EQ(VM_SNAPSHOT_SESSION_ABORT, 3);
	ATF_REQUIRE_EQ(VM_SNAPSHOT_SESSION_ABORT_CURRENT, 4);
	ATF_REQUIRE_EQ(IOCNUM_SNAPSHOT_SESSION, 114);
	ATF_REQUIRE_EQ(IOCPARM_LEN(VM_SNAPSHOT_SESSION),
	    sizeof(struct vm_snapshot_session));
	ATF_REQUIRE((VM_SNAPSHOT_SESSION & IOC_DIRMASK & IOC_IN) != 0);
	ATF_REQUIRE((VM_SNAPSHOT_SESSION & IOC_DIRMASK & IOC_OUT) != 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, layout);
	ATF_TP_ADD_TC(tp, constants);
	return (atf_no_error());
}
