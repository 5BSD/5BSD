/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <bsm/audit_kevents.h>
#include <atf-c.h>

#include "auditcmp_policy.h"

ATF_TC_WITHOUT_HEAD(identity_map);
ATF_TC_BODY(identity_map, tc)
{

	ATF_CHECK_EQ(AUE_NETWORKCMP_POLICY,
	    auditcmp_policy_event("system.Network"));
	ATF_CHECK_EQ(AUE_LOGCMP_POLICY,
	    auditcmp_policy_event("system.Log"));
	ATF_CHECK_EQ(AUE_BSDNOTIFY_POLICY,
	    auditcmp_policy_event("system.Notify"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("*"));
	ATF_CHECK_EQ(0, auditcmp_policy_event(""));
	ATF_CHECK_EQ(0, auditcmp_policy_event(NULL));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, identity_map);
	return (atf_no_error());
}
