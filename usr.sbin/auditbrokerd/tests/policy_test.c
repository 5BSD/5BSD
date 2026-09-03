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

/*
 * A session's BSM event class is derived from its authenticated provider label,
 * and only from the whitelisted providers.  A whitelisted bundle id (optionally
 * carrying a "/<unit>" suffix, which is stripped) yields its real event class; a
 * non-whitelisted label yields event 0, which start_session() turns into an
 * EACCES refusal.  The match is on the exact bundle-id component, so a look-alike
 * label (a longer name sharing a prefix) does not inherit another provider's
 * class.
 */
ATF_TC_WITHOUT_HEAD(event_class_derives_from_authenticated_label);
ATF_TC_BODY(event_class_derives_from_authenticated_label, tc)
{

	(void)tc;
	/* Whitelisted provider, with and without a unit suffix. */
	ATF_CHECK_EQ(AUE_LOGCMP_POLICY, auditcmp_policy_event("system.Log"));
	ATF_CHECK_EQ(AUE_NETWORKCMP_POLICY,
	    auditcmp_policy_event("system.Network/collector"));
	ATF_CHECK_EQ(AUE_BSDNOTIFY_POLICY,
	    auditcmp_policy_event("system.Notify/agent.0"));

	/* Non-whitelisted labels derive event 0 -> the session is refused. */
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.Trace"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("com.evil.Network"));
	/* Prefix look-alikes must not inherit a whitelisted provider's class. */
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.Logger"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.Lo"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.Networking"));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, identity_map);
	ATF_TP_ADD_TC(tp, event_class_derives_from_authenticated_label);
	return (atf_no_error());
}
