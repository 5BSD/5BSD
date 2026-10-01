/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <atf-c.h>
#include <string.h>

#include "switchboard.h"

ATF_TC_WITHOUT_HEAD(every_policy_has_its_own_name);
ATF_TC_BODY(every_policy_has_its_own_name, tc)
{

	ATF_CHECK_STREQ(restart_policy_name(SVC_RESTART_ALWAYS), "always");
	ATF_CHECK_STREQ(restart_policy_name(SVC_RESTART_ON_FAILURE),
	    "on-failure");
	ATF_CHECK_STREQ(restart_policy_name(SVC_RESTART_ON_CRASH), "on-crash");
	ATF_CHECK_STREQ(restart_policy_name(SVC_RESTART_NEVER), "never");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, every_policy_has_its_own_name);
	return (atf_no_error());
}
