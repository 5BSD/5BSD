/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <string.h>

#include <atf-c.h>

#include "policy.h"
#include "session.h"

ATF_TC(defaults);
ATF_TC_HEAD(defaults, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The fixed local component policy permits clients and denies "
	    "server authority");
}
ATF_TC_BODY(defaults, tc)
{
	struct networkcmp_policy policy;

	memset(&policy, 0xa5, sizeof(policy));
	ATF_REQUIRE(networkcmp_policy_default(&policy) == 0);
	ATF_CHECK(policy.ipv4);
	ATF_CHECK(policy.ipv6);
	ATF_CHECK(policy.allow_connect);
	ATF_CHECK(!policy.allow_bind);
	ATF_CHECK_EQ(16, policy.max_results);
	ATF_CHECK_EQ(NETWORKCMP_SESSION_MAX_SOCKETS, policy.max_sockets);
}

ATF_TC(independent_initialization);
ATF_TC_HEAD(independent_initialization, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Initializing one component policy does not retain prior state");
}
ATF_TC_BODY(independent_initialization, tc)
{
	struct networkcmp_policy policy;

	ATF_REQUIRE(networkcmp_policy_default(&policy) == 0);
	policy.allow_bind = true;
	policy.max_sockets = 1;
	ATF_REQUIRE(networkcmp_policy_default(&policy) == 0);
	ATF_CHECK(!policy.allow_bind);
	ATF_CHECK_EQ(NETWORKCMP_SESSION_MAX_SOCKETS, policy.max_sockets);
}

ATF_TC(arguments);
ATF_TC_HEAD(arguments, tc)
{
	atf_tc_set_md_var(tc, "descr", "Null policy output is rejected");
}
ATF_TC_BODY(arguments, tc)
{

	ATF_CHECK_ERRNO(EINVAL, networkcmp_policy_default(NULL) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, defaults);
	ATF_TP_ADD_TC(tp, independent_initialization);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
