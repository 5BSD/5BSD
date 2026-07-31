/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <string.h>

#include "policy.h"

ATF_TC_WITHOUT_HEAD(default_deny);
ATF_TC_BODY(default_deny, tc)
{
	struct notifycmp_policy policy;

	ATF_REQUIRE_EQ(0, notifycmp_policy_parse("{}", &policy));
	ATF_CHECK(!policy.timers);
	ATF_CHECK(!notifycmp_policy_can_publish(&policy, "system.ready",
	    strlen("system.ready")));
	ATF_CHECK(!notifycmp_policy_can_subscribe(&policy, "system.ready",
	    strlen("system.ready")));
}

ATF_TC_WITHOUT_HEAD(exact_topics);
ATF_TC_BODY(exact_topics, tc)
{
	struct notifycmp_policy policy;

	ATF_REQUIRE_EQ(0, notifycmp_policy_parse(
	    "{publish=[\"system.ready\"];"
	    "subscribe=[\"system.ready\",\"system.stop\"];timers=true;}",
	    &policy));
	ATF_CHECK(policy.timers);
	ATF_CHECK(notifycmp_policy_can_publish(&policy, "system.ready",
	    strlen("system.ready")));
	ATF_CHECK(!notifycmp_policy_can_publish(&policy, "system.stop",
	    strlen("system.stop")));
	ATF_CHECK(notifycmp_policy_can_subscribe(&policy, "system.stop",
	    strlen("system.stop")));
	ATF_CHECK(!notifycmp_policy_can_subscribe(&policy, "system",
	    strlen("system")));
}

ATF_TC_WITHOUT_HEAD(wildcard);
ATF_TC_BODY(wildcard, tc)
{
	struct notifycmp_policy policy;

	ATF_REQUIRE_EQ(0, notifycmp_policy_parse(
	    "{publish=[\"*\"];subscribe=[\"*\"];}", &policy));
	ATF_CHECK(notifycmp_policy_can_publish(&policy, "any.valid-topic",
	    strlen("any.valid-topic")));
	ATF_CHECK(notifycmp_policy_can_subscribe(&policy, "another",
	    strlen("another")));
}

ATF_TC_WITHOUT_HEAD(rejects_invalid_policy);
ATF_TC_BODY(rejects_invalid_policy, tc)
{
	struct notifycmp_policy policy;

	ATF_CHECK_ERRNO(EINVAL,
	    notifycmp_policy_parse("{unknown=true;}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notifycmp_policy_parse("{timers=\"yes\";}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notifycmp_policy_parse("{publish=\"topic\";}", &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notifycmp_policy_parse("{publish=[\"*\",\"topic\"];}",
	    &policy) == -1);
	ATF_CHECK_ERRNO(EEXIST,
	    notifycmp_policy_parse("{subscribe=[\"topic\",\"topic\"];}",
	    &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notifycmp_policy_parse("{publish=[\"bad topic\"];}",
	    &policy) == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, default_deny);
	ATF_TP_ADD_TC(tp, exact_topics);
	ATF_TP_ADD_TC(tp, wildcard);
	ATF_TP_ADD_TC(tp, rejects_invalid_policy);
	return (atf_no_error());
}
