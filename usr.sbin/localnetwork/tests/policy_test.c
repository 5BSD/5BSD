/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <string.h>

#include <atf-c.h>

#include "policy.h"

ATF_TC(defaults);
ATF_TC_HEAD(defaults, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The full (admin-equivalent) policy permits every operation, "
	    "including internal destinations");
}
ATF_TC_BODY(defaults, tc)
{
	struct networkcmp_policy policy;

	memset(&policy, 0xa5, sizeof(policy));
	ATF_REQUIRE(networkcmp_policy_default(&policy) == 0);
	ATF_CHECK(policy.ipv4);
	ATF_CHECK(policy.ipv6);
	ATF_CHECK(policy.allow_connect);
	ATF_CHECK(policy.allow_udp);
	ATF_CHECK(policy.resolve);
	ATF_CHECK(policy.allow_internal);
	ATF_CHECK(networkcmp_policy_permits_any(&policy));
	ATF_CHECK_EQ(16, policy.max_results);
}

ATF_TC(rights_none_denies_all);
ATF_TC_HEAD(rights_none_denies_all, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A session that carries no network rights derives an all-deny "
	    "policy (default-deny), permitting nothing");
}
ATF_TC_BODY(rights_none_denies_all, tc)
{
	struct networkcmp_policy policy;

	memset(&policy, 0xa5, sizeof(policy));
	ATF_REQUIRE(networkcmp_policy_from_rights(&policy,
	    SERVICE_RIGHTS_NONE) == 0);
	ATF_CHECK(!policy.ipv4);
	ATF_CHECK(!policy.ipv6);
	ATF_CHECK(!policy.allow_connect);
	ATF_CHECK(!policy.allow_udp);
	ATF_CHECK(!policy.resolve);
	ATF_CHECK(!policy.allow_internal);
	ATF_CHECK(!networkcmp_policy_permits_any(&policy));
	ATF_CHECK_EQ(0, policy.max_results);
}

ATF_TC(rights_derive_per_bit);
ATF_TC_HEAD(rights_derive_per_bit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Each policy dimension is enabled only when its right is held; "
	    "internal reach stays denied without its bit");
}
ATF_TC_BODY(rights_derive_per_bit, tc)
{
	struct networkcmp_policy policy;

	/* A TCP-over-IPv4 grant: connect only, no udp/resolve/internal. */
	ATF_REQUIRE(networkcmp_policy_from_rights(&policy,
	    NETWORKCMP_RIGHT_CONNECT | NETWORKCMP_RIGHT_INET4) == 0);
	ATF_CHECK(policy.ipv4);
	ATF_CHECK(!policy.ipv6);
	ATF_CHECK(policy.allow_connect);
	ATF_CHECK(!policy.allow_udp);
	ATF_CHECK(!policy.resolve);
	ATF_CHECK(!policy.allow_internal);
	ATF_CHECK(networkcmp_policy_permits_any(&policy));
	ATF_CHECK_EQ(0, policy.max_results);

	/* Resolve-only lifts the result ceiling but grants no transport. */
	ATF_REQUIRE(networkcmp_policy_from_rights(&policy,
	    NETWORKCMP_RIGHT_RESOLVE) == 0);
	ATF_CHECK(policy.resolve);
	ATF_CHECK(!policy.allow_connect);
	ATF_CHECK(!policy.allow_udp);
	ATF_CHECK_EQ(16, policy.max_results);

	/* The internal-reach bit is required for internal destinations. */
	ATF_REQUIRE(networkcmp_policy_from_rights(&policy,
	    NETWORKCMP_RIGHT_CONNECT | NETWORKCMP_RIGHT_INET4 |
	    NETWORKCMP_RIGHT_INTERNAL) == 0);
	ATF_CHECK(policy.allow_internal);
}

ATF_TC(rights_admin_grants_all);
ATF_TC_HEAD(rights_admin_grants_all, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SERVICE_RIGHTS_ADMIN bypasses per-bit gating and grants every "
	    "dimension, including internal reach");
}
ATF_TC_BODY(rights_admin_grants_all, tc)
{
	struct networkcmp_policy policy;

	ATF_REQUIRE(networkcmp_policy_from_rights(&policy,
	    SERVICE_RIGHTS_ADMIN) == 0);
	ATF_CHECK(policy.ipv4);
	ATF_CHECK(policy.ipv6);
	ATF_CHECK(policy.allow_connect);
	ATF_CHECK(policy.allow_udp);
	ATF_CHECK(policy.resolve);
	ATF_CHECK(policy.allow_internal);
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
	policy.allow_connect = false;
	policy.max_results = 1;
	ATF_REQUIRE(networkcmp_policy_default(&policy) == 0);
	ATF_CHECK(policy.allow_connect);
	ATF_CHECK_EQ(16, policy.max_results);
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
	ATF_TP_ADD_TC(tp, rights_none_denies_all);
	ATF_TP_ADD_TC(tp, rights_derive_per_bit);
	ATF_TP_ADD_TC(tp, rights_admin_grants_all);
	ATF_TP_ADD_TC(tp, independent_initialization);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
