/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <atf-c.h>
#include <string.h>

#include "launch_limits.h"

ATF_TC(maximum_counts);
ATF_TC_HEAD(maximum_counts, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "All maximum manifest counts fit the launch table");
}
ATF_TC_BODY(maximum_counts, tc)
{
	struct svc_manifest m;

	memset(&m, 0, sizeof(m));
	m.cap_system = 1;

	ATF_REQUIRE(svc_launch_counts_valid(&m));
	ATF_CHECK_EQ(SVC_LAUNCH_MAX_TOKENS, 1);
	ATF_CHECK_EQ(svc_launch_token_count(&m), SVC_LAUNCH_MAX_TOKENS);
	ATF_CHECK(SVC_LAUNCH_MAX_TOKENS <= SERVICE_BOOTSTRAP_TOKEN_MAX);
}

ATF_TC(token_count_tracks_delegated_capabilities);
ATF_TC_HEAD(token_count_tracks_delegated_capabilities, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "The launch token count reflects only path, network, and system "
	    "capabilities; storage and other services are self-minted by the "
	    "consumer and deliver no serviced token");
}
ATF_TC_BODY(token_count_tracks_delegated_capabilities, tc)
{
	struct svc_manifest m;

	memset(&m, 0, sizeof(m));
	ATF_CHECK_EQ(svc_launch_token_count(&m), 0);
	m.cap_system = 1;
	ATF_CHECK_EQ(svc_launch_token_count(&m), 1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, maximum_counts);
	ATF_TP_ADD_TC(tp, token_count_tracks_delegated_capabilities);
	return (atf_no_error());
}
