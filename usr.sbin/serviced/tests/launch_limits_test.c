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
	m.ncap_paths = SERVICED_MAX_CAP_PATHS;
	m.ncap_files = SERVICED_MAX_CAP_FILES;
	m.ncap_net = SERVICED_MAX_CAP_NET;
	m.ncap_jail = SERVICED_MAX_CAP_JAIL;
	m.ncap_vsock = SERVICED_MAX_CAP_VSOCK;
	m.ncap_services = SERVICED_MAX_CAP_SERVICES;
	m.cap_system = 1;

	ATF_REQUIRE(svc_launch_counts_valid(&m));
	ATF_CHECK_EQ(SVC_LAUNCH_MAX_TOKENS, 81);
	ATF_CHECK_EQ(svc_launch_token_count(&m), SVC_LAUNCH_MAX_TOKENS);
	ATF_CHECK(SVC_LAUNCH_MAX_TOKENS <= SERVICE_BOOTSTRAP_TOKEN_MAX);
	ATF_CHECK_EQ(svc_launch_named_fd_count(&m),
	    SVC_LAUNCH_MAX_NAMED_FDS);
	ATF_CHECK(SVC_LAUNCH_MAX_NAMED_FDS <=
	    SERVICE_BOOTSTRAP_CAPABILITY_MAX);
}

ATF_TC(each_count_overflow);
ATF_TC_HEAD(each_count_overflow, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "Every launch collection independently rejects maximum plus one");
}
ATF_TC_BODY(each_count_overflow, tc)
{
	struct svc_manifest m;
	unsigned *counts[] = { &m.ncap_paths, &m.ncap_files, &m.ncap_net,
	    &m.ncap_jail, &m.ncap_vsock,
	    &m.ncap_services };
	const unsigned maxima[] = { SERVICED_MAX_CAP_PATHS,
	    SERVICED_MAX_CAP_FILES, SERVICED_MAX_CAP_NET,
	    SERVICED_MAX_CAP_JAIL, SERVICED_MAX_CAP_VSOCK,
	    SERVICED_MAX_CAP_SERVICES };
	size_t i;

	for (i = 0; i < nitems(counts); i++) {
		memset(&m, 0, sizeof(m));
		*counts[i] = maxima[i] + 1;
		ATF_CHECK_MSG(!svc_launch_counts_valid(&m),
		    "count %zu accepted maximum plus one", i);
	}
}

ATF_TC(services_are_the_only_named_descriptors);
ATF_TC_HEAD(services_are_the_only_named_descriptors, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "Storage is self-minted by the consumer over its own tzfsd channel; "
	    "serviced delivers no storage descriptor or token");
}
ATF_TC_BODY(services_are_the_only_named_descriptors, tc)
{
	struct svc_manifest m;

	memset(&m, 0, sizeof(m));
	ATF_CHECK_EQ(svc_launch_token_count(&m), 0);
	ATF_CHECK_EQ(svc_launch_named_fd_count(&m), 0);
	m.ncap_services = SERVICED_MAX_CAP_SERVICES;
	ATF_CHECK_EQ(svc_launch_named_fd_count(&m),
	    SVC_LAUNCH_MAX_NAMED_FDS);
	m.cap_system = 1;
	ATF_CHECK_EQ(svc_launch_token_count(&m), 1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, maximum_counts);
	ATF_TP_ADD_TC(tp, each_count_overflow);
	ATF_TP_ADD_TC(tp, services_are_the_only_named_descriptors);
	return (atf_no_error());
}
