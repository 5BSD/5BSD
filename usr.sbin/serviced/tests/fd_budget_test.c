/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/un.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Exercise the private admission implementation without daemon state. */
#include "../fd_budget.c"

static void
lower_limit(void)
{
	struct rlimit limit;

	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, &limit));
	if (limit.rlim_cur > 128)
		limit.rlim_cur = 128;
	if (limit.rlim_cur < 32)
		atf_tc_skip("descriptor limit is too small for the reserve test");
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &limit));
}

static size_t
fill_descriptors(int *fds, size_t capacity)
{
	size_t n;

	for (n = 0; n < capacity; n++) {
		fds[n] = open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (fds[n] == -1)
			break;
	}
	ATF_REQUIRE_MSG(n < capacity, "test did not reach RLIMIT_NOFILE");
	ATF_REQUIRE_EQ(EMFILE, errno);
	return (n);
}

ATF_TC(raise_limit);
ATF_TC_HEAD(raise_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "serviced raises its soft descriptor limit before reserving slots");
}
ATF_TC_BODY(raise_limit, tc)
{
	struct serviced_fd_budget_stats stats;
	struct rlimit before, lowered, after;

	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, &before));
	if (before.rlim_cur <= 128 ||
	    (before.rlim_max != RLIM_INFINITY && before.rlim_max <= 128))
		atf_tc_skip("inherited descriptor ceiling is too small");
	lowered = before;
	lowered.rlim_cur = 128;
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &lowered));
	ATF_REQUIRE_EQ(0, serviced_fd_budget_raise_limit());
	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, &after));
	ATF_CHECK(after.rlim_cur > lowered.rlim_cur);
	ATF_CHECK(after.rlim_cur <= after.rlim_max ||
	    after.rlim_max == RLIM_INFINITY);
	serviced_fd_budget_get_stats(&stats);
	ATF_CHECK_EQ(after.rlim_cur, stats.soft_limit);
	ATF_CHECK_EQ(after.rlim_max, stats.hard_limit);
}

ATF_TC(raise_at_inherited_ceiling);
ATF_TC_HEAD(raise_at_inherited_ceiling, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "raising the budget honors the inherited ceiling without "
	    "privilege and the kernel maximum with it");
}
ATF_TC_BODY(raise_at_inherited_ceiling, tc)
{
	struct serviced_fd_budget_stats stats;
	struct rlimit limit;

	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, &limit));
	if (limit.rlim_cur < 64 ||
	    (limit.rlim_max != RLIM_INFINITY && limit.rlim_max < 64))
		atf_tc_skip("inherited descriptor ceiling is too small");
	limit.rlim_cur = 64;
	limit.rlim_max = 64;
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &limit));
	ATF_REQUIRE_EQ(0, serviced_fd_budget_raise_limit());
	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, &limit));
	if (geteuid() == 0) {
		/* Root may raise the hard limit again, so the budget targets
		 * kern.maxfilesperproc instead of the inherited ceiling. */
		int kernel_max;
		size_t length = sizeof(kernel_max);

		ATF_REQUIRE_EQ(0, sysctlbyname("kern.maxfilesperproc",
		    &kernel_max, &length, NULL, 0));
		ATF_CHECK_EQ((rlim_t)kernel_max, limit.rlim_cur);
		ATF_CHECK_EQ((rlim_t)kernel_max, limit.rlim_max);
	} else {
		ATF_CHECK_EQ(64, limit.rlim_cur);
		ATF_CHECK_EQ(64, limit.rlim_max);
	}
	serviced_fd_budget_get_stats(&stats);
	ATF_CHECK_EQ(limit.rlim_cur, stats.soft_limit);
	ATF_CHECK_EQ(limit.rlim_max, stats.hard_limit);
}

ATF_TC(reserve_and_admission);
ATF_TC_HEAD(reserve_and_admission, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "descriptor admission preserves an emergency reserve");
}
ATF_TC_BODY(reserve_and_admission, tc)
{
	struct serviced_fd_budget_stats stats;
	int fillers[256];
	size_t n;

	lower_limit();
	ATF_REQUIRE_EQ(0, serviced_fd_budget_init());
	serviced_fd_budget_get_stats(&stats);
	ATF_CHECK_EQ(SERVICED_FD_EMERGENCY_RESERVE, stats.reserve_count);
	ATF_REQUIRE_EQ(0, serviced_fd_budget_check(4, "unit-test"));
	n = fill_descriptors(fillers, nitems(fillers));
	ATF_CHECK_ERRNO(EMFILE,
	    serviced_fd_budget_check(1, "exhausted") == -1);
	serviced_fd_budget_get_stats(&stats);
	ATF_CHECK_EQ(1, stats.admission_denied);
	ATF_REQUIRE(n >= 3);
	close(fillers[--n]);
	close(fillers[--n]);
	close(fillers[--n]);
	ATF_CHECK_EQ(0, serviced_fd_budget_check(3, "recovered"));
	while (n > 0)
		close(fillers[--n]);
	serviced_fd_budget_fini();
}

ATF_TC(control_shedding);
ATF_TC_HEAD(control_shedding, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "one reserved slot drains a queued control client at EMFILE");
}
ATF_TC_BODY(control_shedding, tc)
{
	struct serviced_fd_budget_stats stats;
	struct sockaddr_un address;
	char path[sizeof(address.sun_path)];
	int fillers[256];
	int client, listener;
	size_t n;

	lower_limit();
	ATF_REQUIRE_EQ(0, serviced_fd_budget_init());
	listener = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	ATF_REQUIRE(listener >= 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_LOCAL;
	snprintf(path, sizeof(path), "/tmp/serviced-fd.%jd.sock",
	    (intmax_t)getpid());
	strlcpy(address.sun_path, path, sizeof(address.sun_path));
	(void)unlink(path);
	ATF_REQUIRE_EQ(0, bind(listener, (struct sockaddr *)&address,
	    sizeof(address)));
	ATF_REQUIRE_EQ(0, listen(listener, 1));
	client = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	ATF_REQUIRE(client >= 0);
	ATF_REQUIRE_EQ(0, connect(client, (struct sockaddr *)&address,
	    sizeof(address)));
	n = fill_descriptors(fillers, nitems(fillers));
	ATF_CHECK_ERRNO(EMFILE,
	    serviced_fd_budget_check(1, "control connection") == -1);
	serviced_fd_budget_shed_control(listener);
	serviced_fd_budget_get_stats(&stats);
	ATF_CHECK_EQ(1, stats.control_shed);
	ATF_CHECK_EQ(SERVICED_FD_EMERGENCY_RESERVE, stats.reserve_count);
	while (n > 0)
		close(fillers[--n]);
	close(client);
	close(listener);
	(void)unlink(path);
	serviced_fd_budget_fini();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, raise_limit);
	ATF_TP_ADD_TC(tp, raise_at_inherited_ceiling);
	ATF_TP_ADD_TC(tp, reserve_and_admission);
	ATF_TP_ADD_TC(tp, control_shedding);
	return (atf_no_error());
}
