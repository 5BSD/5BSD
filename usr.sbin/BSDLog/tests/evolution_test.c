/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Schema evolution for system.Log (evolve:1/evolve:2 pairing).  next_peer is
 * built from evolution/logcmp_next.fidl at bsd:2, which adds a method to the
 * production bsd:1 schema (tools/build/fuchsia/test-bindings.py proves the
 * two agree at bsd:1).  Both directions run over a real capability channel:
 * the bsd:1 liblogcmp client (its source, with discovery replaced by the test
 * channel) is served by a bsd:2 provider, and a bsd:2 client is served by
 * the real bsd:1 BSDLog session code until it calls the added strict method,
 * which ends only that session.
 */
#include <sys/param.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int test_client_fd = -1;

static int
test_service_open(const char *name, int *fd)
{
	(void)name;
	*fd = test_client_fd;
	test_client_fd = -1;
	return (*fd < 0 ? (errno = ENOENT, -1) : 0);
}

#define service_open test_service_open
#include "../../../lib/liblogcmp/logcmp.c"
#undef service_open

#include "logcmp_test.h"

static pid_t
launch_peer(const atf_tc_t *tc, const char *role, int fd)
{
	char path[PATH_MAX];
	pid_t child;

	snprintf(path, sizeof(path), "%s/next_peer",
	    atf_tc_get_config_var(tc, "srcdir"));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		/*
		 * The peer must hold only its own end: an inherited copy of the
		 * test's end would keep the channel open after the test closes it.
		 */
		if (fd == 3 ? fcntl(3, F_SETFD, 0) < 0 : dup2(fd, 3) < 0)
			_exit(126);
		closefrom(4);
		execl(path, path, role, "3", (char *)NULL);
		_exit(127);
	}
	close(fd);
	return (child);
}

static int
reap(pid_t child)
{
	int status;
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

static void
require_plane(void)
{
	int fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("capability plane unavailable: %s",
		    strerror(errno));
	close(fd);
}

ATF_TC(v1_client_with_v2_provider);
ATF_TC_HEAD(v1_client_with_v2_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(v1_client_with_v2_provider, tc)
{
	struct logcmp_client *client;
	struct logcmp_stats stats;
	int ends[2];
	pid_t peer;

	require_plane();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	peer = launch_peer(tc, "serve", ends[1]);
	test_client_fd = ends[0];
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_stats(client, &stats));
	ATF_CHECK_EQ(5, stats.accepted);
	logcmp_client_close(client);
	ATF_CHECK_EQ(0, reap(peer));
}

ATF_TC(v2_client_with_v1_provider);
ATF_TC_HEAD(v2_client_with_v1_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(v2_client_with_v1_provider, tc)
{
	int ends[2];
	pid_t provider, caller;

	require_plane();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	provider = fork();
	ATF_REQUIRE(provider >= 0);
	if (provider == 0) {
		close(ends[0]);
		_exit(logcmp_test_serve(ends[1], "org.test.evolve",
		    64U * 1024, 0));
	}
	close(ends[1]);
	caller = launch_peer(tc, "call", ends[0]);
	ATF_CHECK_EQ(0, reap(caller));
	/* The unknown strict method is a protocol failure for that session. */
	ATF_CHECK_EQ(1, reap(provider));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, v1_client_with_v2_provider);
	ATF_TP_ADD_TC(tp, v2_client_with_v1_provider);
	return (atf_no_error());
}
