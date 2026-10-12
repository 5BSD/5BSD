/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Schema evolution for system.Power (evolve:1/evolve:2 pairing).  next_peer
 * is built from evolution/powercmp_next.fidl at bsd:2, which adds a method to
 * the production bsd:1 schema (tools/build/fuchsia/test-bindings.py proves the
 * two agree at bsd:1).  Both directions run over a real capability channel:
 *
 * - a bsd:1 libpowercmp client against a bsd:2 provider uses every method it
 *   knows;
 * - a bsd:2 client against the real bsd:1 BSDPower server is served the
 *   bsd:1 methods, and the added strict method closes only that session.
 */
#include <sys/param.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <powercmp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "BSDPower_test.h"

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
	struct powercmp_client *client;
	uint32_t supported = 0, count = 0;
	int ends[2];
	pid_t peer;

	require_plane();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	peer = launch_peer(tc, "serve", ends[1]);
	ATF_REQUIRE_EQ(0, powercmp_client_create(ends[0], &client));
	ATF_CHECK_EQ(0, powercmp_states(client, &supported));
	ATF_CHECK_EQ(1u << 3 | 1u << 5, supported);
	ATF_CHECK_EQ(0, powercmp_inhibitors(client, &count));
	ATF_CHECK_EQ(2, count);
	powercmp_client_close(client);
	ATF_CHECK_EQ(0, reap(peer));
}

ATF_TC(v2_client_with_v1_provider);
ATF_TC_HEAD(v2_client_with_v1_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(v2_client_with_v1_provider, tc)
{
	struct powercmp_config config;
	int ends[2];
	pid_t provider, peer;

	require_plane();
	powercmp_config_defaults(&config);
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	provider = fork();
	ATF_REQUIRE(provider >= 0);
	if (provider == 0) {
		close(ends[0]);
		bsdpower_test_set_acpi_fd(-1);
		bsdpower_test_set_states(1u << 3);
		_exit(bsdpower_test_serve_session(ends[1], "org.test.evolve",
		    &config));
	}
	close(ends[1]);
	peer = launch_peer(tc, "call", ends[0]);
	ATF_CHECK_EQ(0, reap(peer));
	/* The provider ended that session cleanly. */
	ATF_CHECK_EQ(0, reap(provider));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, v1_client_with_v2_provider);
	ATF_TP_ADD_TC(tp, v2_client_with_v1_provider);
	return (atf_no_error());
}
