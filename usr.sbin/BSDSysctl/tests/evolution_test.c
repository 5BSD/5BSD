/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Schema evolution for system.Sysctl (evolve:1/evolve:2 pairing).  next_peer
 * is built from evolution/sysctlcmp_next.fidl at bsd:2, which adds a method
 * to the production bsd:1 schema (tools/build/fuchsia/test-bindings.py proves
 * the two agree at bsd:1).  Both directions run over a real capability
 * channel: the bsd:1 libsysctlcmp client reads from a bsd:2 provider, and a
 * bsd:2 client is served by the real bsd:1 BSDSysctl reactor until it calls
 * the added strict method, which closes only that session.
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

#include <sysctlcmp.h>

#include "config.h"
#include "bsdsysctl_test.h"

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
	struct sysctlcmp_client *client;
	char value[32];
	size_t length = sizeof(value);
	int ends[2];
	pid_t peer;

	require_plane();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	peer = launch_peer(tc, "serve", ends[1]);
	ATF_REQUIRE_EQ(0, sysctlcmp_client_create(ends[0], &client));
	ATF_REQUIRE_EQ(0, sysctlcmp_get(client, "kern.ostype", value, &length));
	ATF_CHECK_EQ(5, length);
	ATF_CHECK_STREQ("5BSD", value);
	sysctlcmp_client_close(client);
	ATF_CHECK_EQ(0, reap(peer));
}

ATF_TC(v2_client_with_v1_provider);
ATF_TC_HEAD(v2_client_with_v1_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(v2_client_with_v1_provider, tc)
{
	struct sysctlcmp_config config;
	int ends[2];
	pid_t provider, caller;

	require_plane();
	memset(&config, 0, sizeof(config));
	strlcpy(config.default_acl.read[0], "kern.ostype",
	    sizeof(config.default_acl.read[0]));
	config.default_acl.nread = 1;
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	provider = fork();
	ATF_REQUIRE(provider >= 0);
	if (provider == 0) {
		close(ends[0]);
		_exit(sysctlcmp_test_serve(ends[1], "org.test.evolve",
		    &config));
	}
	close(ends[1]);
	caller = launch_peer(tc, "call", ends[0]);
	ATF_CHECK_EQ(0, reap(caller));
	/* The unknown strict method is reported as a protocol failure. */
	ATF_CHECK_EQ(1, reap(provider));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, v1_client_with_v2_provider);
	ATF_TP_ADD_TC(tp, v2_client_with_v1_provider);
	return (atf_no_error());
}
