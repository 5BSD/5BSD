/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Schema evolution for system.SystemExtension (evolve:1/evolve:2 pairing).
 * next_peer is built from evolution/extensioncmp_next.fidl at bsd:2, which
 * adds a method to the production bsd:1 schema
 * (tools/build/fuchsia/test-bindings.py proves the two agree at bsd:1).  Both
 * directions run over a real capability channel:
 *
 * - the bsd:1 libextensioncmp client against a bsd:2 provider lists, stats
 *   and is refused a load;
 * - a bsd:2 client against the real bsd:1 BSDExtension worker is served
 *   List, and the added strict method closes only that session.
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

#include <libservice.h>
#include <extensioncmp.h>

#include "sysext_proto.h"
#include "bsdextension.h"

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
channel_pair(int ends[2])
{
	if (mac_capability_channel_create(ends) == -1) {
		if (errno == ENOSYS)
			atf_tc_skip("capability channel syscall unavailable");
		atf_tc_fail("channel creation: %s", strerror(errno));
	}
}

ATF_TC_WITHOUT_HEAD(v1_client_with_v2_provider);
ATF_TC_BODY(v1_client_with_v2_provider, tc)
{
	char names[SERVICE_EXTENSION_LIST_MAX][SERVICE_EXTENSION_NAME_MAX];
	struct extensioncmp_session *session;
	size_t count = 0;
	int ends[2], loaded = 0;
	pid_t peer;

	channel_pair(ends);
	peer = launch_peer(tc, "serve", ends[1]);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create(ends[0], &session));
	ATF_REQUIRE_EQ(0, extensioncmp_list(session, names,
	    SERVICE_EXTENSION_LIST_MAX, &count));
	ATF_CHECK_EQ(1, count);
	ATF_CHECK_STREQ("zfs", names[0]);
	ATF_REQUIRE_EQ(0, extensioncmp_stat(session, "zfs", &loaded));
	ATF_CHECK_EQ(1, loaded);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_load(session, "zfs") == -1);
	extensioncmp_session_close(session);
	ATF_CHECK_EQ(0, reap(peer));
}

ATF_TC_WITHOUT_HEAD(v2_client_with_v1_provider);
ATF_TC_BODY(v2_client_with_v1_provider, tc)
{
	struct sysext_config config;
	int ends[2];
	pid_t provider, caller;

	memset(&config, 0, sizeof(config));
	strlcpy(config.allow[0], "zfs", SYSEXT_NAME_MAX);
	config.nallow = 1;
	channel_pair(ends);
	provider = fork();
	ATF_REQUIRE(provider >= 0);
	if (provider == 0) {
		close(ends[0]);
		_exit(sysext_test_serve(ends[1], "org.test.evolve", &config));
	}
	close(ends[1]);
	caller = launch_peer(tc, "call", ends[0]);
	ATF_CHECK_EQ(0, reap(caller));
	/* The provider ended that session cleanly. */
	ATF_CHECK_EQ(0, reap(provider));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, v1_client_with_v2_provider);
	ATF_TP_ADD_TC(tp, v2_client_with_v1_provider);
	return (atf_no_error());
}
