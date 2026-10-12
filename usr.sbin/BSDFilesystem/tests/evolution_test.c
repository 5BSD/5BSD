/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Schema evolution for system.Filesystem (evolve:1/evolve:2 pairing).
 * next_peer is built from evolution/filesystemcmp_next.fidl at bsd:2, which
 * adds a method to the production bsd:1 schema
 * (tools/build/fuchsia/test-bindings.py proves the two agree at bsd:1).  Both
 * directions run over a real capability channel:
 *
 * - the bsd:1 libfilesystemcmp client against a bsd:2 provider lists its
 *   claims and opens a path (receiving the descriptor);
 * - a bsd:2 client against the real bsd:1 BSDFilesystem worker is served
 *   Ping, and the added strict method closes only that session.
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

static int next_peer_open(const char *, int *);
#define service_open next_peer_open
#include <libservice.h>
/* The fixture has no service context; the client's check is not under test. */
#define service_context_check(context) ((void)(context), 0)
#include "../../../lib/libfilesystemcmp/filesystemcmp.c"
#undef service_context_check
#undef service_open

#include "bsdfilesystem.h"

static const atf_tc_t *current;
static pid_t peer = -1;

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

/* libfilesystemcmp's service_open: a channel to a bsd:2 next_peer server. */
static int
next_peer_open(const char *name, int *fdp)
{
	int ends[2];

	ATF_REQUIRE_STREQ(BSDFILESYSTEM_SERVICE_NAME, name);
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	peer = launch_peer(current, "serve", ends[1]);
	*fdp = ends[0];
	return (0);
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
	struct service_storage_claim claims[2];
	size_t count = 0;
	uint32_t cursor = 0;
	int fd = -1;

	require_plane();
	current = tc;
	ATF_REQUIRE_EQ(0, service_storage_list(NULL, claims, 2, &count,
	    &cursor));
	ATF_CHECK_EQ(1, count);
	ATF_CHECK_STREQ("state", claims[0].name);
	ATF_CHECK_EQ(4096, claims[0].used);
	ATF_CHECK_EQ(0, cursor);
	ATF_REQUIRE_EQ(0, service_open_isolated(NULL, "/dev/null",
	    SERVICE_OPEN_READ, 0, &fd));
	ATF_CHECK(fd >= 0);
	close(fd);
	pthread_mutex_lock(&fs_lock);
	fs_transport_drop(&fs_session);
	pthread_mutex_unlock(&fs_lock);
	ATF_CHECK_EQ(0, reap(peer));
}

ATF_TC(v2_client_with_v1_provider);
ATF_TC_HEAD(v2_client_with_v1_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(v2_client_with_v1_provider, tc)
{
	static struct bsdfilesystem_state st;
	int ends[2];
	pid_t provider, caller;

	require_plane();
	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = -1;
	st.root_fd = -1;
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	provider = fork();
	ATF_REQUIRE(provider >= 0);
	if (provider == 0) {
		close(ends[0]);
		_exit(bsdfilesystem_test_worker(&st, ends[1], "org.test.evolve"));
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
