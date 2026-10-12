/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The production BSDSysctl reactor (sessions_admit/sessions_wait over
 * fidl_bsd_connections_wait) with real capability channels and real
 * libsysctlcmp clients: per-session policy isolation, a malformed peer that
 * cannot stall the others, idle expiry, and admission bounds with slot reuse.
 */
#include <sys/wait.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SYSCTLCMP_TESTING
#include "../bsdsysctl.c"

static void
require_plane(void)
{
	int fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("capability plane unavailable: %s",
		    strerror(errno));
	close(fd);
}

/* 0 on success, else the errno the call failed with. */
static int
get_op(struct sysctlcmp_client *client, const char *name)
{
	char value[128];
	size_t length = sizeof(value);

	return (sysctlcmp_get(client, name, value, &length) == 0 ? 0 : errno);
}

static int
interfaces_op(struct sysctlcmp_client *client)
{
	size_t count = 0;

	return (sysctlcmp_interfaces(client, NULL, &count) == 0 ? 0 : errno);
}

ATF_TC(idle_and_policy_isolation);
ATF_TC_HEAD(idle_and_policy_isolation, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(idle_and_policy_isolation, tc)
{
	struct sysctlcmp_config config = { 0 };
	const char *labels[] = { "idle", "allowed", "denied" };
	struct sysctlcmp_client *clients[3] = { 0 };
	struct service_session *raw;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message garbage = { .size = sizeof(garbage),
		.data = "x", .length = 1 };
	uint8_t reply[16];
	struct service_reply incoming = { .size = sizeof(incoming),
		.data = reply, .capacity = sizeof(reply) };
	int pairs[3][2], providers[3], status;
	pid_t child;

	require_plane();
	config.nclients = 1;
	strlcpy(config.clients[0].label, "allowed",
	    sizeof(config.clients[0].label));
	config.clients[0].acl.nread = 2;
	strlcpy(config.clients[0].acl.read[1], SYSCTLCMP_INTERFACES_POLICY,
	    SYSCTLCMP_MAX_PREFIX);
	strlcpy(config.clients[0].acl.read[0], "kern.ostype",
	    SYSCTLCMP_MAX_PREFIX);
	for (unsigned i = 0; i < 3; i++) {
		ATF_REQUIRE_EQ(0, mac_capability_channel_create(pairs[i]));
		providers[i] = pairs[i][1];
	}
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		for (unsigned i = 0; i < 3; i++)
			close(pairs[i][0]);
		_exit(sysctlcmp_test_serve_many(providers, labels, 3, &config,
		    10000));
	}
	for (unsigned i = 0; i < 3; i++)
		close(pairs[i][1]);
	ATF_REQUIRE_EQ(0, service_session_create(pairs[0][0], &raw));
	for (unsigned i = 1; i < 3; i++)
		ATF_REQUIRE_EQ(0, sysctlcmp_client_create(pairs[i][0],
		    &clients[i]));
	/* The idle session stays open and silent throughout. */
	for (unsigned i = 0; i < 4; i++) {
		ATF_CHECK_EQ(0, get_op(clients[1], "kern.ostype"));
		ATF_CHECK_EQ(EPERM, get_op(clients[2], "kern.ostype"));
	}
	ATF_CHECK_EQ(0, interfaces_op(clients[1]));
	ATF_CHECK_EQ(EPERM, interfaces_op(clients[2]));
	/* A malformed frame from the idle client cannot stop the others. */
	options.timeout_ms = 2000;
	ATF_CHECK_EQ(-1, service_session_call(raw, &garbage, &incoming,
	    &options));
	ATF_CHECK_EQ(0, get_op(clients[1], "kern.ostype"));
	ATF_CHECK_EQ(EPERM, get_op(clients[2], "kern.ostype"));
	service_session_close(raw);
	for (unsigned i = 1; i < 3; i++)
		sysctlcmp_client_close(clients[i]);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	/* The malformed session is reported as a protocol failure. */
	ATF_CHECK_EQ(1, WEXITSTATUS(status));
}

ATF_TC(open_silent_peer_still_expires);
ATF_TC_HEAD(open_silent_peer_still_expires, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "5");
}
ATF_TC_BODY(open_silent_peer_still_expires, tc)
{
	struct sysctlcmp_config config = { 0 };
	const char *label = "idle";
	int pair[2], status;
	pid_t child;

	require_plane();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(pair[0]);
		_exit(sysctlcmp_test_serve_many(&pair[1], &label, 1, &config,
		    100));
	}
	close(pair[1]);
	/* Only requests count as activity; an open channel does not. */
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	close(pair[0]);
}

ATF_TC(admission_bounds_and_reuse);
ATF_TC_HEAD(admission_bounds_and_reuse, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(admission_bounds_and_reuse, tc)
{
	static struct session sessions[BSDSYSCTL_MAX_SESSIONS];
	struct sysctlcmp_config config = { 0 };
	int peers[BSDSYSCTL_MAX_SESSIONS], pair[2];
	char label[32];

	require_plane();
	memset(sessions, 0, sizeof(sessions));
	for (unsigned i = 0; i < BSDSYSCTL_MAX_SESSIONS; i++) {
		snprintf(label, sizeof(label), "label.%u",
		    i / BSDSYSCTL_MAX_LABEL_SESSIONS);
		ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
		peers[i] = pair[0];
		ATF_REQUIRE_EQ(0,
		    sessions_admit(sessions, nitems(sessions), pair[1], label,
			&config));
		if (i == BSDSYSCTL_MAX_LABEL_SESSIONS - 1) {
			ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
			ATF_CHECK_ERRNO(ENOSPC,
			    sessions_admit(sessions, nitems(sessions), pair[1],
				label, &config) == -1);
			ATF_CHECK_ERRNO(EBADF, fcntl(pair[1], F_GETFD) == -1);
			close(pair[0]);
		}
	}
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
	ATF_CHECK_ERRNO(ENOSPC,
	    sessions_admit(sessions, nitems(sessions), pair[1], "new.label",
		&config) == -1);
	ATF_CHECK_ERRNO(EBADF, fcntl(pair[1], F_GETFD) == -1);
	close(pair[0]);
	session_close(&sessions[0]);
	close(peers[0]);
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
	peers[0] = pair[0];
	ATF_REQUIRE_EQ(0,
	    sessions_admit(sessions, nitems(sessions), pair[1], "new.label",
		&config));
	ATF_CHECK_STREQ("new.label", sessions[0].label);
	for (unsigned i = 0; i < BSDSYSCTL_MAX_SESSIONS; i++) {
		session_close(&sessions[i]);
		close(peers[i]);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, admission_bounds_and_reuse);
	ATF_TP_ADD_TC(tp, idle_and_policy_isolation);
	ATF_TP_ADD_TC(tp, open_silent_peer_still_expires);
	return (atf_no_error());
}
