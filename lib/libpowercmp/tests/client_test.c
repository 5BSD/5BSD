/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * libpowercmp client semantics against a scripted bsd.power.v1 server over a
 * real capability channel: negotiation, terminal transport/protocol errors,
 * preserved policy errors, deadlines (including a caller's RPC budget),
 * fork ownership and legacy peers.
 */
#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.power.v1/c/bsd.h>
#include <powercmp.h>
#include <service_runtime.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum mode {
	SERVE_NORMAL,	     /* EPERM on the first Inhibit, then success */
	SERVE_FUTURE,	     /* wire version 2 */
	SERVE_SILENT_INFO,   /* never answer negotiation */
	SERVE_CLOSE_INHIBIT, /* close instead of answering Inhibit */
	SERVE_BAD_ERRNO,     /* err = 0 on Inhibit (not an errno) */
	SERVE_BAD_STATES,    /* reports bit 0 (there is no "S0") */
	SERVE_LEGACY	     /* a pre-FIDL provider */
};

struct server {
	enum mode mode;
	unsigned inhibits, operations;
};

static void
require_plane(void)
{
	int fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("capability plane unavailable: %s",
		    strerror(errno));
	close(fd);
}

static void
info(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty)
{
	struct server *server = context;
	struct bsd_power_v1_ProtocolInfo value = { POWERCMP_WIRE_VERSION };
	(void)empty;
	if (server->mode == SERVE_SILENT_INFO)
		return;
	if (server->mode == SERVE_FUTURE)
		value.wire_version++;
	assert(bsd_power_v1_Power_GetProtocolInfo_reply(connection, request,
		   &value) == 0);
}
static void
states(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty)
{
	struct server *server = context;
	struct bsd_power_v1_SleepStates value = { 1u << 3 };
	(void)empty;
	server->operations++;
	if (server->mode == SERVE_BAD_STATES)
		value.supported |= 1;
	assert(bsd_power_v1_Power_States_reply(connection, request, &value) ==
	    0);
}
static void
inhibit(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty)
{
	struct server *server = context;
	struct bsd_power_v1_Power_Inhibit_Result result = {
		.tag = bsd_power_v1_Power_Inhibit_Result_response_tag
	};
	(void)empty;
	server->operations++;
	if (server->mode == SERVE_CLOSE_INHIBIT) {
		fidl_bsd_connection_close(connection, EPIPE);
		return;
	}
	if (server->mode == SERVE_BAD_ERRNO ||
	    (server->mode == SERVE_NORMAL && server->inhibits++ == 0)) {
		result.tag = bsd_power_v1_Power_Inhibit_Result_err_tag;
		result.value.err = server->mode == SERVE_BAD_ERRNO ? 0 : EPERM;
	}
	assert(bsd_power_v1_Power_Inhibit_reply(connection, request,
		   &result) == 0);
}
static void
inhibitors(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty)
{
	struct server *server = context;
	struct bsd_power_v1_InhibitorCount value = { 7 };
	(void)empty;
	server->operations++;
	assert(bsd_power_v1_Power_Inhibitors_reply(connection, request,
		   &value) == 0);
}

static void
legacy_request(struct channel *channel, struct channel_message *message,
    void *context)
{
	struct powercmp_msg reply = { .magic = POWERCMP_MAGIC,
		.opcode = POWERCMP_OP_STATES };
	struct channel_outgoing outgoing = CHANNEL_OUTGOING_INITIALIZER(&reply,
	    sizeof(reply));
	(void)channel;
	(void)channel_send_reply(message, &outgoing);
	channel_message_free(message);
	*(bool *)context = true;
}

/* Serve in a child; the exit status is the number of operations seen. */
static pid_t
serve(enum mode mode, int *client_fd)
{
	int ends[2];
	pid_t child;

	require_plane();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(ends[0]);
		if (mode == SERVE_LEGACY) {
			struct channel_options options =
			    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
			struct channel *channel;
			bool done = false;
			assert(channel_create(ends[1], &options, &channel) == 0);
			assert(channel_set_request_handler(channel,
				   legacy_request, &done) == 0);
			while (!done && channel_wait(channel, false, 5000) > 0)
				(void)channel_dispatch(channel);
			channel_destroy(channel);
			_exit(0);
		}
		struct server server = { .mode = mode };
		struct bsd_power_v1_Power_server handlers = {
			.GetProtocolInfo = info,
			.States = states,
			.Inhibit = inhibit,
			.Inhibitors = inhibitors
		};
		struct fidl_bsd_connection *connection;
		assert(fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER,
			   &connection) == 0);
		assert(bsd_power_v1_Power_bind(connection, &handlers,
			   &server) == 0);
		while (fidl_bsd_connection_poll(connection, 10000) == 0)
			;
		fidl_bsd_connection_destroy(connection);
		_exit((int)server.operations);
	}
	close(ends[1]);
	*client_fd = ends[0];
	return (child);
}

static int
finish(pid_t child)
{
	int status;
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

static struct powercmp_client *
connect_mode(enum mode mode, pid_t *child)
{
	struct powercmp_client *client;
	int fd;
	*child = serve(mode, &fd);
	ATF_REQUIRE_EQ(0, powercmp_client_create(fd, &client));
	/* The constructor consumed the descriptor. */
	ATF_CHECK_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	return (client);
}

ATF_TC_WITHOUT_HEAD(policy_error_preserves_session);
ATF_TC_BODY(policy_error_preserves_session, tc)
{
	pid_t child;
	struct powercmp_client *client = connect_mode(SERVE_NORMAL, &child);
	uint32_t count = 0, supported = 0;
	ATF_CHECK_ERRNO(EPERM, powercmp_inhibit(client) == -1);
	ATF_CHECK_EQ(0, powercmp_inhibit(client));
	ATF_CHECK_EQ(0, powercmp_inhibitors(client, &count));
	ATF_CHECK_EQ(7, count);
	ATF_CHECK_EQ(0, powercmp_states(client, &supported));
	ATF_CHECK_EQ(1u << 3, supported);
	powercmp_client_close(client);
	ATF_CHECK_EQ(4, finish(child));
}

ATF_TC_WITHOUT_HEAD(ambiguous_acquisition_is_terminal);
ATF_TC_BODY(ambiguous_acquisition_is_terminal, tc)
{
	pid_t child;
	struct powercmp_client *client = connect_mode(SERVE_CLOSE_INHIBIT,
	    &child);
	uint32_t count = 99;
	int first;
	ATF_CHECK_EQ(-1, powercmp_inhibit(client));
	first = errno;
	ATF_CHECK(first != 0 && first != EPERM);
	/* The handle stays failed without another round trip. */
	ATF_CHECK_ERRNO(first, powercmp_inhibitors(client, &count) == -1);
	ATF_CHECK_EQ(99, count);
	powercmp_client_close(client);
	ATF_CHECK_EQ(1, finish(child));
}

ATF_TC_WITHOUT_HEAD(malformed_reply_is_terminal);
ATF_TC_BODY(malformed_reply_is_terminal, tc)
{
	pid_t child;
	struct powercmp_client *client = connect_mode(SERVE_BAD_ERRNO, &child);
	uint32_t count = 99;
	ATF_CHECK_ERRNO(EPROTO, powercmp_inhibit(client) == -1);
	ATF_CHECK_ERRNO(EPROTO, powercmp_inhibitors(client, &count) == -1);
	ATF_CHECK_EQ(99, count);
	powercmp_client_close(client);
	ATF_CHECK_EQ(1, finish(child));

	client = connect_mode(SERVE_BAD_STATES, &child);
	ATF_CHECK_ERRNO(EPROTO, powercmp_states(client, &count) == -1);
	ATF_CHECK_EQ(99, count);
	powercmp_client_close(client);
	ATF_CHECK_EQ(1, finish(child));
}

ATF_TC_WITHOUT_HEAD(future_version_rejected_before_operations);
ATF_TC_BODY(future_version_rejected_before_operations, tc)
{
	pid_t child;
	struct powercmp_client *client = connect_mode(SERVE_FUTURE, &child);
	ATF_CHECK_ERRNO(EPROTONOSUPPORT, powercmp_suspend(client, 3) == -1);
	ATF_CHECK_ERRNO(EPROTONOSUPPORT, powercmp_inhibit(client) == -1);
	powercmp_client_close(client);
	ATF_CHECK_EQ(0, finish(child));
}

ATF_TC_WITHOUT_HEAD(legacy_provider_rejected_without_operations);
ATF_TC_BODY(legacy_provider_rejected_without_operations, tc)
{
	pid_t child;
	struct powercmp_client *client = connect_mode(SERVE_LEGACY, &child);
	ATF_CHECK_EQ(-1, powercmp_suspend(client, 3));
	ATF_CHECK(errno == EPROTO || errno == EPIPE || errno == ECONNRESET);
	powercmp_client_close(client);
	ATF_CHECK_EQ(0, finish(child));
}

ATF_TC_WITHOUT_HEAD(budget_bounds_the_call);
ATF_TC_BODY(budget_bounds_the_call, tc)
{
	pid_t child;
	struct powercmp_client *client = connect_mode(SERVE_SILENT_INFO,
	    &child);
	uint64_t start = service_monotime_ms();
	uint32_t count;
	ATF_REQUIRE_EQ(0, service_budget_begin(300));
	ATF_CHECK_ERRNO(ETIMEDOUT, powercmp_inhibitors(client, &count) == -1);
	service_budget_end();
	/* The caller's budget, not the five-second default, bounded it. */
	ATF_CHECK(service_monotime_ms() - start < 3000);
	ATF_CHECK_ERRNO(ETIMEDOUT, powercmp_inhibitors(client, &count) == -1);
	powercmp_client_close(client);
	ATF_CHECK_EQ(0, finish(child));
}

ATF_TC_WITHOUT_HEAD(fork_owner_cannot_use_parent_session);
ATF_TC_BODY(fork_owner_cannot_use_parent_session, tc)
{
	pid_t child, user;
	int status;
	struct powercmp_client *client = connect_mode(SERVE_NORMAL, &child);
	user = fork();
	ATF_REQUIRE(user >= 0);
	if (user == 0) {
		int ok = powercmp_uninhibit(client) == -1 && errno == ECHILD;
		powercmp_client_close(client);
		_exit(ok ? 0 : 1);
	}
	ATF_REQUIRE_EQ(user, waitpid(user, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	powercmp_client_close(client);
	ATF_CHECK_EQ(0, finish(child));
}

ATF_TC_WITHOUT_HEAD(create_failure_keeps_fd);
ATF_TC_BODY(create_failure_keeps_fd, tc)
{
	struct powercmp_client *client = (void *)1;
	int fds[2];
	ATF_REQUIRE_EQ(0, pipe(fds));
	ATF_CHECK_EQ(-1, powercmp_client_create(fds[0], &client));
	ATF_CHECK(client == NULL);
	ATF_CHECK(fcntl(fds[0], F_GETFD) != -1);
	close(fds[0]);
	close(fds[1]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, policy_error_preserves_session);
	ATF_TP_ADD_TC(tp, ambiguous_acquisition_is_terminal);
	ATF_TP_ADD_TC(tp, malformed_reply_is_terminal);
	ATF_TP_ADD_TC(tp, future_version_rejected_before_operations);
	ATF_TP_ADD_TC(tp, legacy_provider_rejected_without_operations);
	ATF_TP_ADD_TC(tp, budget_bounds_the_call);
	ATF_TP_ADD_TC(tp, fork_owner_cannot_use_parent_session);
	ATF_TP_ADD_TC(tp, create_failure_keeps_fd);
	return (atf_no_error());
}
