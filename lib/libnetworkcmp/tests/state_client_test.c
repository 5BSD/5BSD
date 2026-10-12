/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <libservice.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <assert.h>
#include <channel.h>
#include <fcntl.h>
#include <pthread.h>

#include "../network_state.c"

/*
 * A scripted system.Network.State provider: service_open() creates a real
 * capability channel served by a bsd.network.v1 NetworkState server on its
 * own thread.  `fault` selects the reply to the next Watch.
 */
enum fault {
	FAULT_NONE,
	FAULT_SILENT,		/* never answer (client deadline) */
	FAULT_CLOSE,		/* close the session (transport error) */
	FAULT_BAD_LINK,		/* link_state 3: malformed */
	FAULT_SOURCE_ERROR,	/* source_error EIO, no interfaces */
	FAULT_DUPLICATE_NAME	/* two interfaces named em0: malformed */
};
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned created, closed, calls;
static enum fault fault;
static int error_reply;
static uint32_t last_timeout;

struct state_session {
	uint64_t epoch;
};

static void
info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct bsd_network_v1_ProtocolInfo v = { NETWORK_STATE_WIRE_VERSION };
	(void)x;
	(void)e;
	assert(bsd_network_v1_NetworkState_GetProtocolInfo_reply(c, r, &v) == 0);
}

static void
watch_method(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_network_v1_WatchRequest *q)
{
	struct state_session *session = x;
	struct bsd_network_v1_Interface interfaces[2] = {
		{ .index = 1, .mtu = 1500, .name = "em0", .name_size = 3 },
		{ .index = 2, .mtu = 1500, .name = "em0", .name_size = 3 }
	};
	struct bsd_network_v1_NetworkState_Watch_Result result = {
		.tag = bsd_network_v1_NetworkState_Watch_Result_response_tag,
		.value.response = { .epoch = session->epoch, .generation = 1,
		    .interfaces = interfaces, .interfaces_size = 1 }
	};
	enum fault selected;
	int application;

	pthread_mutex_lock(&lock);
	calls++;
	last_timeout = q->timeout_ms;
	selected = fault;
	application = error_reply;
	pthread_mutex_unlock(&lock);
	switch (selected) {
	case FAULT_SILENT:
		return;
	case FAULT_CLOSE:
		fidl_bsd_connection_close(c, ECONNRESET);
		return;
	case FAULT_BAD_LINK:
		interfaces[0].link_state = 3;
		break;
	case FAULT_SOURCE_ERROR:
		result.value.response.source_error = EIO;
		result.value.response.interfaces_size = 0;
		break;
	case FAULT_DUPLICATE_NAME:
		result.value.response.interfaces_size = 2;
		break;
	default:
		break;
	}
	if (application != 0) {
		result.tag = bsd_network_v1_NetworkState_Watch_Result_err_tag;
		result.value.err = (uint32_t)application;
	}
	(void)bsd_network_v1_NetworkState_Watch_reply(c, r, &result);
}

static void *
serve(void *argument)
{
	struct bsd_network_v1_NetworkState_server handlers = {
		.GetProtocolInfo = info,
		.Watch = watch_method
	};
	struct fidl_bsd_connection *connection;
	struct state_session session;
	int fd = (int)(intptr_t)argument;

	pthread_mutex_lock(&lock);
	session.epoch = ++created;
	pthread_mutex_unlock(&lock);
	assert(fidl_bsd_connection_create(fd, FIDL_BSD_SERVER,
	    &connection) == 0);
	assert(bsd_network_v1_NetworkState_bind(connection, &handlers,
	    &session) == 0);
	while (fidl_bsd_connection_poll(connection, 30000) == 0)
		;
	fidl_bsd_connection_destroy(connection);
	pthread_mutex_lock(&lock);
	closed++;
	pthread_mutex_unlock(&lock);
	return (NULL);
}

int service_harden_fd(int, unsigned);

int
service_harden_fd(int fd, unsigned flags)
{
	ATF_CHECK_EQ(0, flags);
	return (fd < 0 ? (errno = EBADF, -1) : 0);
}

int
service_open(const char *name, int *fd)
{
	pthread_t thread;
	int ends[2];

	ATF_REQUIRE_STREQ(NETWORK_STATE_INTERFACE, name);
	if (mac_capability_channel_create(ends) != 0)
		return (-1);
	assert(pthread_create(&thread, NULL, serve,
	    (void *)(intptr_t)ends[1]) == 0);
	assert(pthread_detach(thread) == 0);
	*fd = ends[0];
	return (0);
}

/* Sessions the provider has seen end (waits briefly for teardown). */
static unsigned
closed_sessions(unsigned expected)
{
	unsigned result = 0;

	for (unsigned i = 0; i < 200; i++) {
		pthread_mutex_lock(&lock);
		result = closed;
		pthread_mutex_unlock(&lock);
		if (result >= expected)
			break;
		usleep(10000);
	}
	return (result);
}

static void
set_fault(enum fault value, int application)
{
	pthread_mutex_lock(&lock);
	fault = value;
	error_reply = application;
	pthread_mutex_unlock(&lock);
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

ATF_TC(reconnect_errors_and_deadlines);
ATF_TC_HEAD(reconnect_errors_and_deadlines, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(reconnect_errors_and_deadlines, tc)
{
	struct network_state_client *client;
	struct network_state_snapshot state, before;
	uint64_t epoch;

	require_plane();
	ATF_REQUIRE_EQ(0, network_state_open(&client));
	ATF_REQUIRE_EQ(0, network_state_watch(client, &state, 0));
	ATF_CHECK_EQ(0, last_timeout);
	ATF_CHECK_STREQ("em0", state.interfaces[0].name);
	epoch = state.epoch;
	before = state;
	/* A provider timeout (EAGAIN) keeps the stream. */
	set_fault(FAULT_NONE, EAGAIN);
	ATF_CHECK_ERRNO(EAGAIN, network_state_watch(client, &state, 1) == -1);
	ATF_CHECK_EQ(0, closed_sessions(0));
	ATF_CHECK_EQ(0, memcmp(&before, &state, sizeof(state)));
	/* Another application error resets it. */
	set_fault(FAULT_NONE, EBUSY);
	ATF_CHECK_ERRNO(EBUSY, network_state_watch(client, &state, 0) == -1);
	ATF_CHECK_EQ(1, closed_sessions(1));
	/* So does a transport error; the next watch reconnects. */
	set_fault(FAULT_NONE, 0);
	ATF_REQUIRE_EQ(0, network_state_watch(client, &state, UINT32_MAX - 2));
	ATF_CHECK_EQ(UINT32_MAX - 2, last_timeout);
	ATF_CHECK(state.epoch != epoch);
	set_fault(FAULT_CLOSE, 0);
	ATF_CHECK_EQ(-1, network_state_watch(client, &state, 0));
	ATF_CHECK_EQ(2, closed_sessions(2));
	/* A malformed snapshot resets it and leaves the output untouched. */
	set_fault(FAULT_NONE, 0);
	ATF_REQUIRE_EQ(0, network_state_watch(client, &state, 0));
	before = state;
	static const enum fault malformed[] = {
		FAULT_BAD_LINK, FAULT_DUPLICATE_NAME
	};
	for (size_t i = 0; i < nitems(malformed); i++) {
		set_fault(malformed[i], 0);
		ATF_CHECK_ERRNO(EPROTO,
		    network_state_watch(client, &state, 0) == -1);
		ATF_CHECK_EQ(0, memcmp(&before, &state, sizeof(state)));
	}
	/* The client allows the provider 5 s beyond the watch timeout. */
	set_fault(FAULT_SILENT, 0);
	ATF_CHECK_ERRNO(ETIMEDOUT,
	    network_state_watch(client, &state, 1) == -1);
	set_fault(FAULT_SOURCE_ERROR, 0);
	ATF_REQUIRE_EQ(0,
	    network_state_watch(client, &state,
		NETWORK_STATE_TIMEOUT_INFINITE));
	ATF_CHECK_EQ(NETWORK_STATE_TIMEOUT_INFINITE, last_timeout);
	ATF_CHECK_EQ(EIO, state.source_error);
	ATF_CHECK_EQ(0, state.count);
	set_fault(FAULT_NONE, 0);
	network_state_close(client);
}

ATF_TC(wire_and_fork);
ATF_TC_HEAD(wire_and_fork, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wire_and_fork, tc)
{
	struct network_state_client *client;
	struct network_state_snapshot state;
	struct network_state_request request = {
		.header = { .magic = NETWORK_STATE_MAGIC,
		    .version = 1,
		    .opcode = 1 }
	};
	struct network_state_reply reply = {
		.header = { .magic = NETWORK_STATE_MAGIC,
		    .version = 1,
		    .opcode = 1 },
		.state = { .epoch = 1, .generation = 1 }
	};
	pid_t child;
	int status;

	/* The retained pre-FIDL record validators. */
	ATF_CHECK_EQ(0,
	    network_state_validate_request(&request, sizeof(request)));
	request.reserved = 1;
	ATF_CHECK_ERRNO(EPROTO,
	    network_state_validate_request(&request, sizeof(request)) == -1);
	ATF_CHECK_EQ(0,
	    network_state_validate_reply(&reply, NETWORK_STATE_REPLY_SIZE(0)));
	reply.state.source_error = -1;
	ATF_CHECK_ERRNO(EPROTO,
	    network_state_validate_reply(&reply, NETWORK_STATE_REPLY_SIZE(0)) ==
		-1);
	reply.state.source_error = EIO;
	reply.state.count = 1;
	ATF_CHECK_ERRNO(EPROTO,
	    network_state_validate_reply(&reply, NETWORK_STATE_REPLY_SIZE(1)) ==
		-1);
	require_plane();
	ATF_REQUIRE_EQ(0, network_state_open(&client));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0)
		_exit(network_state_watch(client, &state, 0) == -1 &&
			    errno == ECHILD ?
			0 :
			1);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	network_state_close(client);
}
ATF_TC_WITHOUT_HEAD(interface_wire_validation);
ATF_TC_BODY(interface_wire_validation, tc)
{
	struct network_state_reply good = {
		.header = { .magic = NETWORK_STATE_MAGIC,
		    .version = 1,
		    .opcode = 1 },
		.state = { .epoch = 1,
		    .generation = 1,
		    .count = 2,
		    .interfaces = { { .index = 1, .name = "em0" },
			{ .index = 2, .name = "lo0" } } }
	};
	struct network_state_reply bad;
	size_t length = NETWORK_STATE_REPLY_SIZE(2);

	ATF_REQUIRE_EQ(0, network_state_validate_reply(&good, length));
	for (unsigned variant = 0; variant < 9; variant++) {
		bad = good;
		switch (variant) {
		case 0:
			bad.state.interfaces[1].index = 1;
			break;
		case 1:
			bad.state.interfaces[0].index = 0;
			break;
		case 2:
			memcpy(bad.state.interfaces[1].name, "em0", 4);
			break;
		case 3:
			bad.state.interfaces[0].name[4] = 'x';
			break;
		case 4:
			memset(bad.state.interfaces[0].name, 'x', 16);
			break;
		case 5:
			bad.state.interfaces[0].reserved[0] = 1;
			break;
		case 6:
			bad.state.interfaces[0].link_state = 3;
			break;
		case 7:
			bad.state.count = NETWORK_STATE_MAX_INTERFACES + 1;
			break;
		case 8:
			bad.state.epoch = 0;
			break;
		}
		ATF_CHECK_ERRNO(EPROTO,
		    network_state_validate_reply(&bad, length) == -1);
	}
	ATF_CHECK_ERRNO(EPROTO,
	    network_state_validate_reply(&good, length - 1) == -1);
	ATF_CHECK_ERRNO(EPROTO,
	    network_state_validate_reply(&good, length + 1) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, reconnect_errors_and_deadlines);
	ATF_TP_ADD_TC(tp, wire_and_fork);
	ATF_TP_ADD_TC(tp, interface_wire_validation);
	return (atf_no_error());
}
