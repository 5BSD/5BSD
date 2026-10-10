/* SPDX-License-Identifier: BSD-2-Clause */
/* The actual provider and C client over kernel channels; gate writes are
 * mocked. */
#include <sys/capsicum.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <assert.h>
#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.time.v1/c/bsd.h>
#include <libservice.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "BSDTime_test.h"
#include "config.h"
#include "timecmp.h"
#define TEST_LABEL "org.test.bsdtime.client"
#define TEST_TOKEN 123

int __wrap_service_system_settime(int, const struct timespec *);
int __wrap_service_system_adjtime(int, const struct timeval *,
    struct timeval *);
int
__wrap_service_system_settime(int token, const struct timespec *value)
{
	if (token < 0)
		return (errno = EINVAL, -1);
	assert(token == TEST_TOKEN);
	assert(value->tv_sec == 1893456000 && value->tv_nsec == 123456789);
	return (0);
}
int
__wrap_service_system_adjtime(int token, const struct timeval *value,
    struct timeval *old)
{
	if (token < 0)
		return (errno = EINVAL, -1);
	assert(token == TEST_TOKEN);
	assert(value->tv_sec == -2 && value->tv_usec == -345678);
	*old = (struct timeval) { -1, -123456 };
	return (0);
}
struct fixture {
	int fd;
	pid_t child;
	struct timecmp_client *client;
};
static void
fake_info(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty)
{
	(void)empty;
	if (*(int *)context == 2)
		return; /* Test the client's finite deadline. */
	struct bsd_time_v1_ProtocolInfo info = { TIMECMP_WIRE_VERSION +
		(*(int *)context == 1) };
	assert(bsd_time_v1_Time_GetProtocolInfo_reply(connection, request,
		   &info) == 0);
}
static void
fake_get(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty)
{
	(void)empty;
	struct bsd_time_v1_Time_Get_Result result = { 0 };
	if (*(int *)context == 3) {
		result.tag = bsd_time_v1_Time_Get_Result_response_tag;
		result.value.response.nanoseconds = 1000000000;
	} else {
		result.tag = bsd_time_v1_Time_Get_Result_err_tag;
		result.value.err = 0; /* Zero is not an application errno. */
	}
	assert(bsd_time_v1_Time_Get_reply(connection, request, &result) == 0);
}
static void
fake_adjust(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_time_v1_Delta *value)
{
	(void)context;
	(void)value;
	struct bsd_time_v1_Time_Adjust_Result result = {
		.tag = bsd_time_v1_Time_Adjust_Result_response_tag,
		.value.response.microseconds = 1000000
	};
	assert(
	    bsd_time_v1_Time_Adjust_reply(connection, request, &result) == 0);
}
static void
legacy_request(struct channel *channel, struct channel_message *message,
    void *context)
{
	(void)channel;
	uint64_t ordinal;
	assert(channel_message_length(message) == 16);
	memcpy(&ordinal, (const char *)channel_message_data(message) + 8,
	    sizeof(ordinal));
	assert(ordinal == UINT64_C(0x493b59c6165a6b6c));
	struct timecmp_msg reply = { .magic = TIMECMP_MAGIC,
		.opcode = TIMECMP_OP_GET,
		.status = -EPROTO };
	struct channel_outgoing outgoing = CHANNEL_OUTGOING_INITIALIZER(&reply,
	    sizeof(reply));
	assert(channel_send_reply(message, &outgoing) == 0);
	channel_message_free(message);
	*(bool *)context = true;
}
static void
fixture_create(struct fixture *f, int policy, bool token, int fake)
{
	int ends[2];
	struct timecmp_config config;
	timecmp_config_defaults(&config);
	if (policy) {
		config.nclients = 1;
		strlcpy(config.clients[0].label,
		    policy == 1 ? TEST_LABEL : "org.other.client",
		    sizeof(config.clients[0].label));
		config.clients[0].may_set = true;
	}
	*f = (struct fixture) { .fd = -1 };
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	f->child = fork();
	ATF_REQUIRE(f->child >= 0);
	if (!f->child) {
		close(ends[0]);
		assert(cap_enter() == 0);
		if (!fake) {
			bsdtime_test_set_token(token ? TEST_TOKEN : -1);
			_exit(bsdtime_test_serve_session(ends[1], TEST_LABEL,
			    &config));
		}
		if (fake == 6) {
			struct channel *channel;
			struct channel_options options =
			    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
			bool done = false;
			assert(
			    channel_create(ends[1], &options, &channel) == 0);
			assert(channel_set_request_handler(channel,
				   legacy_request, &done) == 0);
			while (!done) {
				assert(channel_wait(channel, false, 1000) >= 0);
				assert(channel_dispatch(channel) >= 0);
			}
			channel_destroy(channel);
			_exit(0);
		}
		struct fidl_bsd_connection *connection;
		struct bsd_time_v1_Time_server handlers = {
			.GetProtocolInfo = fake_info,
			.Get = fake_get,
			.Adjust = fake_adjust
		};
		assert(fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER,
			   &connection) == 0);
		assert(
		    bsd_time_v1_Time_bind(connection, &handlers, &fake) == 0);
		while (!fidl_bsd_connection_poll(connection, 1000)) {
		}
		fidl_bsd_connection_destroy(connection);
		_exit(0);
	}
	close(ends[1]);
	f->fd = ends[0];
}
static void
connect_client(struct fixture *f)
{
	ATF_REQUIRE_EQ(0, timecmp_client_create(f->fd, &f->client));
	f->fd = -1;
}
static void
fixture_destroy(struct fixture *f)
{
	int status;
	if (f->client)
		timecmp_client_close(f->client);
	if (f->fd >= 0)
		close(f->fd);
	ATF_REQUIRE_EQ(f->child, waitpid(f->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
ATF_TC_WITHOUT_HEAD(get_reads_clock);
ATF_TC_BODY(get_reads_clock, tc)
{
	struct fixture f;
	struct timespec before, now, after;
	fixture_create(&f, 0, false, 0);
	connect_client(&f);
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_REALTIME, &before));
	ATF_REQUIRE_EQ(0, timecmp_get(f.client, &now));
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_REALTIME, &after));
	ATF_CHECK(now.tv_sec >= before.tv_sec && now.tv_sec <= after.tv_sec);
	ATF_CHECK(now.tv_nsec >= 0 && now.tv_nsec < 1000000000);
	ATF_REQUIRE_EQ(0, timecmp_get(f.client, &now));
	fixture_destroy(&f);
}
static void
denied(int policy)
{
	struct fixture f;
	struct timespec time = { 1893456000, 123456789 };
	struct timeval delta = { -2, -345678 };
	fixture_create(&f, policy, true, 0);
	connect_client(&f);
	ATF_REQUIRE_ERRNO(EPERM, timecmp_set(f.client, &time) == -1);
	ATF_REQUIRE_ERRNO(EPERM, timecmp_adjust(f.client, &delta, NULL) == -1);
	ATF_REQUIRE_EQ(0, timecmp_get(f.client, &time));
	fixture_destroy(&f);
}
ATF_TC_WITHOUT_HEAD(default_denies_writes);
ATF_TC_BODY(default_denies_writes, tc)
{
	denied(0);
}
ATF_TC_WITHOUT_HEAD(named_policy_does_not_grant_other_labels);
ATF_TC_BODY(named_policy_does_not_grant_other_labels, tc)
{
	denied(2);
}
ATF_TC_WITHOUT_HEAD(allowed_writes_preserve_signed_delta);
ATF_TC_BODY(allowed_writes_preserve_signed_delta, tc)
{
	struct fixture f;
	struct timespec time = { 1893456000, 123456789 };
	struct timeval delta = { -2, -345678 }, old = { 0 };
	fixture_create(&f, 1, true, 0);
	connect_client(&f);
	ATF_REQUIRE_EQ(0, timecmp_set(f.client, &time));
	ATF_REQUIRE_EQ(0, timecmp_adjust(f.client, &delta, &old));
	ATF_CHECK_EQ(-1, old.tv_sec);
	ATF_CHECK_EQ(-123456, old.tv_usec);
	fixture_destroy(&f);
}
ATF_TC_WITHOUT_HEAD(allowed_without_token_reaches_gate);
ATF_TC_BODY(allowed_without_token_reaches_gate, tc)
{
	struct fixture f;
	struct timespec time = { 1893456000, 123456789 };
	struct timeval delta = { -2, -345678 };
	fixture_create(&f, 1, false, 0);
	connect_client(&f);
	ATF_REQUIRE_ERRNO(EINVAL, timecmp_set(f.client, &time) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, timecmp_adjust(f.client, &delta, NULL) == -1);
	fixture_destroy(&f);
}
ATF_TC_WITHOUT_HEAD(client_value_validation);
ATF_TC_BODY(client_value_validation, tc)
{
	struct fixture f;
	struct timespec time = { 0, -1 };
	struct timeval delta = { 0, 1000000 };
	fixture_create(&f, 1, true, 0);
	connect_client(&f);
	ATF_REQUIRE_ERRNO(EINVAL, timecmp_set(f.client, &time) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, timecmp_adjust(f.client, &delta, NULL) == -1);
	ATF_REQUIRE_EQ(0, timecmp_get(f.client, &time));
	fixture_destroy(&f);
}
struct response {
	bool done;
	int error;
};
static void
info_response(void *p, int error, struct bsd_time_v1_ProtocolInfo *v)
{
	struct response *r = p;
	r->done = true;
	r->error = error;
	ATF_REQUIRE(v && v->wire_version == TIMECMP_WIRE_VERSION);
}
static void
set_response(void *p, int error, struct bsd_time_v1_Time_Set_Result *v)
{
	struct response *r = p;
	r->done = true;
	ATF_REQUIRE_EQ(0, error);
	ATF_REQUIRE(v && v->tag == bsd_time_v1_Time_Set_Result_err_tag);
	r->error = v->value.err;
}
static void
adjust_response(void *p, int error, struct bsd_time_v1_Time_Adjust_Result *v)
{
	struct response *r = p;
	r->done = true;
	ATF_REQUIRE_EQ(0, error);
	ATF_REQUIRE(v && v->tag == bsd_time_v1_Time_Adjust_Result_err_tag);
	r->error = v->value.err;
}
static void
pump(struct fidl_bsd_connection *c, struct response *r)
{
	for (unsigned i = 0; !r->done && i < 500; ++i)
		ATF_REQUIRE_EQ(0, fidl_bsd_connection_poll(c, 10));
	ATF_REQUIRE(r->done);
}
static void
server_bad_values(int policy, int expected)
{
	struct fixture f;
	struct fidl_bsd_connection *c;
	uint32_t tx;
	struct response r = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	fixture_create(&f, policy, true, 0);
	ATF_REQUIRE_EQ(0,
	    fidl_bsd_connection_create(f.fd, FIDL_BSD_CLIENT, &c));
	f.fd = -1;
	ATF_REQUIRE_EQ(0,
	    bsd_time_v1_Time_GetProtocolInfo(c, &empty, info_response, &r,
		&tx));
	pump(c, &r);
	struct bsd_time_v1_Timestamp time = { 0, -1 };
	r = (struct response) { 0 };
	ATF_REQUIRE_EQ(0,
	    bsd_time_v1_Time_Set(c, &time, set_response, &r, &tx));
	pump(c, &r);
	ATF_REQUIRE_EQ(expected, r.error);
	struct bsd_time_v1_Delta delta = { 0, INT32_MAX };
	r = (struct response) { 0 };
	ATF_REQUIRE_EQ(0,
	    bsd_time_v1_Time_Adjust(c, &delta, adjust_response, &r, &tx));
	pump(c, &r);
	ATF_REQUIRE_EQ(expected, r.error);
	fidl_bsd_connection_destroy(c);
	fixture_destroy(&f);
}
ATF_TC_WITHOUT_HEAD(server_value_validation);
ATF_TC_BODY(server_value_validation, tc)
{
	/* Bypass client range checks: authorization must win over validation.
	 */
	server_bad_values(0, EPERM);
	server_bad_values(2, EPERM);
	server_bad_values(1, EINVAL);
}
// Independent FIDL v2 wire header. Constants pin the v1 protocol ordinals.
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
_Static_assert(sizeof(struct wire_header) == 16, "FIDL header");
static void
reject_frame(int mode)
{
	struct fixture f;
	struct service_session *session;
	struct wire_header wire = { 1, { 2, 0, 0 }, 1,
		UINT64_C(0x493b59c6165a6b6c) };
	struct timecmp_msg legacy = { .magic = TIMECMP_MAGIC,
		.opcode = TIMECMP_OP_GET };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing = { .size = sizeof(outgoing),
		.data = &wire,
		.length = sizeof(wire) };
	uint8_t bytes[128];
	int fds[2] = { -1, -1 };
	struct service_reply incoming = { .size = sizeof(incoming),
		.data = bytes,
		.capacity = sizeof(bytes) };
	if (mode == 0)
		wire.ordinal = 123; // Unknown strict method.
	if (mode == 1)
		outgoing.length = 8;
	if (mode == 2) {
		outgoing.data = &legacy;
		outgoing.length = sizeof(legacy);
	}
	if (mode == 3)
		wire.ordinal = UINT64_C(
		    0x1bdb7c2879c591c7); // SET without body.
	fixture_create(&f, 1, true, 0);
	if (mode == 4) {
		ATF_REQUIRE_EQ(0, pipe(fds));
		outgoing.fds = &fds[1];
		outgoing.nfds = 1;
	}
	ATF_REQUIRE_EQ(0, service_session_create(f.fd, &session));
	f.fd = -1;
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(-1,
	    service_session_call(session, &outgoing, &incoming, &options));
	ATF_REQUIRE(errno != ETIMEDOUT);
	service_session_close(session);
	fixture_destroy(&f);
	if (mode == 4) {
		close(fds[1]);
		char byte;
		ATF_REQUIRE(fcntl(fds[0], F_SETFL, O_NONBLOCK) != -1);
		ATF_REQUIRE_EQ(0, read(fds[0], &byte, 1));
		close(fds[0]);
	}
}
ATF_TC_WITHOUT_HEAD(unknown_method_rejected);
ATF_TC_BODY(unknown_method_rejected, tc)
{
	reject_frame(0);
}
ATF_TC_WITHOUT_HEAD(short_frame_rejected);
ATF_TC_BODY(short_frame_rejected, tc)
{
	reject_frame(1);
}
ATF_TC_WITHOUT_HEAD(legacy_wire_rejected);
ATF_TC_BODY(legacy_wire_rejected, tc)
{
	reject_frame(2);
}
ATF_TC_WITHOUT_HEAD(missing_body_rejected);
ATF_TC_BODY(missing_body_rejected, tc)
{
	reject_frame(3);
}
ATF_TC_WITHOUT_HEAD(attached_descriptor_closed);
ATF_TC_BODY(attached_descriptor_closed, tc)
{
	reject_frame(4);
}
ATF_TC_WITHOUT_HEAD(future_version_rejected);
ATF_TC_BODY(future_version_rejected, tc)
{
	struct fixture f;
	struct timespec time;
	fixture_create(&f, 0, false, 1);
	connect_client(&f);
	ATF_REQUIRE_ERRNO(EPROTONOSUPPORT, timecmp_get(f.client, &time) == -1);
	ATF_REQUIRE_ERRNO(EPROTONOSUPPORT, timecmp_get(f.client, &time) == -1);
	fixture_destroy(&f);
}
ATF_TC_WITHOUT_HEAD(timeout_closes_client);
ATF_TC_BODY(timeout_closes_client, tc)
{
	struct fixture f;
	struct timespec time;
	fixture_create(&f, 0, false, 2);
	connect_client(&f);
	ATF_REQUIRE_ERRNO(ETIMEDOUT, timecmp_get(f.client, &time) == -1);
	ATF_REQUIRE_ERRNO(ETIMEDOUT, timecmp_get(f.client, &time) == -1);
	fixture_destroy(&f);
}
ATF_TC_WITHOUT_HEAD(forked_client_rejected);
ATF_TC_BODY(forked_client_rejected, tc)
{
	struct fixture f;
	struct timespec time;
	int status;
	fixture_create(&f, 0, false, 0);
	connect_client(&f);
	ATF_REQUIRE_EQ(0, timecmp_get(f.client, &time));
	pid_t child = fork();
	ATF_REQUIRE(child >= 0);
	if (!child) {
		bool ok = timecmp_get(f.client, &time) == -1 && errno == ECHILD;
		timecmp_client_close(f.client);
		_exit(ok ? 0 : 1);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE_EQ(0, status);
	ATF_REQUIRE_EQ(0, timecmp_get(f.client, &time));
	fixture_destroy(&f);
}
ATF_TC_WITHOUT_HEAD(create_failure_keeps_fd);
ATF_TC_BODY(create_failure_keeps_fd, tc)
{
	int fds[2];
	struct timecmp_client *client = NULL;
	ATF_REQUIRE_EQ(0, pipe(fds));
	ATF_REQUIRE_EQ(-1, timecmp_client_create(fds[0], &client));
	ATF_REQUIRE(client == NULL && fcntl(fds[0], F_GETFD) >= 0);
	close(fds[0]);
	close(fds[1]);
}
ATF_TC_WITHOUT_HEAD(malformed_reply_closes_client);
ATF_TC_BODY(malformed_reply_closes_client, tc)
{
	for (int mode = 3; mode <= 4; ++mode) {
		struct fixture f;
		struct timespec time = { 11, 22 };
		fixture_create(&f, 0, false, mode);
		connect_client(&f);
		ATF_REQUIRE_ERRNO(EPROTO, timecmp_get(f.client, &time) == -1);
		ATF_CHECK_EQ(11, time.tv_sec);
		ATF_CHECK_EQ(22, time.tv_nsec);
		ATF_REQUIRE_ERRNO(EPROTO, timecmp_get(f.client, &time) == -1);
		fixture_destroy(&f);
	}
}
ATF_TC_WITHOUT_HEAD(malformed_old_delta_even_when_discarded);
ATF_TC_BODY(malformed_old_delta_even_when_discarded, tc)
{
	struct fixture f;
	struct timeval delta = { 0 };
	struct timespec time;
	fixture_create(&f, 0, false, 5);
	connect_client(&f);
	ATF_REQUIRE_ERRNO(EPROTO, timecmp_adjust(f.client, &delta, NULL) == -1);
	ATF_REQUIRE_ERRNO(EPROTO, timecmp_get(f.client, &time) == -1);
	fixture_destroy(&f);
}
ATF_TC_WITHOUT_HEAD(new_client_rejects_legacy_peer_without_writes);
ATF_TC_BODY(new_client_rejects_legacy_peer_without_writes, tc)
{
	struct fixture f;
	struct timespec time = { 1893456000, 123456789 };
	fixture_create(&f, 0, false, 6);
	connect_client(&f);
	ATF_REQUIRE_EQ(-1, timecmp_set(f.client, &time));
	ATF_REQUIRE(errno == EPROTO || errno == EPIPE || errno == ECONNRESET);
	fixture_destroy(&f);
}
static unsigned
open_fd_count(void)
{
	unsigned count = 0;
	for (int fd = 0; fd < 256; ++fd)
		if (fcntl(fd, F_GETFD) != -1)
			count++;
	return (count);
}
ATF_TC_WITHOUT_HEAD(reactor_capacity_and_expiry);
ATF_TC_BODY(reactor_capacity_and_expiry, tc)
{
	struct bsdtime_server *server;
	struct timecmp_config config;
	int clients[32], ends[2];
	unsigned before = open_fd_count();
	timecmp_config_defaults(&config);
	ATF_REQUIRE_EQ(0, bsdtime_test_server_create(100, &server));
	for (unsigned i = 0; i < 32; ++i) {
		ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
		clients[i] = ends[0];
		char label[64];
		snprintf(label, sizeof(label), "org.capacity.%u", i);
		ATF_REQUIRE_EQ(0,
		    bsdtime_test_server_add(server, ends[1], label, &config));
	}
	ATF_REQUIRE_EQ(32, bsdtime_test_server_count(server));
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	ATF_REQUIRE_EQ(ENOBUFS,
	    bsdtime_test_server_add(server, ends[1], TEST_LABEL, &config));
	ATF_REQUIRE_ERRNO(EBADF, fcntl(ends[1], F_GETFD) == -1);
	close(ends[0]);
	/* Expiry releases quota without requiring a client to send or close. */
	for (unsigned i = 0; i < 20 && bsdtime_test_server_count(server); ++i)
		ATF_REQUIRE_EQ(0, bsdtime_test_server_step(server, 100));
	ATF_REQUIRE_EQ(0, bsdtime_test_server_count(server));
	for (unsigned i = 0; i < 32; ++i)
		close(clients[i]);
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	ATF_REQUIRE_EQ(0,
	    bsdtime_test_server_add(server, ends[1], TEST_LABEL, &config));
	close(ends[0]);
	bsdtime_test_server_destroy(server);
	ATF_REQUIRE_EQ(before, open_fd_count());
}
ATF_TC_WITHOUT_HEAD(reactor_reuses_slots_without_fd_growth);
ATF_TC_BODY(reactor_reuses_slots_without_fd_growth, tc)
{
	struct bsdtime_server *server;
	struct timecmp_config config;
	struct rlimit limit = { 256, 256 };
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &limit));
	unsigned before = open_fd_count();
	timecmp_config_defaults(&config);
	ATF_REQUIRE_EQ(0, bsdtime_test_server_create(1000, &server));
	for (unsigned i = 0; i < 512; ++i) {
		int ends[2];
		ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
		ATF_REQUIRE_EQ(0,
		    bsdtime_test_server_add(server, ends[1], TEST_LABEL,
			&config));
		close(ends[0]);
		for (unsigned n = 0;
		    n < 10 && bsdtime_test_server_count(server); ++n)
			ATF_REQUIRE_EQ(0, bsdtime_test_server_step(server, 10));
		ATF_REQUIRE_EQ(0, bsdtime_test_server_count(server));
	}
	bsdtime_test_server_destroy(server);
	ATF_REQUIRE_EQ(before, open_fd_count());
}
static pid_t
multi_server(int clients[3])
{
	int ends[3][2];
	for (unsigned i = 0; i < 3; ++i)
		ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends[i]));
	pid_t child = fork();
	ATF_REQUIRE(child >= 0);
	if (!child) {
		struct bsdtime_server *server;
		struct timecmp_config config;
		char label[64];
		assert(cap_enter() == 0);
		timecmp_config_defaults(&config);
		config.nclients = 1;
		strlcpy(config.clients[0].label, TEST_LABEL,
		    sizeof(config.clients[0].label));
		config.clients[0].may_set = true;
		bsdtime_test_set_token(TEST_TOKEN);
		assert(bsdtime_test_server_create(30000, &server) == 0);
		for (unsigned i = 0; i < 3; ++i) {
			close(ends[i][0]);
			strlcpy(label, i == 1 ? TEST_LABEL : "org.denied",
			    sizeof(label));
			assert(bsdtime_test_server_add(server, ends[i][1],
				   label, &config) == 0);
		}
		/* The accept loop reuses its identity buffer; sessions must
		 * copy it. */
		memset(label, 0xa5, sizeof(label));
		while (bsdtime_test_server_count(server))
			assert(bsdtime_test_server_step(server, 1000) == 0);
		bsdtime_test_server_destroy(server);
		_exit(0);
	}
	for (unsigned i = 0; i < 3; ++i) {
		close(ends[i][1]);
		clients[i] = ends[i][0];
	}
	return (child);
}
static void
join_server(pid_t child)
{
	int status;
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
ATF_TC_WITHOUT_HEAD(multiple_clients_idle_and_policy_isolation);
ATF_TC_BODY(multiple_clients_idle_and_policy_isolation, tc)
{
	int clients[3];
	pid_t child = multi_server(clients);
	struct timecmp_client *allowed, *denied;
	struct timespec time = { 1893456000, 123456789 };
	ATF_REQUIRE_EQ(0, timecmp_client_create(clients[1], &allowed));
	ATF_REQUIRE_EQ(0, timecmp_client_create(clients[2], &denied));
	/* Client zero sends nothing; it must not hold the token-holder hostage.
	 */
	ATF_REQUIRE_EQ(0, timecmp_set(allowed, &time));
	ATF_REQUIRE_ERRNO(EPERM, timecmp_set(denied, &time) == -1);
	for (unsigned i = 0; i < 64; ++i) {
		ATF_REQUIRE_EQ(0, timecmp_get(allowed, &time));
		ATF_REQUIRE_EQ(0, timecmp_get(denied, &time));
	}
	timecmp_client_close(allowed);
	timecmp_client_close(denied);
	close(clients[0]);
	join_server(child);
}
static void
ignore_reply(struct channel_request *request, struct channel_message *message,
    int error, void *context)
{
	(void)context;
	(void)error;
	channel_message_free(message);
	channel_request_release(request);
}
ATF_TC_WITHOUT_HEAD(nonreading_peer_does_not_block_others);
ATF_TC_BODY(nonreading_peer_does_not_block_others, tc)
{
	int clients[3];
	pid_t child = multi_server(clients);
	struct fidl_bsd_connection *negotiation;
	struct channel *flood;
	struct timecmp_client *client;
	struct response response = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t txid;
	struct timespec time;
	ATF_REQUIRE_EQ(0,
	    fidl_bsd_connection_create(clients[0], FIDL_BSD_CLIENT,
		&negotiation));
	ATF_REQUIRE_EQ(0,
	    bsd_time_v1_Time_GetProtocolInfo(negotiation, &empty, info_response,
		&response, &txid));
	pump(negotiation, &response);
	/* Keep the negotiated endpoint but use send/flush without reading
	 * replies. This forces real backpressure past both kernel and userspace
	 * queues. */
	int fd = fcntl(fidl_bsd_connection_fd(negotiation), F_DUPFD_CLOEXEC, 0);
	ATF_REQUIRE(fd >= 0);
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	options.max_pending_requests = 2048;
	options.max_queued_messages = 2048;
	ATF_REQUIRE_EQ(0, channel_create(fd, &options, &flood));
	fidl_bsd_connection_destroy(negotiation);
	ATF_REQUIRE_EQ(0, timecmp_client_create(clients[1], &client));
	struct wire_header wire = { 1, { 2, 0, 0 }, 1,
		UINT64_C(0x3653d79f9212efb7) };
	struct channel_outgoing out = CHANNEL_OUTGOING_INITIALIZER(&wire,
	    sizeof(wire));
	unsigned sent = 0;
	for (; sent < 2048; ++sent) {
		struct channel_request *request;
		wire.txid = sent + 1;
		if (channel_send_request(flood, &out, ignore_reply, NULL,
			&request))
			break;
	}
	ATF_REQUIRE(sent > 256);
	/* Never dispatch/read this endpoint. Flush writes until the server
	 * closes it for exhausting its reply queue, while another client keeps
	 * working. */
	for (unsigned i = 0; i < 128 && !channel_error(flood); ++i) {
		ATF_REQUIRE_EQ(0, timecmp_get(client, &time));
		(void)channel_flush(flood);
	}
	ATF_REQUIRE(channel_error(flood) != 0);
	for (unsigned i = 0; i < 64; ++i)
		ATF_REQUIRE_EQ(0, timecmp_get(client, &time));
	channel_destroy(flood);
	timecmp_client_close(client);
	close(clients[2]);
	join_server(child);
}

ATF_TC_WITHOUT_HEAD(reactor_label_quota_isolated);
ATF_TC_BODY(reactor_label_quota_isolated, tc)
{
	struct bsdtime_server *server;
	struct timecmp_config config;
	int clients[9], ends[2];
	unsigned before = open_fd_count();
	timecmp_config_defaults(&config);
	ATF_REQUIRE_EQ(0, bsdtime_test_server_create(30000, &server));
	for (unsigned i = 0; i < 8; ++i) {
		ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
		clients[i] = ends[0];
		ATF_REQUIRE_EQ(0,
		    bsdtime_test_server_add(server, ends[1], TEST_LABEL,
			&config));
	}
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	ATF_REQUIRE_EQ(ENOBUFS,
	    bsdtime_test_server_add(server, ends[1], TEST_LABEL, &config));
	ATF_REQUIRE_ERRNO(EBADF, fcntl(ends[1], F_GETFD) == -1);
	close(ends[0]);
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	clients[8] = ends[0];
	ATF_REQUIRE_EQ(0,
	    bsdtime_test_server_add(server, ends[1], "org.other", &config));
	ATF_REQUIRE_EQ(9, bsdtime_test_server_count(server));
	bsdtime_test_server_destroy(server);
	for (unsigned i = 0; i < 9; ++i)
		close(clients[i]);
	ATF_REQUIRE_EQ(before, open_fd_count());
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, reactor_label_quota_isolated);
	ATF_TP_ADD_TC(tp, reactor_capacity_and_expiry);
	ATF_TP_ADD_TC(tp, reactor_reuses_slots_without_fd_growth);
	ATF_TP_ADD_TC(tp, multiple_clients_idle_and_policy_isolation);
	ATF_TP_ADD_TC(tp, nonreading_peer_does_not_block_others);
	ATF_TP_ADD_TC(tp, get_reads_clock);
	ATF_TP_ADD_TC(tp, new_client_rejects_legacy_peer_without_writes);
	ATF_TP_ADD_TC(tp, malformed_reply_closes_client);
	ATF_TP_ADD_TC(tp, malformed_old_delta_even_when_discarded);
	ATF_TP_ADD_TC(tp, default_denies_writes);
	ATF_TP_ADD_TC(tp, named_policy_does_not_grant_other_labels);
	ATF_TP_ADD_TC(tp, allowed_writes_preserve_signed_delta);
	ATF_TP_ADD_TC(tp, allowed_without_token_reaches_gate);
	ATF_TP_ADD_TC(tp, client_value_validation);
	ATF_TP_ADD_TC(tp, server_value_validation);
	ATF_TP_ADD_TC(tp, unknown_method_rejected);
	ATF_TP_ADD_TC(tp, short_frame_rejected);
	ATF_TP_ADD_TC(tp, legacy_wire_rejected);
	ATF_TP_ADD_TC(tp, missing_body_rejected);
	ATF_TP_ADD_TC(tp, attached_descriptor_closed);
	ATF_TP_ADD_TC(tp, future_version_rejected);
	ATF_TP_ADD_TC(tp, timeout_closes_client);
	ATF_TP_ADD_TC(tp, forked_client_rejected);
	ATF_TP_ADD_TC(tp, create_failure_keeps_fd);
	return (atf_no_error());
}
