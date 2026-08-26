/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <networkcmp.h>
#include <networkcmp_server.h>

#include "networkcmp_test.h"
#include "policy.h"

union wire_buffer {
	max_align_t align;
	uint8_t bytes[NETWORKCMP_MAX_MESSAGE];
};

struct fixture {
	struct service_session *session;
	pid_t child;
	int resolver_ready;
	int resolver_release;
};

struct resolve_call {
	struct fixture *fixture;
	int error;
	int status;
};

static int call(struct fixture *, const void *, size_t, const int *, size_t,
    union wire_buffer *, size_t *);

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s",
	    strerror(errno));
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, name, sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error;
		return (-1);
	}
	close(control);
	return (connect.fd);
}

static void
channel_pair(int *client, int *provider)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t operation;

	*client = capability_connect("channel");
	ATF_REQUIRE(*client >= 0);
	operation = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &operation;
	send.payload_len = sizeof(operation);
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_SENDMSG, &send));
	memset(&receive, 0, sizeof(receive));
	receive.fds = provider;
	receive.nfds = 1;
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_RECVMSG, &receive));
	ATF_REQUIRE_EQ(1, receive.nfds);
}

static void
fixture_create(struct fixture *fixture)
{
	struct networkcmp_policy policy;
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	fixture->resolver_ready = -1;
	fixture->resolver_release = -1;
	ATF_REQUIRE_EQ(0, networkcmp_policy_default(&policy));
	policy.max_sockets = 2;
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(networkcmp_test_serve(provider, NULL, &policy,
		    "org.test.network"));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_create_blocked_resolver_timeout(struct fixture *fixture,
    uint32_t timeout_ms)
{
	struct networkcmp_policy policy;
	int client, provider, ready[2], release[2];

	memset(fixture, 0, sizeof(*fixture));
	fixture->resolver_ready = -1;
	fixture->resolver_release = -1;
	ATF_REQUIRE_EQ(0, networkcmp_policy_default(&policy));
	policy.max_sockets = 2;
	ATF_REQUIRE_EQ(0, pipe(ready));
	ATF_REQUIRE_EQ(0, pipe(release));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		close(ready[0]);
		close(release[1]);
		if (timeout_ms == 0)
			_exit(networkcmp_test_serve_blocked_resolver(provider, NULL,
			    &policy, "org.test.network", ready[1], release[0]));
		_exit(networkcmp_test_serve_blocked_resolver_timeout(provider, NULL,
		    &policy, "org.test.network", ready[1], release[0], timeout_ms));
	}
	close(provider);
	close(ready[1]);
	close(release[0]);
	fixture->resolver_ready = ready[0];
	fixture->resolver_release = release[1];
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_create_blocked_resolver(struct fixture *fixture)
{

	fixture_create_blocked_resolver_timeout(fixture, 0);
}

static void
fixture_destroy(struct fixture *fixture, int expected_status)
{
	int status;

	if (fixture->resolver_ready >= 0)
		close(fixture->resolver_ready);
	if (fixture->resolver_release >= 0)
		close(fixture->resolver_release);
	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
}

static void *
resolve_call_thread(void *argument)
{
	struct resolve_call *resolve_call;
	struct {
		struct networkcmp_msg message;
		struct networkcmp_resolve_request request;
		char host[9];
	} request;
	union wire_buffer reply;
	size_t length;

	resolve_call = argument;
	memset(&request, 0, sizeof(request));
	if (networkcmp_message_init(&request.message, NETWORKCMP_OP_RESOLVE, 0) ==
	    -1) {
		resolve_call->error = errno;
		return (NULL);
	}
	request.request.host_length = sizeof(request.host);
	request.request.family = NETWORKCMP_AF_UNSPEC;
	request.request.socket_type = NETWORKCMP_SOCK_ANY;
	request.request.max_results = 1;
	memcpy(request.host, "localhost", sizeof(request.host));
	/* Exact wire length: the validator rejects tail padding. */
	if (call(resolve_call->fixture, &request, sizeof(request.message) +
	    sizeof(request.request) + sizeof(request.host), NULL, 0,
	    &reply, &length) == -1) {
		resolve_call->error = errno;
		return (NULL);
	}
	if (networkcmp_validate_message((void *)reply.bytes, length,
	    NETWORKCMP_MESSAGE_REPLY) == -1) {
		resolve_call->error = errno;
		return (NULL);
	}
	resolve_call->status = -((struct networkcmp_msg *)(void *)reply.bytes)->status;
	return (NULL);
}

static int
call(struct fixture *fixture, const void *request, size_t request_length,
    const int *fds, size_t nfds, union wire_buffer *reply, size_t *reply_length)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message message = {
		.size = sizeof(message),
		.data = request,
		.length = request_length,
		.fds = fds,
		.nfds = nfds,
	};
	struct service_reply response = {
		.size = sizeof(response),
		.data = reply->bytes,
		.capacity = sizeof(reply->bytes),
	};

	if (service_session_call(fixture->session, &message, &response,
	    &options) == -1)
		return (-1);
	*reply_length = response.length;
	return (0);
}

static int
reply_status(union wire_buffer *wire, size_t length, uint16_t opcode)
{
	struct networkcmp_msg *message = (void *)wire->bytes;

	ATF_REQUIRE_EQ(0, networkcmp_validate_message(message, length,
	    NETWORKCMP_MESSAGE_REPLY));
	ATF_REQUIRE_EQ(opcode, message->opcode);
	return (-message->status);
}

static int
request_status(struct fixture *fixture, uint16_t opcode, const void *payload,
    size_t payload_length, const int *fds, size_t nfds)
{
	union wire_buffer request, reply;
	struct networkcmp_msg *message;
	size_t length;

	ATF_REQUIRE(payload_length <= sizeof(request.bytes) - sizeof(*message));
	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, networkcmp_message_init(message, opcode, 0));
	if (payload_length != 0)
		memcpy(message + 1, payload, payload_length);
	ATF_REQUIRE_EQ_MSG(0, call(fixture, message,
	    sizeof(*message) + payload_length, fds, nfds, &reply, &length),
	    "opcode %u call: %s", opcode, strerror(errno));
	return (reply_status(&reply, length, opcode));
}

ATF_TC(provider_socket_lifecycle);
ATF_TC_HEAD(provider_socket_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "The real dispatcher allocates bounded sockets, applies policy, and rejects stale handles");
}
ATF_TC_BODY(provider_socket_lifecycle, tc)
{
	struct fixture fixture;
	union wire_buffer request, reply;
	struct networkcmp_msg *message;
	struct networkcmp_hello *hello_request;
	struct networkcmp_hello_reply *hello;
	struct networkcmp_socket_request *socket_request;
	struct networkcmp_handle_reply *handle_reply;
	struct networkcmp_endpoint_request *endpoint_request;
	struct networkcmp_inline_request *inline_request;
	struct networkcmp_close_request *close_request;
	struct networkcmp_handle socket;
	size_t length;

	fixture_create(&fixture);
	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, networkcmp_message_init(message,
	    NETWORKCMP_OP_HELLO, 0));
	hello_request = (void *)(message + 1);
	hello_request->min_version = NETWORKCMP_ABI_VERSION;
	hello_request->max_version = NETWORKCMP_ABI_VERSION;
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*hello_request), NULL, 0, &reply,
	    &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, NETWORKCMP_OP_HELLO));
	hello = (void *)(reply.bytes + sizeof(*message));
	ATF_CHECK_EQ(2, hello->max_sockets);
	ATF_CHECK((hello->features & NETWORKCMP_FEATURE_UDP) != 0);
	ATF_CHECK_EQ(NETWORKCMP_INLINE_MAX, hello->max_inline);
	ATF_CHECK_EQ(NETWORKCMP_INLINE_MAX, hello->max_datagram);
	ATF_CHECK_EQ(NETWORKCMP_IO_TIMEOUT_MAX, hello->io_timeout_max);

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, networkcmp_message_init(message,
	    NETWORKCMP_OP_SOCKET, 0));
	socket_request = (void *)(message + 1);
	socket_request->family = NETWORKCMP_AF_INET4;
	socket_request->type = NETWORKCMP_SOCK_DGRAM;
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*socket_request), NULL, 0, &reply,
	    &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, NETWORKCMP_OP_SOCKET));
	handle_reply = (void *)(reply.bytes + sizeof(*message));
	socket = handle_reply->socket;

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, networkcmp_message_init(message,
	    NETWORKCMP_OP_BIND, 0));
	endpoint_request = (void *)(message + 1);
	endpoint_request->socket = socket;
	endpoint_request->endpoint.family = NETWORKCMP_AF_INET4;
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*endpoint_request), NULL, 0, &reply,
	    &length));
	ATF_CHECK_EQ(EACCES, reply_status(&reply, length, NETWORKCMP_OP_BIND));

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, networkcmp_message_init(message,
	    NETWORKCMP_OP_RECV, 0));
	inline_request = (void *)(message + 1);
	inline_request->socket = socket;
	inline_request->length = 16;
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*inline_request), NULL, 0, &reply,
	    &length));
	ATF_CHECK_EQ(EAGAIN, reply_status(&reply, length, NETWORKCMP_OP_RECV));

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, networkcmp_message_init(message,
	    NETWORKCMP_OP_CLOSE, 0));
	close_request = (void *)(message + 1);
	close_request->socket = socket;
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*close_request), NULL, 0, &reply,
	    &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, NETWORKCMP_OP_CLOSE));
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*close_request), NULL, 0, &reply,
	    &length));
	ATF_CHECK_EQ(ESTALE, reply_status(&reply, length, NETWORKCMP_OP_CLOSE));
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_malformed_channel);
ATF_TC_HEAD(provider_malformed_channel, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Unexpected descriptors terminate a provider channel without being interpreted");
}

ATF_TC(provider_resolver_does_not_block_session);
ATF_TC_HEAD(provider_resolver_does_not_block_session, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A stalled resolver does not block other RPCs and overlapping resolves are bounded");
}

ATF_TC(provider_resolver_deadline_terminates_session);
ATF_TC_HEAD(provider_resolver_deadline_terminates_session, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A resolver that exceeds its provider deadline cannot retain the session indefinitely");
}
ATF_TC_BODY(provider_resolver_deadline_terminates_session, tc)
{
	struct resolve_call resolve_call;
	struct fixture fixture;
	pthread_t thread;
	uint8_t byte;
	ssize_t amount;
	int error;

	fixture_create_blocked_resolver_timeout(&fixture, 25);
	memset(&resolve_call, 0, sizeof(resolve_call));
	resolve_call.fixture = &fixture;
	error = pthread_create(&thread, NULL, resolve_call_thread, &resolve_call);
	ATF_REQUIRE_EQ_MSG(0, error, "pthread_create: %s", strerror(error));
	do {
		amount = read(fixture.resolver_ready, &byte, sizeof(byte));
	} while (amount == -1 && errno == EINTR);
	ATF_REQUIRE_EQ(sizeof(byte), amount);
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK(resolve_call.error == ECONNRESET ||
	    resolve_call.error == EPIPE || resolve_call.error == ETIMEDOUT);
	fixture_destroy(&fixture, 1);
}
ATF_TC_BODY(provider_resolver_does_not_block_session, tc)
{
	struct {
		struct networkcmp_resolve_request request;
		char host[9];
	} resolve;
	struct networkcmp_close_request close_request;
	struct resolve_call resolve_call;
	struct fixture fixture;
	pthread_t thread;
	uint8_t byte;
	ssize_t amount;
	int error;

	fixture_create_blocked_resolver(&fixture);
	memset(&resolve_call, 0, sizeof(resolve_call));
	resolve_call.fixture = &fixture;
	error = pthread_create(&thread, NULL, resolve_call_thread, &resolve_call);
	ATF_REQUIRE_EQ_MSG(0, error, "pthread_create: %s", strerror(error));
	do {
		amount = read(fixture.resolver_ready, &byte, sizeof(byte));
	} while (amount == -1 && errno == EINTR);
	ATF_REQUIRE_EQ(sizeof(byte), amount);

	close_request.socket = (struct networkcmp_handle){ .handle = UINT64_MAX };
	ATF_CHECK_EQ(EBADF, request_status(&fixture, NETWORKCMP_OP_CLOSE,
	    &close_request, sizeof(close_request), NULL, 0));

	memset(&resolve, 0, sizeof(resolve));
	resolve.request.host_length = sizeof(resolve.host);
	resolve.request.family = NETWORKCMP_AF_UNSPEC;
	resolve.request.socket_type = NETWORKCMP_SOCK_ANY;
	resolve.request.max_results = 1;
	memcpy(resolve.host, "localhost", sizeof(resolve.host));
	ATF_CHECK_EQ(EBUSY, request_status(&fixture, NETWORKCMP_OP_RESOLVE,
	    &resolve, sizeof(resolve.request) + sizeof(resolve.host), NULL, 0));

	byte = 1;
	do {
		amount = write(fixture.resolver_release, &byte, sizeof(byte));
	} while (amount == -1 && errno == EINTR);
	ATF_REQUIRE_EQ(sizeof(byte), amount);
	error = pthread_join(thread, NULL);
	ATF_REQUIRE_EQ_MSG(0, error, "pthread_join: %s", strerror(error));
	ATF_CHECK_EQ(0, resolve_call.error);
	ATF_CHECK_EQ(EOPNOTSUPP, resolve_call.status);
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_all_dispatch_opcodes);
ATF_TC_HEAD(provider_all_dispatch_opcodes, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Every NetworkCmp production dispatcher opcode returns a validated correlated reply");
}
ATF_TC_BODY(provider_all_dispatch_opcodes, tc)
{
	struct {
		struct networkcmp_setopt_request request;
		int value;
	} setopt;
	struct {
		struct networkcmp_resolve_request request;
		char host[9];
	} resolve;
	struct networkcmp_close_request close_request;
	struct networkcmp_endpoint_request endpoint;
	struct networkcmp_inline_request inline_request;
	struct networkcmp_listen_request listen_request;
	struct networkcmp_shutdown_request shutdown_request;
	struct networkcmp_socket_request socket_request;
	struct networkcmp_handle socket;
	struct networkcmp_handle_reply *handle_reply;
	struct fixture fixture;
	union wire_buffer request, reply;
	struct networkcmp_msg *message;
	size_t length;

	fixture_create(&fixture);
	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, networkcmp_message_init(message,
	    NETWORKCMP_OP_SOCKET, 0));
	socket_request = (struct networkcmp_socket_request){
		.family = NETWORKCMP_AF_INET4,
		.type = NETWORKCMP_SOCK_DGRAM,
	};
	memcpy(message + 1, &socket_request, sizeof(socket_request));
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(socket_request), NULL, 0, &reply,
	    &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, NETWORKCMP_OP_SOCKET));
	handle_reply = (void *)(reply.bytes + sizeof(*message));
	socket = handle_reply->socket;

	memset(&endpoint, 0, sizeof(endpoint));
	endpoint.socket = socket;
	endpoint.endpoint.family = NETWORKCMP_AF_INET4;
	ATF_CHECK_EQ(EOPNOTSUPP, request_status(&fixture,
	    NETWORKCMP_OP_CONNECT, &endpoint, sizeof(endpoint), NULL, 0));

	memset(&listen_request, 0, sizeof(listen_request));
	listen_request.socket = socket;
	listen_request.backlog = 1;
	ATF_CHECK_EQ(EACCES, request_status(&fixture, NETWORKCMP_OP_LISTEN,
	    &listen_request, sizeof(listen_request), NULL, 0));
	close_request.socket = socket;
	ATF_CHECK_EQ(EACCES, request_status(&fixture, NETWORKCMP_OP_ACCEPT,
	    &close_request, sizeof(close_request), NULL, 0));

	memset(&setopt, 0, sizeof(setopt));
	setopt.request.socket = socket;
	setopt.request.level = SOL_SOCKET;
	setopt.request.option = SO_REUSEADDR;
	setopt.request.value_length = sizeof(setopt.value);
	setopt.value = 1;
	ATF_CHECK_EQ(0, request_status(&fixture, NETWORKCMP_OP_SETOPT,
	    &setopt, sizeof(setopt.request) + sizeof(setopt.value), NULL, 0));

	memset(&shutdown_request, 0, sizeof(shutdown_request));
	shutdown_request.socket = (struct networkcmp_handle){ .handle = UINT64_MAX };
	ATF_CHECK_EQ(EBADF, request_status(&fixture, NETWORKCMP_OP_SHUTDOWN,
	    &shutdown_request, sizeof(shutdown_request), NULL, 0));
	/* CONNECT_STATUS is stream-only; a datagram socket rejects it. */
	ATF_CHECK_EQ(EOPNOTSUPP, request_status(&fixture,
	    NETWORKCMP_OP_CONNECT_STATUS, &close_request,
	    sizeof(close_request), NULL, 0));

	memset(&resolve, 0, sizeof(resolve));
	resolve.request.host_length = sizeof(resolve.host);
	resolve.request.family = NETWORKCMP_AF_UNSPEC;
	resolve.request.socket_type = NETWORKCMP_SOCK_ANY;
	resolve.request.max_results = 1;
	memcpy(resolve.host, "localhost", sizeof(resolve.host));
	ATF_CHECK_EQ(EOPNOTSUPP, request_status(&fixture,
	    NETWORKCMP_OP_RESOLVE, &resolve, sizeof(resolve.request) + sizeof(resolve.host), NULL, 0));

	memset(&inline_request, 0, sizeof(inline_request));
	inline_request.socket = (struct networkcmp_handle){ .handle = UINT64_MAX };
	inline_request.length = 1;
	ATF_CHECK_EQ(EBADF, request_status(&fixture, NETWORKCMP_OP_SEND,
	    &(struct {
		struct networkcmp_inline_request request;
		uint8_t byte;
	    }){ .request = inline_request, .byte = 1 },
	    sizeof(inline_request) + 1, NULL, 0));
	ATF_CHECK_EQ(EBADF, request_status(&fixture, NETWORKCMP_OP_RECV,
	    &inline_request, sizeof(inline_request), NULL, 0));

	ATF_CHECK_EQ(0, request_status(&fixture, NETWORKCMP_OP_CLOSE,
	    &close_request, sizeof(close_request), NULL, 0));
	fixture_destroy(&fixture, 0);
}
ATF_TC_BODY(provider_malformed_channel, tc)
{
	struct fixture fixture;
	union wire_buffer request, reply;
	struct networkcmp_msg *message = (void *)request.bytes;
	struct networkcmp_hello *hello;
	size_t length;
	int pipefd[2];

	fixture_create(&fixture);
	memset(&request, 0, sizeof(request));
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	ATF_REQUIRE_EQ(0, networkcmp_message_init(message,
	    NETWORKCMP_OP_HELLO, 0));
	hello = (void *)(message + 1);
	hello->min_version = NETWORKCMP_ABI_VERSION;
	hello->max_version = NETWORKCMP_ABI_VERSION;
	ATF_CHECK_EQ(-1, call(&fixture, message,
	    sizeof(*message) + sizeof(*hello), &pipefd[0], 1, &reply, &length));
	close(pipefd[0]);
	close(pipefd[1]);
	fixture_destroy(&fixture, 1);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct networkcmp_policy policy;

	ATF_REQUIRE_EQ(0, networkcmp_policy_default(&policy));
	ATF_CHECK_ERRNO(EINVAL,
	    networkcmp_test_serve(-1, NULL, &policy, "org.test") == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    networkcmp_test_serve(0, NULL, NULL, "org.test") == -1);
	policy.max_sockets = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    networkcmp_test_serve(0, NULL, &policy, "org.test") == -1);
	policy.max_sockets = 1;
	ATF_CHECK_ERRNO(EINVAL,
	    networkcmp_test_serve(0, NULL, &policy, "") == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, provider_socket_lifecycle);
	ATF_TP_ADD_TC(tp, provider_all_dispatch_opcodes);
	ATF_TP_ADD_TC(tp, provider_malformed_channel);
	ATF_TP_ADD_TC(tp, provider_resolver_does_not_block_session);
	ATF_TP_ADD_TC(tp, provider_resolver_deadline_terminates_session);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
