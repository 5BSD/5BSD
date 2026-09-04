/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <networkcmp.h>
#include <networkcmp_server.h>

#include "config.h"
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

static int call(struct fixture *, const void *, size_t, union wire_buffer *,
    size_t *, int *);

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
fixture_create_policy(struct fixture *fixture,
    const struct networkcmp_policy *policy)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	fixture->resolver_ready = -1;
	fixture->resolver_release = -1;
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(networkcmp_test_serve(provider, NULL, policy,
		    "org.test.network"));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

/*
 * Serve a session for `label` under a per-client policy CONFIG (N1): the
 * config text is parsed by the daemon's real loader and the session policy is
 * resolved through networkcmp_config_session_policy() exactly as main() does
 * for a non-admin session, then installed as the fixture's immutable policy.
 */
static void
fixture_create_config(struct fixture *fixture, const char *config_text,
    const char *label)
{
	struct networkcmp_config config;
	struct networkcmp_policy policy;
	const char *source;
	int client, provider;

	ATF_REQUIRE_EQ(0, networkcmp_config_parse(config_text, &config));
	ATF_REQUIRE_EQ(0, networkcmp_config_session_policy(&config, label,
	    SERVICE_RIGHTS_NONE, &policy, &source));
	memset(fixture, 0, sizeof(*fixture));
	fixture->resolver_ready = -1;
	fixture->resolver_release = -1;
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(networkcmp_test_serve(provider, NULL, &policy, label));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_create(struct fixture *fixture)
{
	struct networkcmp_policy policy;

	ATF_REQUIRE_EQ(0, networkcmp_policy_default(&policy));
	fixture_create_policy(fixture, &policy);
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
	    sizeof(request.request) + sizeof(request.host), &reply, &length,
	    NULL) == -1) {
		resolve_call->error = errno;
		return (NULL);
	}
	if (networkcmp_validate_message((void *)reply.bytes, length,
	    NETWORKCMP_MESSAGE_REPLY) == -1) {
		resolve_call->error = errno;
		return (NULL);
	}
	resolve_call->status =
	    -((struct networkcmp_msg *)(void *)reply.bytes)->status;
	return (NULL);
}

static int
call(struct fixture *fixture, const void *request, size_t request_length,
    union wire_buffer *reply, size_t *reply_length, int *out_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message message = {
		.size = sizeof(message),
		.data = request,
		.length = request_length,
	};
	struct service_reply response = {
		.size = sizeof(response),
		.data = reply->bytes,
		.capacity = sizeof(reply->bytes),
	};

	if (out_fd != NULL) {
		*out_fd = -1;
		response.fds = out_fd;
		response.fd_capacity = 1;
	}
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

/* Fill a networkcmp_endpoint from an IPv4 loopback address and port. */
static void
loopback_endpoint(struct networkcmp_endpoint *endpoint, uint16_t port)
{
	struct in_addr loopback;

	memset(endpoint, 0, sizeof(*endpoint));
	endpoint->family = NETWORKCMP_AF_INET4;
	endpoint->port = port;
	loopback.s_addr = htonl(INADDR_LOOPBACK);
	memcpy(endpoint->address, &loopback, sizeof(loopback));
}

/* Bind a listening (stream) or bound (datagram) loopback socket. */
static int
open_loopback(int type, uint16_t *port)
{
	struct sockaddr_in sin;
	socklen_t length;
	int fd;

	fd = socket(AF_INET, type | SOCK_CLOEXEC, 0);
	ATF_REQUIRE(fd >= 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE_EQ(0, bind(fd, (struct sockaddr *)&sin, sizeof(sin)));
	if (type == SOCK_STREAM)
		ATF_REQUIRE_EQ(0, listen(fd, 4));
	length = sizeof(sin);
	ATF_REQUIRE_EQ(0, getsockname(fd, (struct sockaddr *)&sin, &length));
	*port = ntohs(sin.sin_port);
	return (fd);
}

/* Build an IPv4 networkcmp_endpoint from four address octets. */
static void
ipv4_endpoint(struct networkcmp_endpoint *endpoint, uint8_t a, uint8_t b,
    uint8_t c, uint8_t d)
{

	memset(endpoint, 0, sizeof(*endpoint));
	endpoint->family = NETWORKCMP_AF_INET4;
	endpoint->address[0] = a;
	endpoint->address[1] = b;
	endpoint->address[2] = c;
	endpoint->address[3] = d;
}

/* Build an IPv6 networkcmp_endpoint from a 16-byte address. */
static void
ipv6_endpoint(struct networkcmp_endpoint *endpoint, const uint8_t address[16])
{

	memset(endpoint, 0, sizeof(*endpoint));
	endpoint->family = NETWORKCMP_AF_INET6;
	memcpy(endpoint->address, address, 16);
}

/*
 * N2 SSRF guard, pure classifier.  endpoint_is_internal() is the pre-connect
 * gate that fails closed on loopback/link-local/RFC1918/ULA (and their
 * IPv4-mapped forms) for sessions lacking internal reach.  This regression pins
 * the range table directly; it needs no provider channel and no privilege.
 */
ATF_TC_WITHOUT_HEAD(endpoint_internal_ranges_are_blocked);
ATF_TC_BODY(endpoint_internal_ranges_are_blocked, tc)
{
	static const uint8_t v6_loopback[16] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	static const uint8_t v6_linklocal[16] = {
		0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	static const uint8_t v6_ula[16] = {
		0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	static const uint8_t v6_mapped_loopback[16] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 };
	static const uint8_t v6_public[16] = {
		0x26, 0x06, 0x28, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	static const uint8_t v6_mapped_public[16] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 93, 184, 216, 34 };
	struct networkcmp_endpoint endpoint;

	/* IPv4 internal ranges are all flagged. */
	ipv4_endpoint(&endpoint, 127, 0, 0, 1);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));
	ipv4_endpoint(&endpoint, 0, 0, 0, 0);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));
	ipv4_endpoint(&endpoint, 169, 254, 1, 1);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));
	ipv4_endpoint(&endpoint, 10, 0, 0, 1);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));
	ipv4_endpoint(&endpoint, 172, 16, 0, 1);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));
	ipv4_endpoint(&endpoint, 172, 31, 255, 254);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));
	ipv4_endpoint(&endpoint, 192, 168, 1, 1);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));

	/* IPv4 public addresses and the 172.16/12 boundaries are not flagged. */
	ipv4_endpoint(&endpoint, 93, 184, 216, 34);
	ATF_CHECK(!networkcmp_test_endpoint_is_internal(&endpoint));
	ipv4_endpoint(&endpoint, 172, 15, 0, 1);
	ATF_CHECK(!networkcmp_test_endpoint_is_internal(&endpoint));
	ipv4_endpoint(&endpoint, 172, 32, 0, 1);
	ATF_CHECK(!networkcmp_test_endpoint_is_internal(&endpoint));
	ipv4_endpoint(&endpoint, 8, 8, 8, 8);
	ATF_CHECK(!networkcmp_test_endpoint_is_internal(&endpoint));

	/* IPv6 loopback, link-local, ULA, and IPv4-mapped internal are flagged. */
	ipv6_endpoint(&endpoint, v6_loopback);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));
	ipv6_endpoint(&endpoint, v6_linklocal);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));
	ipv6_endpoint(&endpoint, v6_ula);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));
	ipv6_endpoint(&endpoint, v6_mapped_loopback);
	ATF_CHECK(networkcmp_test_endpoint_is_internal(&endpoint));

	/* IPv6 public, including an IPv4-mapped public address, is not flagged. */
	ipv6_endpoint(&endpoint, v6_public);
	ATF_CHECK(!networkcmp_test_endpoint_is_internal(&endpoint));
	ipv6_endpoint(&endpoint, v6_mapped_public);
	ATF_CHECK(!networkcmp_test_endpoint_is_internal(&endpoint));
}

ATF_TC(provider_hello);
ATF_TC_HEAD(provider_hello, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "HELLO negotiates the version-1 broker features and resolve bound");
}
ATF_TC_BODY(provider_hello, tc)
{
	struct fixture fixture;
	union wire_buffer request, reply;
	struct networkcmp_msg *message;
	struct networkcmp_hello *hello_request;
	struct networkcmp_hello_reply *hello;
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
	    sizeof(*message) + sizeof(*hello_request), &reply, &length, NULL));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, NETWORKCMP_OP_HELLO));
	hello = (void *)(reply.bytes + sizeof(*message));
	ATF_CHECK_EQ(NETWORKCMP_ABI_VERSION, hello->version);
	ATF_CHECK((hello->features & NETWORKCMP_FEATURE_TCP) != 0);
	ATF_CHECK((hello->features & NETWORKCMP_FEATURE_UDP) != 0);
	ATF_CHECK((hello->features & NETWORKCMP_FEATURE_DNS) != 0);
	ATF_CHECK_EQ(16, hello->max_resolve_results);
	fixture_destroy(&fixture, 0);
}

/*
 * Send CONNECT/UDP and assert the reply status and, on success, that the
 * received descriptor is present.  Returns the errno-style status.
 */
static int
broker_request(struct fixture *fixture, uint16_t opcode,
    const struct networkcmp_endpoint *endpoint, int *out_fd)
{
	union wire_buffer request, reply;
	struct networkcmp_msg *message;
	struct networkcmp_connect_request *connect;
	size_t length;
	int status;

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, networkcmp_message_init(message, opcode, 0));
	connect = (void *)(message + 1);
	connect->endpoint = *endpoint;
	ATF_REQUIRE_EQ(0, call(fixture, message,
	    sizeof(*message) + sizeof(*connect), &reply, &length, out_fd));
	status = reply_status(&reply, length, opcode);
	return (status);
}

/* Assert the delivered socket carries only data-transfer rights. */
static void
check_delivered_rights(int fd)
{
	cap_rights_t rights, expected;

	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	cap_rights_init(&expected, CAP_READ, CAP_WRITE, CAP_EVENT,
	    CAP_SHUTDOWN, CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_FCNTL, CAP_FSTAT,
	    CAP_IOCTL);
	ATF_CHECK(cap_rights_contains(&expected, &rights));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_READ));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_WRITE));
	/* The client cannot bind, connect, listen, accept, or peel off. */
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_BIND));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_CONNECT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_LISTEN));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_ACCEPT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_PEELOFF));
}

ATF_TC(provider_connect_returns_fd);
ATF_TC_HEAD(provider_connect_returns_fd, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "CONNECT returns a connected, rights-limited descriptor the client "
	    "owns");
}
ATF_TC_BODY(provider_connect_returns_fd, tc)
{
	struct fixture fixture;
	struct networkcmp_endpoint endpoint;
	char buffer[4];
	uint16_t port;
	int listener, accepted, fd, flags;

	fixture_create(&fixture);
	listener = open_loopback(SOCK_STREAM, &port);
	loopback_endpoint(&endpoint, port);
	fd = -1;
	ATF_REQUIRE_EQ(0, broker_request(&fixture, NETWORKCMP_OP_CONNECT,
	    &endpoint, &fd));
	ATF_REQUIRE(fd >= 0);
	check_delivered_rights(fd);
	/* The delivered descriptor toggles O_NONBLOCK through fcntl. */
	flags = fcntl(fd, F_GETFL);
	ATF_REQUIRE(flags != -1);
	ATF_CHECK_EQ(0, fcntl(fd, F_SETFL, flags | O_NONBLOCK));
	/* The socket is really connected: bytes flow end to end. */
	accepted = accept(listener, NULL, NULL);
	ATF_REQUIRE(accepted >= 0);
	ATF_REQUIRE_EQ(4, write(fd, "ping", 4));
	ATF_REQUIRE_EQ(4, read(accepted, buffer, sizeof(buffer)));
	ATF_CHECK_EQ(0, memcmp(buffer, "ping", 4));
	close(accepted);
	close(fd);
	close(listener);
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_udp_returns_fd);
ATF_TC_HEAD(provider_udp_returns_fd, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "UDP returns a connected datagram descriptor bound to the peer");
}
ATF_TC_BODY(provider_udp_returns_fd, tc)
{
	struct fixture fixture;
	struct networkcmp_endpoint endpoint;
	char buffer[8];
	uint16_t port;
	int peer, fd;

	fixture_create(&fixture);
	peer = open_loopback(SOCK_DGRAM, &port);
	loopback_endpoint(&endpoint, port);
	fd = -1;
	ATF_REQUIRE_EQ(0, broker_request(&fixture, NETWORKCMP_OP_UDP,
	    &endpoint, &fd));
	ATF_REQUIRE(fd >= 0);
	check_delivered_rights(fd);
	/* A connected UDP socket sends to its peer with send(2). */
	ATF_REQUIRE_EQ(5, write(fd, "hello", 5));
	ATF_REQUIRE_EQ(5, recv(peer, buffer, sizeof(buffer), 0));
	ATF_CHECK_EQ(0, memcmp(buffer, "hello", 5));
	close(fd);
	close(peer);
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_connect_denied);
ATF_TC_HEAD(provider_connect_denied, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Immutable session policy denies connect and udp and returns no fd");
}
ATF_TC_BODY(provider_connect_denied, tc)
{
	struct networkcmp_policy policy;
	struct fixture fixture;
	struct networkcmp_endpoint endpoint;
	uint16_t port;
	int listener, fd;

	ATF_REQUIRE_EQ(0, networkcmp_policy_default(&policy));
	policy.allow_connect = false;
	policy.allow_udp = false;
	fixture_create_policy(&fixture, &policy);
	listener = open_loopback(SOCK_STREAM, &port);
	loopback_endpoint(&endpoint, port);
	fd = -1;
	ATF_CHECK_EQ(EACCES, broker_request(&fixture, NETWORKCMP_OP_CONNECT,
	    &endpoint, &fd));
	ATF_CHECK_EQ(-1, fd);
	fd = -1;
	ATF_CHECK_EQ(EACCES, broker_request(&fixture, NETWORKCMP_OP_UDP,
	    &endpoint, &fd));
	ATF_CHECK_EQ(-1, fd);
	close(listener);
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_connect_refused);
ATF_TC_HEAD(provider_connect_refused, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A refused connect returns the connect errno and no descriptor");
}
ATF_TC_BODY(provider_connect_refused, tc)
{
	struct fixture fixture;
	struct networkcmp_endpoint endpoint;
	uint16_t port;
	int listener, fd, status;

	fixture_create(&fixture);
	/* Bind then close a listener so its port is (very likely) unused. */
	listener = open_loopback(SOCK_STREAM, &port);
	close(listener);
	loopback_endpoint(&endpoint, port);
	fd = -1;
	status = broker_request(&fixture, NETWORKCMP_OP_CONNECT, &endpoint,
	    &fd);
	ATF_CHECK(status == ECONNREFUSED || status == EADDRNOTAVAIL ||
	    status == ETIMEDOUT);
	ATF_CHECK_EQ(-1, fd);
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_malformed_channel);
ATF_TC_HEAD(provider_malformed_channel, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Unexpected descriptors terminate a provider channel without being "
	    "interpreted");
}
ATF_TC_BODY(provider_malformed_channel, tc)
{
	struct fixture fixture;
	union wire_buffer reply;
	struct networkcmp_msg message;
	struct networkcmp_hello *hello;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply response;
	uint8_t request[sizeof(struct networkcmp_msg) +
	    sizeof(struct networkcmp_hello)];
	int pipefd[2];

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	memset(request, 0, sizeof(request));
	ATF_REQUIRE_EQ(0, networkcmp_message_init(&message,
	    NETWORKCMP_OP_HELLO, 0));
	memcpy(request, &message, sizeof(message));
	hello = (void *)(request + sizeof(message));
	hello->min_version = NETWORKCMP_ABI_VERSION;
	hello->max_version = NETWORKCMP_ABI_VERSION;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = request;
	outgoing.length = sizeof(request);
	outgoing.fds = &pipefd[0];
	outgoing.nfds = 1;
	memset(&response, 0, sizeof(response));
	response.size = sizeof(response);
	response.data = reply.bytes;
	response.capacity = sizeof(reply.bytes);
	ATF_CHECK_EQ(-1, service_session_call(fixture.session, &outgoing,
	    &response, &options));
	close(pipefd[0]);
	close(pipefd[1]);
	fixture_destroy(&fixture, 1);
}

ATF_TC(provider_resolver_does_not_block_session);
ATF_TC_HEAD(provider_resolver_does_not_block_session, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A stalled resolver does not block other RPCs and overlapping "
	    "resolves are bounded");
}
ATF_TC_BODY(provider_resolver_does_not_block_session, tc)
{
	struct {
		struct networkcmp_msg message;
		struct networkcmp_resolve_request request;
		char host[9];
	} resolve;
	struct networkcmp_endpoint endpoint;
	struct resolve_call resolve_call;
	struct fixture fixture;
	union wire_buffer reply;
	pthread_t thread;
	uint8_t byte;
	size_t length;
	ssize_t amount;
	uint16_t port;
	int error, listener, fd;

	fixture_create_blocked_resolver(&fixture);
	memset(&resolve_call, 0, sizeof(resolve_call));
	resolve_call.fixture = &fixture;
	error = pthread_create(&thread, NULL, resolve_call_thread, &resolve_call);
	ATF_REQUIRE_EQ_MSG(0, error, "pthread_create: %s", strerror(error));
	do {
		amount = read(fixture.resolver_ready, &byte, sizeof(byte));
	} while (amount == -1 && errno == EINTR);
	ATF_REQUIRE_EQ(sizeof(byte), amount);

	/* A CONNECT still completes while the resolver is stalled. */
	listener = open_loopback(SOCK_STREAM, &port);
	loopback_endpoint(&endpoint, port);
	fd = -1;
	ATF_CHECK_EQ(0, broker_request(&fixture, NETWORKCMP_OP_CONNECT,
	    &endpoint, &fd));
	ATF_CHECK(fd >= 0);
	if (fd >= 0)
		close(fd);
	close(listener);

	/* A second, overlapping resolve is bounded. */
	memset(&resolve, 0, sizeof(resolve));
	ATF_REQUIRE_EQ(0, networkcmp_message_init(&resolve.message,
	    NETWORKCMP_OP_RESOLVE, 0));
	resolve.request.host_length = sizeof(resolve.host);
	resolve.request.family = NETWORKCMP_AF_UNSPEC;
	resolve.request.socket_type = NETWORKCMP_SOCK_ANY;
	resolve.request.max_results = 1;
	memcpy(resolve.host, "localhost", sizeof(resolve.host));
	ATF_REQUIRE_EQ(0, call(&fixture, &resolve, sizeof(resolve.message) +
	    sizeof(resolve.request) + sizeof(resolve.host), &reply, &length,
	    NULL));
	ATF_CHECK_EQ(EBUSY, reply_status(&reply, length,
	    NETWORKCMP_OP_RESOLVE));

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

ATF_TC(provider_resolver_deadline_terminates_session);
ATF_TC_HEAD(provider_resolver_deadline_terminates_session, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A resolver that exceeds its provider deadline cannot retain the "
	    "session indefinitely");
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

/*
 * N2 SSRF guard over the plane.  A session that lacks internal reach must be
 * denied a connect to loopback with EACCES BEFORE any connect is attempted, even
 * when a live listener is bound there; a session that carries internal reach
 * (admin-equivalent) reaches the very same peer.  This proves the guard, not a
 * connection refusal, is what fails closed.
 */
ATF_TC(non_admin_connect_to_loopback_is_denied);
ATF_TC_HEAD(non_admin_connect_to_loopback_is_denied, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Connecting to loopback is denied without internal reach and allowed "
	    "with it");
}
ATF_TC_BODY(non_admin_connect_to_loopback_is_denied, tc)
{
	struct networkcmp_policy policy;
	struct fixture fixture;
	struct networkcmp_endpoint endpoint;
	uint16_t port;
	int listener, accepted, fd;

	/* A live loopback listener: a real connect to it would succeed. */
	listener = open_loopback(SOCK_STREAM, &port);
	loopback_endpoint(&endpoint, port);

	/* No internal reach: the broker fails closed with EACCES and no fd. */
	ATF_REQUIRE_EQ(0, networkcmp_policy_default(&policy));
	policy.allow_internal = false;
	fixture_create_policy(&fixture, &policy);
	fd = -1;
	ATF_CHECK_EQ(EACCES, broker_request(&fixture, NETWORKCMP_OP_CONNECT,
	    &endpoint, &fd));
	ATF_CHECK_EQ(-1, fd);
	fixture_destroy(&fixture, 0);

	/* Internal reach (admin-equivalent default) reaches the same peer. */
	ATF_REQUIRE_EQ(0, networkcmp_policy_default(&policy));
	ATF_REQUIRE(policy.allow_internal);
	fixture_create_policy(&fixture, &policy);
	fd = -1;
	ATF_CHECK_EQ(0, broker_request(&fixture, NETWORKCMP_OP_CONNECT,
	    &endpoint, &fd));
	ATF_CHECK(fd >= 0);
	if (fd >= 0) {
		accepted = accept(listener, NULL, NULL);
		ATF_CHECK(accepted >= 0);
		if (accepted >= 0)
			close(accepted);
		close(fd);
	}
	fixture_destroy(&fixture, 0);
	close(listener);
}

/*
 * N1 per-client policy over the plane.  A session whose LABEL carries a
 * clients{} entry denying connect is refused CONNECT with EACCES (no fd),
 * while RESOLVE on the very same session still passes the policy gate: under
 * NETWORKCMP_TESTING the resolver stub answers EOPNOTSUPP, so any status
 * other than EACCES proves the request reached the resolver.  An unlisted
 * sibling label on the same config retains the default outbound grant.
 */
ATF_TC(per_label_config_denies_connect_allows_resolve);
ATF_TC_HEAD(per_label_config_denies_connect_allows_resolve, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A clients{} entry denying connect yields EACCES on CONNECT while "
	    "RESOLVE still works, and an unlisted label keeps the default");
}
/* Send HELLO on the fixture session and return the negotiated features. */
static uint32_t
hello_features(struct fixture *fixture)
{
	union wire_buffer request, reply;
	struct networkcmp_msg *message;
	struct networkcmp_hello *hello_request;
	struct networkcmp_hello_reply *hello;
	size_t length;

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, networkcmp_message_init(message,
	    NETWORKCMP_OP_HELLO, 0));
	hello_request = (void *)(message + 1);
	hello_request->min_version = NETWORKCMP_ABI_VERSION;
	hello_request->max_version = NETWORKCMP_ABI_VERSION;
	ATF_REQUIRE_EQ(0, call(fixture, message,
	    sizeof(*message) + sizeof(*hello_request), &reply, &length, NULL));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, NETWORKCMP_OP_HELLO));
	hello = (void *)(reply.bytes + sizeof(*message));
	return (hello->features);
}

ATF_TC_BODY(per_label_config_denies_connect_allows_resolve, tc)
{
	static const char *config_text =
	    "default { resolve = true; connect = true; udp = true;\n"
	    "  inet4 = true; inet6 = true; internal = false; }\n"
	    "clients { \"org.test.restricted\" { connect = false; } }\n";
	struct resolve_call resolve_call;
	struct fixture fixture;
	struct networkcmp_endpoint endpoint;
	pthread_t thread;
	uint32_t features;
	int error, fd;

	/* The listed label: CONNECT denied by ITS policy, RESOLVE permitted. */
	fixture_create_config(&fixture, config_text, "org.test.restricted");
	features = hello_features(&fixture);
	ATF_CHECK((features & NETWORKCMP_FEATURE_TCP) == 0);
	ATF_CHECK((features & NETWORKCMP_FEATURE_UDP) != 0);
	ATF_CHECK((features & NETWORKCMP_FEATURE_DNS) != 0);
	ipv4_endpoint(&endpoint, 93, 184, 216, 34);
	endpoint.port = 80;
	fd = -1;
	ATF_CHECK_EQ(EACCES, broker_request(&fixture, NETWORKCMP_OP_CONNECT,
	    &endpoint, &fd));
	ATF_CHECK_EQ(-1, fd);
	memset(&resolve_call, 0, sizeof(resolve_call));
	resolve_call.fixture = &fixture;
	error = pthread_create(&thread, NULL, resolve_call_thread,
	    &resolve_call);
	ATF_REQUIRE_EQ_MSG(0, error, "pthread_create: %s", strerror(error));
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ(0, resolve_call.error);
	/* The testing resolver stub's status — NOT a policy EACCES. */
	ATF_CHECK_EQ(EOPNOTSUPP, resolve_call.status);
	fixture_destroy(&fixture, 0);

	/*
	 * An unlisted sibling label under the same config keeps the default
	 * outbound grant: TCP is negotiated again.  (A live connect proof
	 * would need an external destination — the SSRF guard still denies
	 * internal ranges — so the feature bit, which is derived from the
	 * same immutable policy connect checks consult, stands in.)
	 */
	fixture_create_config(&fixture, config_text, "org.test.unlisted");
	features = hello_features(&fixture);
	ATF_CHECK((features & NETWORKCMP_FEATURE_TCP) != 0);
	fixture_destroy(&fixture, 0);
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
	ATF_CHECK_ERRNO(EINVAL,
	    networkcmp_test_serve(0, NULL, &policy, "") == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, endpoint_internal_ranges_are_blocked);
	ATF_TP_ADD_TC(tp, provider_hello);
	ATF_TP_ADD_TC(tp, provider_connect_returns_fd);
	ATF_TP_ADD_TC(tp, provider_udp_returns_fd);
	ATF_TP_ADD_TC(tp, provider_connect_denied);
	ATF_TP_ADD_TC(tp, provider_connect_refused);
	ATF_TP_ADD_TC(tp, provider_malformed_channel);
	ATF_TP_ADD_TC(tp, provider_resolver_does_not_block_session);
	ATF_TP_ADD_TC(tp, provider_resolver_deadline_terminates_session);
	ATF_TP_ADD_TC(tp, non_admin_connect_to_loopback_is_denied);
	ATF_TP_ADD_TC(tp, per_label_config_denies_connect_allows_resolve);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
