/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <libcasper.h>
#include <casper/cap_net.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>
#include <networkcmp.h>

#include "networkcmp_probes.h"
#include "io.h"
#include "policy.h"
#include "session.h"

#define	NETWORKCMP_PROVIDER_NAME	"org.5bsd.NetworkCmp"

union provider_buffer {
	max_align_t align;
	struct {
		struct networkcmp_msg msg;
		uint8_t payload[NETWORKCMP_MAX_MESSAGE -
		    sizeof(struct networkcmp_msg)];
	} wire;
};

struct session_state {
	cap_channel_t		*capnet;
	struct networkcmp_policy policy;
	struct networkcmp_session sockets;
	const char		*label;
	int			 terminal_error;
};

static int
endpoint_sockaddr(const struct networkcmp_endpoint *endpoint,
    struct sockaddr_storage *storage, socklen_t *length)
{

	memset(storage, 0, sizeof(*storage));
	if (endpoint->family == NETWORKCMP_AF_INET4) {
		struct sockaddr_in *sin;

		sin = (void *)storage;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_port = htons(endpoint->port);
		memcpy(&sin->sin_addr, endpoint->address, sizeof(sin->sin_addr));
		*length = sizeof(*sin);
		return (0);
	}
	if (endpoint->family == NETWORKCMP_AF_INET6) {
		struct sockaddr_in6 *sin6;

		sin6 = (void *)storage;
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(endpoint->port);
		sin6->sin6_scope_id = endpoint->scope_id;
		memcpy(&sin6->sin6_addr, endpoint->address,
		    sizeof(sin6->sin6_addr));
		*length = sizeof(*sin6);
		return (0);
	}
	errno = EAFNOSUPPORT;
	return (-1);
}

static int
endpoint_request(struct session_state *state, uint16_t opcode,
    const struct networkcmp_endpoint_request *request)
{
	struct sockaddr_storage storage;
	struct networkcmp_session_socket *socket;
	socklen_t length;

	socket = networkcmp_session_lookup(&state->sockets, request->socket);
	if (socket == NULL)
		return (-1);
	if ((socket->family == NETWORKCMP_AF_INET4 &&
	    request->endpoint.family != NETWORKCMP_AF_INET4) ||
	    (socket->family == NETWORKCMP_AF_INET6 &&
	    request->endpoint.family != NETWORKCMP_AF_INET6)) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	if (endpoint_sockaddr(&request->endpoint, &storage, &length) == -1)
		return (-1);
	if (opcode == NETWORKCMP_OP_BIND)
		return (cap_bind(state->capnet, socket->fd,
		    (const void *)&storage, length));
	if (cap_connect(state->capnet, socket->fd,
	    (const void *)&storage, length) == 0) {
		socket->connect_started = true;
		socket->connect_complete = true;
		return (0);
	}
	if (errno == EINPROGRESS)
		socket->connect_started = true;
	return (-1);
}

static void
audit_policy(const char *label, const char *operation, int error)
{

	(void)audit_submit((short)AUE_NETWORKCMP_POLICY, getuid(), (char)error,
	    error != 0, "client=%s operation=%s result=%d", label, operation,
	    error);
}

/*
 * Casper's master channel is factory authority.  It must remain in the
 * provider and must never cross either a fork or exec boundary.
 */
static int
harden_factory_channel(cap_channel_t *channel)
{
	int fd;

	fd = cap_sock(channel);
	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

/*
 * A limited per-session channel crosses exactly the worker pdfork.  The
 * CAP_CLOFORK_ONCE transition locks it in both processes after that fork.
 */
static int
harden_worker_channel(cap_channel_t *channel)
{
	int fd;

	fd = cap_sock(channel);
	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static int
harden_worker_fd(int fd)
{

	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static int
send_reply(struct channel_message *request_message,
    const struct networkcmp_msg *request, int error, const void *payload,
    size_t payload_length)
{
	union provider_buffer buffer;
	struct networkcmp_msg *reply;
	size_t length;

	memset(&buffer, 0, sizeof(buffer));
	reply = &buffer.wire.msg;
	if (networkcmp_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1)
		return (-1);
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	if (networkcmp_validate_message(reply, length,
	    NETWORKCMP_MESSAGE_REPLY) == -1 ||
	    networkcmp_validate_fds(reply, 0, NETWORKCMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(reply, length)));
}

static int
gai_to_errno(int error)
{

	switch (error) {
	case 0:
		return (0);
	case EAI_AGAIN:
		return (EAGAIN);
	case EAI_MEMORY:
		return (ENOMEM);
	case EAI_NONAME:
		return (ENOENT);
	case EAI_SERVICE:
	case EAI_SOCKTYPE:
		return (EPROTONOSUPPORT);
	case EAI_SYSTEM:
		return (errno != 0 ? errno : EIO);
	default:
		return (EIO);
	}
}

static int
resolve_request(struct channel_message *request_message,
    cap_channel_t *capnet,
    const struct networkcmp_policy *policy, const struct networkcmp_msg *message,
    const char *label)
{
	union provider_buffer reply_buffer;
	const struct networkcmp_resolve_request *request;
	struct networkcmp_resolve_reply *reply;
	struct networkcmp_resolve_result *results;
	struct addrinfo hints, *addresses, *ai;
	const char *wire;
	char host[NETWORKCMP_NAME_MAX + 1];
	char service[NETWORKCMP_SERVICE_MAX + 1];
	char *canonical;
	size_t canonical_length, payload_length;
	uint32_t count, maximum;
	int error;

	request = (const void *)(message + 1);
	wire = (const char *)(request + 1);
	memcpy(host, wire, request->host_length);
	host[request->host_length] = '\0';
	memcpy(service, wire + request->host_length, request->service_length);
	service[request->service_length] = '\0';
	if ((request->family == NETWORKCMP_AF_INET4 && !policy->ipv4) ||
	    (request->family == NETWORKCMP_AF_INET6 && !policy->ipv6)) {
		error = EAFNOSUPPORT;
		goto reject;
	}
	memset(&hints, 0, sizeof(hints));
	switch (request->family) {
	case NETWORKCMP_AF_UNSPEC:
		hints.ai_family = AF_UNSPEC;
		break;
	case NETWORKCMP_AF_INET4:
		hints.ai_family = AF_INET;
		break;
	case NETWORKCMP_AF_INET6:
		hints.ai_family = AF_INET6;
		break;
	default:
		error = EAFNOSUPPORT;
		goto reject;
	}
	switch (request->socket_type) {
	case NETWORKCMP_SOCK_ANY:
		hints.ai_socktype = 0;
		break;
	case NETWORKCMP_SOCK_STREAM:
		hints.ai_socktype = SOCK_STREAM;
		break;
	case NETWORKCMP_SOCK_DGRAM:
		hints.ai_socktype = SOCK_DGRAM;
		break;
	default:
		error = EPROTOTYPE;
		goto reject;
	}
	if ((request->flags & NETWORKCMP_RESOLVE_F_PASSIVE) != 0)
		hints.ai_flags |= AI_PASSIVE;
	if ((request->flags & NETWORKCMP_RESOLVE_F_CANONNAME) != 0)
		hints.ai_flags |= AI_CANONNAME;
	if ((request->flags & NETWORKCMP_RESOLVE_F_NUMERIC_HOST) != 0)
		hints.ai_flags |= AI_NUMERICHOST;
	if ((request->flags & NETWORKCMP_RESOLVE_F_NUMERIC_SERVICE) != 0)
		hints.ai_flags |= AI_NUMERICSERV;

	NETWORKCMP_PROVIDER_RESOLVE_START(__DECONST(char *, label), host);
	addresses = NULL;
	error = cap_getaddrinfo(capnet, request->host_length != 0 ? host : NULL,
	    request->service_length != 0 ? service : NULL, &hints, &addresses);
	if (error != 0) {
		error = gai_to_errno(error);
		goto reject_probe;
	}
	memset(&reply_buffer, 0, sizeof(reply_buffer));
	reply = (void *)reply_buffer.wire.payload;
	results = (void *)(reply + 1);
	maximum = MIN(request->max_results, policy->max_results);
	canonical = NULL;
	count = 0;
	for (ai = addresses; ai != NULL && count < maximum; ai = ai->ai_next) {
		struct networkcmp_resolve_result *result;

		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		result = &results[count];
		result->endpoint.family = ai->ai_family == AF_INET ?
		    NETWORKCMP_AF_INET4 : NETWORKCMP_AF_INET6;
		result->socket_type = ai->ai_socktype == SOCK_STREAM ?
		    NETWORKCMP_SOCK_STREAM : ai->ai_socktype == SOCK_DGRAM ?
		    NETWORKCMP_SOCK_DGRAM : NETWORKCMP_SOCK_ANY;
		result->protocol = (uint32_t)ai->ai_protocol;
		if (ai->ai_family == AF_INET) {
			const struct sockaddr_in *sin = (const void *)ai->ai_addr;

			result->endpoint.port = ntohs(sin->sin_port);
			memcpy(result->endpoint.address, &sin->sin_addr,
			    sizeof(sin->sin_addr));
		} else {
			const struct sockaddr_in6 *sin6 = (const void *)ai->ai_addr;

			result->endpoint.port = ntohs(sin6->sin6_port);
			result->endpoint.scope_id = sin6->sin6_scope_id;
			memcpy(result->endpoint.address, &sin6->sin6_addr,
			    sizeof(sin6->sin6_addr));
		}
		if (canonical == NULL && ai->ai_canonname != NULL)
			canonical = ai->ai_canonname;
		count++;
	}
	canonical_length = canonical != NULL ? strlen(canonical) : 0;
	if (canonical_length > NETWORKCMP_CANONNAME_MAX)
		canonical_length = NETWORKCMP_CANONNAME_MAX;
	reply->result_count = count;
	reply->canonname_length = (uint32_t)canonical_length;
	/* cap_net/getaddrinfo does not expose DNS TTLs; zero means unknown. */
	reply->ttl_seconds = 0;
	if (canonical_length != 0)
		memcpy(results + count, canonical, canonical_length);
	payload_length = sizeof(*reply) + count * sizeof(*results) +
	    canonical_length;
	freeaddrinfo(addresses);
	NETWORKCMP_PROVIDER_RESOLVE_DONE(__DECONST(char *, label), count, 0);
	audit_policy(label, "resolve", 0);
	return (send_reply(request_message, message, 0, reply,
	    payload_length));

reject_probe:
	NETWORKCMP_PROVIDER_RESOLVE_DONE(__DECONST(char *, label), 0, error);
reject:
	audit_policy(label, "resolve", error);
	return (send_reply(request_message, message, error, NULL, 0));
}

static int
dispatch(struct channel_message *request_message,
    struct session_state *state, const struct networkcmp_msg *message,
    const char *label)
{
	const struct networkcmp_close_request *close_request;
	const struct networkcmp_endpoint_request *endpoint;
	const struct networkcmp_listen_request *listen_request;
	const struct networkcmp_shutdown_request *shutdown_request;
	const struct networkcmp_socket_request *create_request;
	const struct networkcmp_setopt_request *setopt_request;
	const struct networkcmp_inline_request *inline_request;
	struct networkcmp_handle_reply handle_reply;
	union provider_buffer inline_reply;
	struct networkcmp_inline_reply *inline_result;
	struct networkcmp_hello_reply hello;
	struct networkcmp_session_socket *socket;
	int accepted, error;

	switch (message->opcode) {
	case NETWORKCMP_OP_HELLO:
		memset(&hello, 0, sizeof(hello));
		hello.version = NETWORKCMP_ABI_VERSION;
		/*
		 * TCP and UDP are available through bounded inline operations.
		 * Shared rings remain a separately negotiated future fast path.
		 */
		hello.features = NETWORKCMP_FEATURE_DNS |
		    NETWORKCMP_FEATURE_TCP | NETWORKCMP_FEATURE_UDP |
		    (state->policy.ipv6 ? NETWORKCMP_FEATURE_IPV6 : 0);
		hello.max_sockets = state->policy.max_sockets;
		hello.max_ring_size = 0;
		return (send_reply(request_message, message, 0, &hello,
		    sizeof(hello)));
	case NETWORKCMP_OP_SOCKET:
		create_request = (const void *)(message + 1);
		memset(&handle_reply, 0, sizeof(handle_reply));
		if ((create_request->family == NETWORKCMP_AF_INET4 &&
		    !state->policy.ipv4) ||
		    (create_request->family == NETWORKCMP_AF_INET6 &&
		    !state->policy.ipv6))
			error = EAFNOSUPPORT;
		else
			error = networkcmp_session_socket(&state->sockets,
			    create_request, &handle_reply) == -1 ? errno : 0;
		audit_policy(label, "socket", error);
		return (send_reply(request_message, message, error, &handle_reply,
		    sizeof(handle_reply)));
	case NETWORKCMP_OP_BIND:
	case NETWORKCMP_OP_CONNECT:
		endpoint = (const void *)(message + 1);
		if ((message->opcode == NETWORKCMP_OP_BIND &&
		    !state->policy.allow_bind) ||
		    (message->opcode == NETWORKCMP_OP_CONNECT &&
		    !state->policy.allow_connect))
			error = EACCES;
		else
			error = endpoint_request(state, message->opcode,
			    endpoint) == -1 ? errno : 0;
		audit_policy(label, message->opcode == NETWORKCMP_OP_BIND ?
		    "bind" : "connect", error);
		return (send_reply(request_message, message, error, NULL, 0));
	case NETWORKCMP_OP_LISTEN:
		listen_request = (const void *)(message + 1);
		if (!state->policy.allow_bind)
			error = EACCES;
		else {
			socket = networkcmp_session_lookup(&state->sockets,
			    listen_request->socket);
			error = socket == NULL ? errno :
			    (listen(socket->fd, (int)MIN(
			    listen_request->backlog, SOMAXCONN)) == -1 ?
			    errno : 0);
		}
		audit_policy(label, "listen", error);
		return (send_reply(request_message, message, error, NULL, 0));
	case NETWORKCMP_OP_ACCEPT:
		close_request = (const void *)(message + 1);
		socket = NULL;
		accepted = -1;
		if (!state->policy.allow_bind)
			error = EACCES;
		else {
			socket = networkcmp_session_lookup(&state->sockets,
			    close_request->socket);
			accepted = socket == NULL ? -1 :
			    accept4(socket->fd, NULL, NULL,
			    SOCK_CLOEXEC | SOCK_NONBLOCK);
			error = accepted == -1 ? errno : 0;
		}
		memset(&handle_reply, 0, sizeof(handle_reply));
		if (error == 0 && networkcmp_session_allocate(&state->sockets,
		    accepted, socket->family, socket->type,
		    &handle_reply.socket) == -1) {
			error = errno;
			close(accepted);
		}
		if (error == 0) {
			struct networkcmp_session_socket *accepted_socket;

			accepted_socket = networkcmp_session_lookup(&state->sockets,
			    handle_reply.socket);
			if (accepted_socket != NULL) {
				accepted_socket->connect_started = true;
				accepted_socket->connect_complete = true;
			}
		}
		audit_policy(label, "accept", error);
		return (send_reply(request_message, message, error, &handle_reply,
		    sizeof(handle_reply)));
	case NETWORKCMP_OP_CONNECT_STATUS:
		close_request = (const void *)(message + 1);
		error = networkcmp_session_connect_status(&state->sockets,
		    close_request->socket) == -1 ? errno : 0;
		audit_policy(label, "connect-status", error);
		return (send_reply(request_message, message, error, NULL, 0));
	case NETWORKCMP_OP_SETOPT:
		setopt_request = (const void *)(message + 1);
		error = networkcmp_session_setopt(&state->sockets,
		    setopt_request->socket, setopt_request->level,
		    setopt_request->option, setopt_request + 1,
		    setopt_request->value_length) == -1 ? errno : 0;
		audit_policy(label, "setopt", error);
		return (send_reply(request_message, message, error, NULL, 0));
	case NETWORKCMP_OP_SHUTDOWN:
		shutdown_request = (const void *)(message + 1);
		socket = networkcmp_session_lookup(&state->sockets,
		    shutdown_request->socket);
		error = socket == NULL ? errno :
		    (shutdown(socket->fd, (int)shutdown_request->how) == -1 ?
		    errno : 0);
		return (send_reply(request_message, message, error, NULL, 0));
	case NETWORKCMP_OP_CLOSE:
		close_request = (const void *)(message + 1);
		error = networkcmp_session_close(&state->sockets,
		    close_request->socket) == -1 ? errno : 0;
		return (send_reply(request_message, message, error, NULL, 0));
	case NETWORKCMP_OP_SEND:
		inline_request = (const void *)(message + 1);
		inline_result = (void *)inline_reply.wire.payload;
		error = networkcmp_io_send(&state->sockets, inline_request,
		    inline_result) == -1 ?
		    errno : 0;
		audit_policy(label, "send", error);
		return (send_reply(request_message, message, error, inline_result,
		    sizeof(*inline_result)));
	case NETWORKCMP_OP_RECV:
		inline_request = (const void *)(message + 1);
		inline_result = (void *)inline_reply.wire.payload;
		error = networkcmp_io_recv(&state->sockets, inline_request,
		    inline_result,
		    inline_result + 1) == -1 ? errno : 0;
		audit_policy(label, "recv", error);
		return (send_reply(request_message, message, error, inline_result,
		    sizeof(*inline_result) +
		    (error == 0 ? inline_result->length : 0)));
	case NETWORKCMP_OP_RESOLVE:
		return (resolve_request(request_message, state->capnet,
		    &state->policy, message, label));
	default:
		audit_policy(label, "unsupported", EOPNOTSUPP);
		return (send_reply(request_message, message, EOPNOTSUPP, NULL,
		    0));
	}
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *request_message, void *argument)
{
	struct session_state *state;
	const struct networkcmp_msg *message;
	size_t length;

	state = argument;
	message = channel_message_data(request_message);
	length = channel_message_length(request_message);
	if (networkcmp_validate_message(message, length,
	    NETWORKCMP_MESSAGE_REQUEST) == -1 ||
	    networkcmp_validate_fds(message,
	    channel_message_fd_count(request_message),
	    NETWORKCMP_MESSAGE_REQUEST) == -1) {
		state->terminal_error = EPROTO;
		NETWORKCMP_PROVIDER_REJECT(__DECONST(char *, state->label),
		    EPROTO);
		audit_policy(state->label, "malformed-request", EPROTO);
		channel_message_free(request_message);
		return;
	}
	if (dispatch(request_message, state, message, state->label) == -1)
		state->terminal_error = errno;
	channel_message_free(request_message);
}

static int
worker(int fd, int barrier, cap_channel_t *capnet,
    const struct networkcmp_policy *policy, const char *label)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct session_state state;
	struct channel *channel;
	struct pollfd descriptor;
	char byte;
	int error, result, wants_write;

	channel = NULL;
	if (service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC) == -1) {
		error = errno;
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	service_worker_drop_inherited_authority();
	if (cap_enter() == -1) {
		error = errno;
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	NETWORKCMP_PROVIDER_SESSION_START(__DECONST(char *, label),
	    policy->max_results);
	memset(&state, 0, sizeof(state));
	state.capnet = capnet;
	state.policy = *policy;
	state.label = label;
	if (networkcmp_session_init(&state.sockets, policy->max_sockets) == -1)
		return (1);
	if (channel_create(fd, &options, &channel) == -1 ||
	    channel_set_request_handler(channel, handle_request, &state) ==
	    -1) {
		error = errno;
		if (channel != NULL)
			channel_destroy(channel);
		networkcmp_session_destroy(&state.sockets);
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	error = 0;
	if (write(barrier, &error, sizeof(error)) != sizeof(error) ||
	    read(barrier, &byte, 1) != 1) {
		channel_destroy(channel);
		networkcmp_session_destroy(&state.sockets);
		return (1);
	}
	close(barrier);
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel_fd(channel);
		descriptor.events = POLLIN | (wants_write ? POLLOUT : 0);
		do {
			result = poll(&descriptor, 1, -1);
		} while (result == -1 && errno == EINTR);
		if (result == -1)
			break;
		if ((descriptor.revents & POLLOUT) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((descriptor.revents &
		    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
		if (state.terminal_error != 0) {
			errno = state.terminal_error;
			break;
		}
	}
	networkcmp_session_destroy(&state.sockets);
	channel_destroy(channel);
	cap_close(capnet);
	return (0);
}

static int
start_session(int fd, cap_channel_t *casper, const char *peer_label)
{
	struct service_component_bootstrap *bootstrap;
	struct networkcmp_policy policy;
	cap_channel_t *capnet;
	cap_net_limit_t *limit;
	int families[2], mode;
	size_t nfamilies;
	int syncfd[2], pd, child_error, error;
	pid_t pid;
	char byte;
	ssize_t n;

	bootstrap = NULL;
	if (service_component_accept(fd, &bootstrap) == -1)
		return (-1);
	if (service_component_resource_count(bootstrap) != 0) {
		error = EPROTO;
		goto reject;
	}
	if (strcmp(service_component_interface(bootstrap),
	    NETWORKCMP_INTERFACE) != 0 ||
	    strcmp(service_component_interface_version(bootstrap),
	    NETWORKCMP_INTERFACE_VERSION) != 0) {
		error = EOPNOTSUPP;
		goto reject;
	}
	if (harden_worker_fd(fd) == -1) {
		error = errno;
		goto reject;
	}
	if (networkcmp_policy_default(&policy) == -1) {
		error = errno;
		goto reject;
	}
	nfamilies = 0;
	if (policy.ipv4)
		families[nfamilies++] = AF_INET;
	if (policy.ipv6)
		families[nfamilies++] = AF_INET6;
	capnet = cap_service_open(casper, "system.net");
	if (capnet == NULL) {
		error = errno;
		goto reject;
	}
	mode = CAPNET_NAME2ADDR;
	if (policy.allow_connect)
		mode |= CAPNET_CONNECT;
	if (policy.allow_bind)
		mode |= CAPNET_BIND;
	limit = cap_net_limit_init(capnet, mode);
	if (limit == NULL ||
	    cap_net_limit_name2addr_family(limit, families,
	    nfamilies) == NULL ||
	    cap_net_limit(limit) == -1) {
		error = errno;
		cap_close(capnet);
		goto reject;
	}
	if (harden_worker_channel(capnet) == -1) {
		error = errno;
		cap_close(capnet);
		goto reject;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd) == -1) {
		error = errno;
		cap_close(capnet);
		goto reject;
	}
	if (cap_xfer_limit(syncfd[0], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(syncfd[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(syncfd[0], CAP_CLOEXEC_LOCKED) == -1 ||
	    harden_worker_fd(syncfd[1]) == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		cap_close(capnet);
		goto reject;
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		cap_close(capnet);
		goto reject;
	}
	if (pid == 0) {
		close(syncfd[0]);
		cap_close(casper);
		_exit(worker(fd, syncfd[1], capnet, &policy, peer_label));
	}
	cap_close(capnet);
	close(syncfd[1]);
	n = read(syncfd[0], &child_error, sizeof(child_error));
	if (n != sizeof(child_error) || child_error != 0) {
		error = n == sizeof(child_error) ? child_error : EIO;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		goto reject;
	}
	if (service_component_complete(bootstrap,
	    SERVICE_COMPONENT_MEMBER_PROCDESC, pd) == -1) {
		bootstrap = NULL;
		error = errno;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		return (-1);
	}
	bootstrap = NULL;
	close(pd);
	byte = 1;
	(void)write(syncfd[0], &byte, 1);
	close(syncfd[0]);
	audit_policy(peer_label, "session-bootstrap", 0);
	return (0);

reject:
	if (bootstrap != NULL) {
		(void)service_component_fail(bootstrap, error);
		bootstrap = NULL;
	}
	audit_policy(peer_label, "session-bootstrap", error);
	errno = error;
	return (-1);
}

int
main(void)
{
	cap_channel_t *casper;
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	openlog("networkcmp", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	casper = cap_init();
	if (casper == NULL)
		goto fail;
	if (harden_factory_channel(casper) == -1)
		goto fail;
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, NETWORKCMP_PROVIDER_NAME,
	    &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (start_session(fd, casper, identity.client_label) == -1)
			syslog(LOG_WARNING, "session for %s rejected: %m",
			    identity.client_label);
		close(fd);
	}

fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
