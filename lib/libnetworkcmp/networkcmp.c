/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libservice.h>

#include "networkcmp.h"
#include "networkcmp_server.h"
#include "networkcmp_probes.h"

/*
 * Retained in static consumers and available in the shared object so
 * servicectl deps can suggest, but never authorize, manifest requirements.
 */
static const char networkcmp_dependency_note[]
    __attribute__((section(".note.5bsd.descriptors"), used)) =
    "interface=system.Network\n"
    "version=1.0.0\n"
    "local-name=network\n"
    "required=true\n";

union networkcmp_buffer {
	max_align_t align;
	struct {
		struct networkcmp_msg msg;
		uint8_t payload[NETWORKCMP_MAX_MESSAGE -
		    sizeof(struct networkcmp_msg)];
	} wire;
};

struct networkcmp_client {
	struct service_session		*channel;
	struct networkcmp_hello_reply	limits;
	pid_t				 owner;
	uint32_t			 references;
	_Atomic int			 terminal_error;
};

static pthread_mutex_t networkcmp_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t networkcmp_registry_ready = PTHREAD_COND_INITIALIZER;
static pthread_once_t networkcmp_atfork_once = PTHREAD_ONCE_INIT;
static struct networkcmp_client *networkcmp_process_client;
static int networkcmp_atfork_error;
static bool networkcmp_initializing;

static void networkcmp_atfork_prepare(void) __no_lock_analysis;
static void networkcmp_atfork_parent(void) __no_lock_analysis;
static void networkcmp_atfork_child(void) __no_lock_analysis;

static void
networkcmp_atfork_prepare(void)
{

	(void)pthread_mutex_lock(&networkcmp_registry_lock);
}

static void
networkcmp_atfork_parent(void)
{

	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
}

static void
networkcmp_atfork_child(void)
{

	networkcmp_process_client = NULL;
	networkcmp_initializing = false;
	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
}

static void
networkcmp_atfork_init(void)
{

	networkcmp_atfork_error = pthread_atfork(networkcmp_atfork_prepare,
	    networkcmp_atfork_parent, networkcmp_atfork_child);
}

static bool
networkcmp_endpoint_valid(const struct networkcmp_endpoint *endpoint)
{
	static const uint8_t zero[12];

	if (endpoint->prefix != 0)
		return (false);
	switch (endpoint->family) {
	case NETWORKCMP_AF_INET4:
		return (endpoint->scope_id == 0 &&
		    memcmp(endpoint->address + 4, zero, sizeof(zero)) == 0);
	case NETWORKCMP_AF_INET6:
		return (true);
	default:
		return (false);
	}
}

static int
networkcmp_header_validate(const struct networkcmp_msg *msg, size_t received,
    enum networkcmp_message_role role)
{

	if (msg == NULL || received < sizeof(*msg) ||
	    received > NETWORKCMP_MAX_MESSAGE ||
	    (role != NETWORKCMP_MESSAGE_REQUEST &&
	    role != NETWORKCMP_MESSAGE_REPLY &&
	    role != NETWORKCMP_MESSAGE_EVENT) ||
	    msg->magic != NETWORKCMP_MAGIC ||
	    msg->version != NETWORKCMP_ABI_VERSION ||
	    msg->opcode < NETWORKCMP_OP_HELLO ||
	    msg->opcode > NETWORKCMP_OP_UDP ||
	    (msg->flags & ~NETWORKCMP_MSG_F_MASK) != 0 ||
	    (role != NETWORKCMP_MESSAGE_REPLY && msg->status != 0) ||
	    (role == NETWORKCMP_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
networkcmp_message_init(struct networkcmp_msg *msg, uint16_t opcode,
    uint32_t flags)
{

	if (msg == NULL || opcode < NETWORKCMP_OP_HELLO ||
	    opcode > NETWORKCMP_OP_UDP ||
	    (flags & ~NETWORKCMP_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = NETWORKCMP_MAGIC;
	msg->version = NETWORKCMP_ABI_VERSION;
	msg->opcode = opcode;
	msg->flags = flags;
	return (0);
}

int
networkcmp_message_init_reply(struct networkcmp_msg *reply,
    const struct networkcmp_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    networkcmp_header_validate(request, sizeof(*request),
	    NETWORKCMP_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = NETWORKCMP_MAGIC;
	reply->version = NETWORKCMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
networkcmp_validate_message(const struct networkcmp_msg *msg,
    size_t received, enum networkcmp_message_role role)
{
	size_t payload, expected;
	uint16_t probe_opcode;

	probe_opcode = msg != NULL ? msg->opcode : 0;
	if (networkcmp_header_validate(msg, received, role) == -1)
		goto reject;
	payload = received - sizeof(*msg);
	if (role == NETWORKCMP_MESSAGE_EVENT)
		goto reject;
	if (role == NETWORKCMP_MESSAGE_REPLY && msg->status != 0)
		expected = 0;
	else if (role == NETWORKCMP_MESSAGE_REPLY) {
		switch (msg->opcode) {
		case NETWORKCMP_OP_HELLO: {
			const struct networkcmp_hello_reply *hello;

			expected = sizeof(struct networkcmp_hello_reply);
			if (payload == expected) {
				hello = (const void *)(msg + 1);
				if (hello->version != NETWORKCMP_ABI_VERSION ||
				    hello->reserved != 0 ||
				    (hello->features &
				    ~(NETWORKCMP_FEATURE_TCP |
				    NETWORKCMP_FEATURE_UDP |
				    NETWORKCMP_FEATURE_IPV6 |
				    NETWORKCMP_FEATURE_DNS)) != 0 ||
				    hello->max_resolve_results == 0 ||
				    hello->max_resolve_results >
				    NETWORKCMP_RESOLVE_MAX_RESULTS)
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_CONNECT:
		case NETWORKCMP_OP_UDP:
			/* The connected descriptor arrives out of band. */
			expected = 0;
			break;
		case NETWORKCMP_OP_RESOLVE: {
			const struct networkcmp_resolve_reply *resolve;
			const struct networkcmp_resolve_result *results;
			const char *canonname;
			size_t entries;
			uint32_t i;

			if (payload < sizeof(*resolve))
				goto reject;
			resolve = (const void *)(msg + 1);
			if (resolve->reserved != 0 ||
			    resolve->result_count >
			    NETWORKCMP_RESOLVE_MAX_RESULTS ||
			    resolve->canonname_length >
			    NETWORKCMP_CANONNAME_MAX)
				goto reject;
			entries = (size_t)resolve->result_count *
			    sizeof(struct networkcmp_resolve_result);
			expected = sizeof(*resolve) + entries +
			    resolve->canonname_length;
			if (payload != expected)
				goto reject;
			results = (const void *)(resolve + 1);
			for (i = 0; i < resolve->result_count; i++)
				if (!networkcmp_endpoint_valid(
				    &results[i].endpoint) ||
				    results[i].socket_type >
				    NETWORKCMP_SOCK_DGRAM)
					goto reject;
			canonname = (const char *)(results +
			    resolve->result_count);
			if (memchr(canonname, '\0',
			    resolve->canonname_length) != NULL)
				goto reject;
			break;
		}
		default:
			expected = 0;
			break;
		}
	} else {
		switch (msg->opcode) {
		case NETWORKCMP_OP_HELLO: {
			const struct networkcmp_hello *hello;

			expected = sizeof(struct networkcmp_hello);
			if (payload == expected) {
				hello = (const void *)(msg + 1);
				if (hello->reserved != 0 ||
				    hello->min_version > hello->max_version ||
				    hello->min_version >
				    NETWORKCMP_ABI_VERSION ||
				    hello->max_version <
				    NETWORKCMP_ABI_VERSION ||
				    (hello->features &
				    ~(NETWORKCMP_FEATURE_TCP |
				    NETWORKCMP_FEATURE_UDP |
				    NETWORKCMP_FEATURE_IPV6 |
				    NETWORKCMP_FEATURE_DNS)) != 0)
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_CONNECT:
		case NETWORKCMP_OP_UDP: {
			const struct networkcmp_connect_request *connect;

			expected = sizeof(struct networkcmp_connect_request);
			if (payload == expected) {
				connect = (const void *)(msg + 1);
				if (!networkcmp_endpoint_valid(
				    &connect->endpoint))
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_RESOLVE: {
			const struct networkcmp_resolve_request *resolve;

			if (payload < sizeof(*resolve))
				goto reject;
			resolve = (const void *)(msg + 1);
			if (resolve->host_length > NETWORKCMP_NAME_MAX ||
			    resolve->service_length > NETWORKCMP_SERVICE_MAX ||
			    (resolve->host_length == 0 &&
			    resolve->service_length == 0) ||
			    resolve->family > NETWORKCMP_AF_INET6 ||
			    resolve->socket_type > NETWORKCMP_SOCK_DGRAM ||
			    (resolve->flags & ~NETWORKCMP_RESOLVE_F_MASK) != 0 ||
			    resolve->max_results == 0 ||
			    resolve->max_results >
			    NETWORKCMP_RESOLVE_MAX_RESULTS)
				goto reject;
			expected = sizeof(*resolve) + resolve->host_length +
			    resolve->service_length;
			if (payload != expected ||
			    memchr(resolve + 1, '\0',
			    resolve->host_length + resolve->service_length) !=
			    NULL)
				goto reject;
			break;
		}
		default:
			goto reject;
		}
	}
	if (expected > NETWORKCMP_MAX_MESSAGE - sizeof(*msg) ||
	    payload != expected)
		goto reject;
	return (0);

reject:
	errno = EPROTO;
	NETWORKCMP_PROBE_REJECT(probe_opcode, (uint32_t)received, EPROTO);
	return (-1);
}

int
networkcmp_validate_fds(const struct networkcmp_msg *msg, size_t nfds,
    enum networkcmp_message_role role)
{
	size_t expected;

	if (msg == NULL || (role != NETWORKCMP_MESSAGE_REQUEST &&
	    role != NETWORKCMP_MESSAGE_REPLY &&
	    role != NETWORKCMP_MESSAGE_EVENT)) {
		errno = EINVAL;
		return (-1);
	}
	/*
	 * Only a successful CONNECT or UDP reply carries exactly one
	 * descriptor: the connected socket.  Every other message carries none.
	 */
	expected = role == NETWORKCMP_MESSAGE_REPLY && msg->status == 0 &&
	    (msg->opcode == NETWORKCMP_OP_CONNECT ||
	    msg->opcode == NETWORKCMP_OP_UDP) ? 1 : 0;
	if (nfds != expected) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int networkcmp_call(struct networkcmp_client *, uint16_t,
    const void *, size_t, union networkcmp_buffer *, size_t *, int *)
    __no_lock_analysis;

static int
networkcmp_call(struct networkcmp_client *client, uint16_t opcode,
    const void *payload, size_t payload_length,
    union networkcmp_buffer *reply, size_t *reply_length, int *out_fd)
{
	union networkcmp_buffer request;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct networkcmp_msg *msg;
	size_t received, request_length;
	int terminal_error, received_fd;

	if (out_fd != NULL)
		*out_fd = -1;
	received_fd = -1;
	if (client == NULL || client->owner != getpid() ||
	    client->channel == NULL || payload_length >
	    NETWORKCMP_MAX_MESSAGE - sizeof(struct networkcmp_msg) ||
	    (payload_length != 0 && payload == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	terminal_error = atomic_load(&client->terminal_error);
	if (terminal_error != 0)
		return (errno = terminal_error, -1);
	memset(&request, 0, sizeof(request));
	msg = &request.wire.msg;
	if (networkcmp_message_init(msg, opcode, 0) == -1)
		return (-1);
	if (payload_length != 0)
		memcpy(msg + 1, payload, payload_length);
	request_length = sizeof(*msg) + payload_length;
	NETWORKCMP_PROBE_SEND(opcode, (uint32_t)request_length, 0, 0);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = msg;
	outgoing.length = request_length;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(*reply);
	if (out_fd != NULL) {
		incoming.fds = &received_fd;
		incoming.fd_capacity = 1;
	}
	options.timeout_ms = 30000;
	if (service_session_call(client->channel, &outgoing, &incoming,
	    &options) == -1) {
		NETWORKCMP_PROBE_REJECT(opcode, 0, errno);
		return (-1);
	}
	received = incoming.length;
	msg = &reply->wire.msg;
	if (networkcmp_validate_message(msg, received,
	    NETWORKCMP_MESSAGE_REPLY) == -1 ||
	    networkcmp_validate_fds(msg, incoming.nfds,
	    NETWORKCMP_MESSAGE_REPLY) == -1 || msg->opcode != opcode) {
		if (incoming.nfds != 0 && received_fd >= 0)
			(void)close(received_fd);
		errno = EPROTO;
		atomic_store(&client->terminal_error, EPROTO);
		NETWORKCMP_PROBE_REJECT(opcode, (uint32_t)received, EPROTO);
		return (-1);
	}
	NETWORKCMP_PROBE_RECEIVE(opcode, (uint32_t)received,
	    (uint32_t)incoming.nfds, 0);
	if (msg->status != 0) {
		errno = -msg->status;
		return (-1);
	}
	if (out_fd != NULL)
		*out_fd = received_fd;
	*reply_length = (size_t)received;
	return (0);
}

int
networkcmp_hello(struct networkcmp_client *client,
    struct networkcmp_hello_reply *reply_value)
{
	union networkcmp_buffer reply;
	struct networkcmp_hello request;
	size_t length;

	if (client == NULL || reply_value == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.min_version = NETWORKCMP_ABI_VERSION;
	request.max_version = NETWORKCMP_ABI_VERSION;
	request.features = NETWORKCMP_FEATURE_TCP | NETWORKCMP_FEATURE_UDP |
	    NETWORKCMP_FEATURE_IPV6 | NETWORKCMP_FEATURE_DNS;
	if (networkcmp_call(client, NETWORKCMP_OP_HELLO, &request,
	    sizeof(request), &reply, &length, NULL) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

int
networkcmp_client_open(struct networkcmp_client **clientp) __no_lock_analysis
{
	struct networkcmp_client *client;
	int error, fd;

	if (clientp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*clientp = NULL;
	error = pthread_once(&networkcmp_atfork_once, networkcmp_atfork_init);
	if (error == 0)
		error = networkcmp_atfork_error;
	if (error == 0)
		error = pthread_mutex_lock(&networkcmp_registry_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	while (networkcmp_initializing) {
		error = pthread_cond_wait(&networkcmp_registry_ready,
		    &networkcmp_registry_lock);
		if (error != 0) {
			(void)pthread_mutex_unlock(&networkcmp_registry_lock);
			errno = error;
			return (-1);
		}
	}
	if (networkcmp_process_client != NULL) {
		networkcmp_process_client->references++;
		*clientp = networkcmp_process_client;
		(void)pthread_mutex_unlock(&networkcmp_registry_lock);
		return (0);
	}
	networkcmp_initializing = true;
	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		goto fail;
	if (service_open(NETWORKCMP_INTERFACE, &fd) == -1)
		goto fail;
	if (service_session_create(fd, &client->channel) == -1) {
		error = errno;
		close(fd);
		errno = error;
		goto fail;
	}
	client->owner = getpid();
	if (networkcmp_hello(client, &client->limits) == -1)
		goto fail;
	client->references = 1;
	error = pthread_mutex_lock(&networkcmp_registry_lock);
	if (error != 0) {
		errno = error;
		goto fail;
	}
	networkcmp_process_client = client;
	networkcmp_initializing = false;
	*clientp = client;
	(void)pthread_cond_broadcast(&networkcmp_registry_ready);
	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
	NETWORKCMP_PROBE_OPEN(__DECONST(char *, NETWORKCMP_INTERFACE), 0);
	return (0);

fail:
	error = errno;
	if (client != NULL && client->channel != NULL)
		service_session_close(client->channel);
	free(client);
	if (pthread_mutex_lock(&networkcmp_registry_lock) == 0) {
		networkcmp_initializing = false;
		(void)pthread_cond_broadcast(&networkcmp_registry_ready);
		(void)pthread_mutex_unlock(&networkcmp_registry_lock);
	}
	NETWORKCMP_PROBE_OPEN(__DECONST(char *, NETWORKCMP_INTERFACE), error);
	errno = error;
	return (-1);
}

const struct networkcmp_hello_reply *
networkcmp_client_limits(const struct networkcmp_client *client)
{

	if (client == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return (&client->limits);
}

void
networkcmp_client_close(struct networkcmp_client *client) __no_lock_analysis
{
	if (client == NULL)
		return;
	if (pthread_mutex_lock(&networkcmp_registry_lock) != 0)
		return;
	if (client != networkcmp_process_client ||
	    client->owner != getpid() || client->references == 0) {
		(void)pthread_mutex_unlock(&networkcmp_registry_lock);
		return;
	}
	if (--client->references != 0) {
		(void)pthread_mutex_unlock(&networkcmp_registry_lock);
		return;
	}
	/*
	 * Keep the one injected process session alive with no public borrows.
	 * Reopening then reuses the existing managed reader rather than
	 * duplicating a channel receive queue or attempting global discovery.
	 */
	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
}

static int
networkcmp_sockaddr_endpoint(const struct sockaddr *sa, socklen_t salen,
    struct networkcmp_endpoint *endpoint)
{

	if (sa == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(endpoint, 0, sizeof(*endpoint));
	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const void *)sa;

		if (salen < (socklen_t)sizeof(*sin)) {
			errno = EINVAL;
			return (-1);
		}
		endpoint->family = NETWORKCMP_AF_INET4;
		endpoint->port = ntohs(sin->sin_port);
		memcpy(endpoint->address, &sin->sin_addr,
		    sizeof(sin->sin_addr));
		return (0);
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 = (const void *)sa;

		if (salen < (socklen_t)sizeof(*sin6)) {
			errno = EINVAL;
			return (-1);
		}
		endpoint->family = NETWORKCMP_AF_INET6;
		endpoint->port = ntohs(sin6->sin6_port);
		endpoint->scope_id = sin6->sin6_scope_id;
		memcpy(endpoint->address, &sin6->sin6_addr,
		    sizeof(sin6->sin6_addr));
		return (0);
	}
	default:
		errno = EAFNOSUPPORT;
		return (-1);
	}
}

static int
networkcmp_endpoint_op(struct networkcmp_client *client, uint16_t opcode,
    const struct sockaddr *sa, socklen_t salen, int *out_fd)
{
	union networkcmp_buffer reply;
	struct networkcmp_connect_request request;
	size_t length;
	int fd;

	if (out_fd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*out_fd = -1;
	memset(&request, 0, sizeof(request));
	if (networkcmp_sockaddr_endpoint(sa, salen, &request.endpoint) == -1)
		return (-1);
	fd = -1;
	if (networkcmp_call(client, opcode, &request, sizeof(request), &reply,
	    &length, &fd) == -1)
		return (-1);
	if (fd < 0) {
		/* A successful broker reply must carry the connected socket. */
		errno = EPROTO;
		atomic_store(&client->terminal_error, EPROTO);
		return (-1);
	}
	*out_fd = fd;
	return (0);
}

int
networkcmp_connect(struct networkcmp_client *client,
    const struct sockaddr *address, socklen_t address_length, int *out_fd)
{

	return (networkcmp_endpoint_op(client, NETWORKCMP_OP_CONNECT, address,
	    address_length, out_fd));
}

int
networkcmp_udp(struct networkcmp_client *client, const struct sockaddr *peer,
    socklen_t peer_length, int *out_fd)
{

	return (networkcmp_endpoint_op(client, NETWORKCMP_OP_UDP, peer,
	    peer_length, out_fd));
}

int
networkcmp_resolve(struct networkcmp_client *client, const char *host,
    const char *service,
    uint32_t family, uint32_t socket_type, uint32_t flags,
    struct networkcmp_resolve_result *results, size_t *nresults,
    char *canonname, size_t canonname_size, uint32_t *ttl_seconds)
{
	union networkcmp_buffer request, reply;
	struct networkcmp_resolve_request *resolve;
	const struct networkcmp_resolve_reply *resolved;
	const struct networkcmp_resolve_result *wire_results;
	const char *wire_canonname;
	size_t host_length, service_length, capacity, length;

	host_length = host != NULL ? strlen(host) : 0;
	service_length = service != NULL ? strlen(service) : 0;
	if (nresults == NULL || (results == NULL && *nresults != 0) ||
	    host_length > NETWORKCMP_NAME_MAX ||
	    service_length > NETWORKCMP_SERVICE_MAX ||
	    (host_length == 0 && service_length == 0) ||
	    family > NETWORKCMP_AF_INET6 ||
	    socket_type > NETWORKCMP_SOCK_DGRAM ||
	    (flags & ~NETWORKCMP_RESOLVE_F_MASK) != 0 ||
	    *nresults == 0 || *nresults > NETWORKCMP_RESOLVE_MAX_RESULTS ||
	    (canonname == NULL && canonname_size != 0)) {
		errno = EINVAL;
		return (-1);
	}
	capacity = *nresults;
	memset(&request, 0, sizeof(request));
	resolve = (void *)request.wire.payload;
	resolve->host_length = (uint32_t)host_length;
	resolve->service_length = (uint32_t)service_length;
	resolve->family = family;
	resolve->socket_type = socket_type;
	resolve->flags = flags;
	resolve->max_results = (uint32_t)capacity;
	if (host_length != 0)
		memcpy(resolve + 1, host, host_length);
	if (service_length != 0)
		memcpy((char *)(resolve + 1) + host_length, service,
		    service_length);
	if (networkcmp_call(client, NETWORKCMP_OP_RESOLVE, resolve,
	    sizeof(*resolve) + host_length + service_length, &reply,
	    &length, NULL) == -1)
		return (-1);
	resolved = (const void *)(&reply.wire.msg + 1);
	if (resolved->result_count > capacity) {
		errno = EOVERFLOW;
		return (-1);
	}
	wire_results = (const void *)(resolved + 1);
	wire_canonname = (const char *)(wire_results + resolved->result_count);
	if (canonname != NULL &&
	    resolved->canonname_length + 1 > canonname_size) {
		errno = ERANGE;
		return (-1);
	}
	/*
	 * Validate every caller-provided capacity before publishing any output.
	 * A failed call therefore leaves results, counts, TTL and canonname
	 * untouched.
	 */
	memcpy(results, wire_results,
	    resolved->result_count * sizeof(*wire_results));
	if (canonname != NULL) {
		memcpy(canonname, wire_canonname, resolved->canonname_length);
		canonname[resolved->canonname_length] = '\0';
	}
	*nresults = resolved->result_count;
	if (ttl_seconds != NULL)
		*ttl_seconds = resolved->ttl_seconds;
	return (0);
}

struct networkcmp_addrinfo {
	struct addrinfo ai;
	struct sockaddr_storage address;
	char canonical[NETWORKCMP_CANONNAME_MAX + 1];
};

void
networkcmp_freeaddrinfo(struct addrinfo *result)
{
	struct addrinfo *next;

	while (result != NULL) {
		next = result->ai_next;
		free(result);
		result = next;
	}
}

static int
networkcmp_gai_error(int error)
{

	switch (error) {
	case EAGAIN:
		return (EAI_AGAIN);
	case ENOMEM:
		return (EAI_MEMORY);
	case ENOENT:
		return (EAI_NONAME);
	case EAFNOSUPPORT:
		return (EAI_FAMILY);
	case EPROTONOSUPPORT:
	case EPROTOTYPE:
		return (EAI_SERVICE);
	default:
		return (EAI_SYSTEM);
	}
}

int
networkcmp_getaddrinfo(struct networkcmp_client *client, const char *host,
    const char *service,
    const struct addrinfo *hints, struct addrinfo **result)
{
	struct networkcmp_resolve_result resolved[NETWORKCMP_RESOLVE_MAX_RESULTS];
	struct networkcmp_addrinfo *entry;
	struct addrinfo **tail;
	char canonical[NETWORKCMP_CANONNAME_MAX + 1];
	uint32_t family, socket_type, flags;
	size_t count, i;
	int saved_errno;

	if (result == NULL)
		return (EAI_FAIL);
	*result = NULL;
	family = NETWORKCMP_AF_UNSPEC;
	socket_type = NETWORKCMP_SOCK_ANY;
	flags = 0;
	if (hints != NULL) {
		switch (hints->ai_family) {
		case AF_UNSPEC:
			break;
		case AF_INET:
			family = NETWORKCMP_AF_INET4;
			break;
		case AF_INET6:
			family = NETWORKCMP_AF_INET6;
			break;
		default:
			return (EAI_FAMILY);
		}
		switch (hints->ai_socktype) {
		case 0:
			break;
		case SOCK_STREAM:
			socket_type = NETWORKCMP_SOCK_STREAM;
			break;
		case SOCK_DGRAM:
			socket_type = NETWORKCMP_SOCK_DGRAM;
			break;
		default:
			return (EAI_SOCKTYPE);
		}
		switch (hints->ai_protocol) {
		case 0:
			break;
		case IPPROTO_TCP:
			if (socket_type == NETWORKCMP_SOCK_DGRAM)
				return (EAI_SOCKTYPE);
			socket_type = NETWORKCMP_SOCK_STREAM;
			break;
		case IPPROTO_UDP:
			if (socket_type == NETWORKCMP_SOCK_STREAM)
				return (EAI_SOCKTYPE);
			socket_type = NETWORKCMP_SOCK_DGRAM;
			break;
		default:
			return (EAI_SERVICE);
		}
		if ((hints->ai_flags & ~(AI_PASSIVE | AI_CANONNAME |
		    AI_NUMERICHOST | AI_NUMERICSERV)) != 0)
			return (EAI_BADFLAGS);
		if ((hints->ai_flags & AI_PASSIVE) != 0)
			flags |= NETWORKCMP_RESOLVE_F_PASSIVE;
		if ((hints->ai_flags & AI_CANONNAME) != 0)
			flags |= NETWORKCMP_RESOLVE_F_CANONNAME;
		if ((hints->ai_flags & AI_NUMERICHOST) != 0)
			flags |= NETWORKCMP_RESOLVE_F_NUMERIC_HOST;
		if ((hints->ai_flags & AI_NUMERICSERV) != 0)
			flags |= NETWORKCMP_RESOLVE_F_NUMERIC_SERVICE;
	}
	count = nitems(resolved);
	if (networkcmp_resolve(client, host, service, family, socket_type,
	    flags,
	    resolved, &count, canonical, sizeof(canonical), NULL) == -1)
		return (networkcmp_gai_error(errno));
	tail = result;
	for (i = 0; i < count; i++) {
		entry = calloc(1, sizeof(*entry));
		if (entry == NULL) {
			saved_errno = errno;
			networkcmp_freeaddrinfo(*result);
			*result = NULL;
			errno = saved_errno;
			return (EAI_MEMORY);
		}
		entry->ai.ai_family =
		    resolved[i].endpoint.family == NETWORKCMP_AF_INET4 ?
		    AF_INET : AF_INET6;
		entry->ai.ai_socktype =
		    resolved[i].socket_type == NETWORKCMP_SOCK_STREAM ?
		    SOCK_STREAM : resolved[i].socket_type ==
		    NETWORKCMP_SOCK_DGRAM ? SOCK_DGRAM : 0;
		entry->ai.ai_protocol = (int)resolved[i].protocol;
		if (entry->ai.ai_family == AF_INET) {
			struct sockaddr_in *sin = (void *)&entry->address;

			sin->sin_family = AF_INET;
			sin->sin_len = sizeof(*sin);
			sin->sin_port = htons(resolved[i].endpoint.port);
			memcpy(&sin->sin_addr, resolved[i].endpoint.address,
			    sizeof(sin->sin_addr));
			entry->ai.ai_addrlen = sizeof(*sin);
		} else {
			struct sockaddr_in6 *sin6 = (void *)&entry->address;

			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(*sin6);
			sin6->sin6_port = htons(resolved[i].endpoint.port);
			sin6->sin6_scope_id = resolved[i].endpoint.scope_id;
			memcpy(&sin6->sin6_addr, resolved[i].endpoint.address,
			    sizeof(sin6->sin6_addr));
			entry->ai.ai_addrlen = sizeof(*sin6);
		}
		entry->ai.ai_addr = (void *)&entry->address;
		if (i == 0 && canonical[0] != '\0') {
			strlcpy(entry->canonical, canonical,
			    sizeof(entry->canonical));
			entry->ai.ai_canonname = entry->canonical;
		}
		*tail = &entry->ai;
		tail = &entry->ai.ai_next;
	}
	if (*result == NULL)
		return (EAI_NONAME);
	return (0);
}
