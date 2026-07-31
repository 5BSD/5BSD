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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libservice.h>
#include <shmring.h>

#include "networkcmp.h"
#include "networkcmp_probes.h"

/*
 * Retained in static consumers and available in the shared object so
 * servicectl deps can suggest, but never authorize, manifest requirements.
 */
static const char networkcmp_dependency_note[]
    __attribute__((section(".note.5bsd.components"), used)) =
    "interface=org.5bsd.network\n"
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
};

struct networkcmp_io {
	uint32_t		socket_type;
	struct shmring		*tx;
	struct shmring		*rx;
	pthread_mutex_t		tx_lock;
	pthread_mutex_t		rx_lock;
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

static bool
networkcmp_ring_size_valid(uint32_t size)
{

	return (size >= NETWORKCMP_RING_MIN_SIZE &&
	    size <= NETWORKCMP_RING_MAX_SIZE && (size & (size - 1)) == 0);
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
	    msg->opcode > NETWORKCMP_OP_CONNECT_STATUS ||
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
	    opcode > NETWORKCMP_OP_CONNECT_STATUS ||
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
				    NETWORKCMP_FEATURE_SHM_RINGS |
				    NETWORKCMP_FEATURE_QUIC_DATAGRAM |
				    NETWORKCMP_FEATURE_DNS)) != 0)
					goto reject;
				if ((hello->features &
				    NETWORKCMP_FEATURE_SHM_RINGS) == 0) {
					if (hello->max_ring_size != 0 ||
					    hello->tx_ring_size != 0 ||
					    hello->rx_ring_size != 0 ||
					    hello->max_datagram != 0)
						goto reject;
				} else if (!networkcmp_ring_size_valid(
				    hello->max_ring_size) ||
				    !networkcmp_ring_size_valid(
				    hello->tx_ring_size) ||
				    !networkcmp_ring_size_valid(
				    hello->rx_ring_size) ||
				    hello->tx_ring_size >
				    hello->max_ring_size ||
				    hello->rx_ring_size >
				    hello->max_ring_size ||
				    hello->max_datagram == 0 ||
				    hello->max_datagram >
				    MIN(hello->tx_ring_size,
				    hello->rx_ring_size) - sizeof(uint32_t))
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_SOCKET:
		case NETWORKCMP_OP_ACCEPT:
			expected = sizeof(struct networkcmp_handle_reply);
			break;
		case NETWORKCMP_OP_SEND:
			expected = sizeof(struct networkcmp_inline_reply);
			break;
		case NETWORKCMP_OP_RECV: {
			const struct networkcmp_inline_reply *io;

			if (payload < sizeof(*io))
				goto reject;
			io = (const void *)(msg + 1);
			if (io->length > NETWORKCMP_INLINE_MAX ||
			    (io->flags & ~NETWORKCMP_IO_F_MASK) != 0 ||
			    io->reserved[0] != 0 || io->reserved[1] != 0)
				goto reject;
			expected = sizeof(*io) + io->length;
			break;
		}
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
				    hello->reserved2 != 0 ||
				    hello->min_version > hello->max_version ||
				    hello->min_version >
				    NETWORKCMP_ABI_VERSION ||
				    hello->max_version <
				    NETWORKCMP_ABI_VERSION ||
				    (hello->features &
				    ~(NETWORKCMP_FEATURE_TCP |
				    NETWORKCMP_FEATURE_UDP |
				    NETWORKCMP_FEATURE_IPV6 |
				    NETWORKCMP_FEATURE_SHM_RINGS |
				    NETWORKCMP_FEATURE_QUIC_DATAGRAM |
				    NETWORKCMP_FEATURE_DNS)) != 0 ||
				    (hello->preferred_tx_ring_size != 0 &&
				    !networkcmp_ring_size_valid(
				    hello->preferred_tx_ring_size)) ||
				    (hello->preferred_rx_ring_size != 0 &&
				    !networkcmp_ring_size_valid(
				    hello->preferred_rx_ring_size)) ||
				    hello->preferred_max_datagram >
				    NETWORKCMP_RING_MAX_SIZE - sizeof(uint32_t))
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_SOCKET: {
			const struct networkcmp_socket_request *socket;

			expected = sizeof(struct networkcmp_socket_request);
			if (payload == expected) {
				socket = (const void *)(msg + 1);
				if (socket->family < NETWORKCMP_AF_INET4 ||
				    socket->family > NETWORKCMP_AF_INET6 ||
				    socket->type < NETWORKCMP_SOCK_STREAM ||
				    socket->type > NETWORKCMP_SOCK_DGRAM ||
				    socket->flags != 0)
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_BIND:
		case NETWORKCMP_OP_CONNECT: {
			const struct networkcmp_endpoint_request *endpoint;

			expected = sizeof(struct networkcmp_endpoint_request);
			if (payload == expected) {
				endpoint = (const void *)(msg + 1);
				if (!networkcmp_endpoint_valid(
				    &endpoint->endpoint))
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_LISTEN: {
			const struct networkcmp_listen_request *listen;

			expected = sizeof(struct networkcmp_listen_request);
			if (payload == expected) {
				listen = (const void *)(msg + 1);
				if (listen->reserved != 0)
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_ACCEPT:
		case NETWORKCMP_OP_CLOSE:
		case NETWORKCMP_OP_CONNECT_STATUS:
			expected = sizeof(struct networkcmp_close_request);
			break;
		case NETWORKCMP_OP_SETOPT:
			if (payload < sizeof(struct networkcmp_setopt_request))
				goto reject;
			const struct networkcmp_setopt_request *setopt;

			setopt = (const void *)(msg + 1);
			if (setopt->reserved != 0)
				goto reject;
			expected = sizeof(*setopt) + setopt->value_length;
			break;
		case NETWORKCMP_OP_SHUTDOWN: {
			const struct networkcmp_shutdown_request *shutdown;

			expected = sizeof(struct networkcmp_shutdown_request);
			if (payload == expected) {
				shutdown = (const void *)(msg + 1);
				if (shutdown->how > 2 || shutdown->reserved != 0)
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
		case NETWORKCMP_OP_ATTACH_RINGS:
			expected = sizeof(struct networkcmp_ring_request);
			if (payload == expected) {
				const struct networkcmp_ring_request *rings;

				rings = (const void *)(msg + 1);
				if ((rings->tx_mode != SHMRING_MODE_STREAM &&
				    rings->tx_mode != SHMRING_MODE_RECORD) ||
				    rings->rx_mode != rings->tx_mode)
					goto reject;
			}
			break;
		case NETWORKCMP_OP_SEND:
		case NETWORKCMP_OP_RECV: {
			const struct networkcmp_inline_request *io;

			if (payload < sizeof(*io))
				goto reject;
			io = (const void *)(msg + 1);
			if (io->length == 0 || io->length > NETWORKCMP_INLINE_MAX ||
			    io->flags != 0 || io->reserved != 0 ||
			    io->timeout_ms != 0)
				goto reject;
			expected = sizeof(*io) +
			    (msg->opcode == NETWORKCMP_OP_SEND ? io->length : 0);
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

	if (msg == NULL) {
		errno = EINVAL;
		return (-1);
	}
	expected = role == NETWORKCMP_MESSAGE_REQUEST &&
	    msg->opcode == NETWORKCMP_OP_ATTACH_RINGS ?
	    NETWORKCMP_RING_FD_COUNT : 0;
	if (nfds != expected) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int networkcmp_rpc_fds(struct networkcmp_client *, uint16_t,
    const void *, size_t,
    const int *, size_t, union networkcmp_buffer *, size_t *)
    __no_lock_analysis;

static int
networkcmp_rpc_fds(struct networkcmp_client *client, uint16_t opcode,
    const void *payload,
    size_t payload_length, const int *fds, size_t nfds,
    union networkcmp_buffer *reply, size_t *reply_length)
{
	union networkcmp_buffer request;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct networkcmp_msg *msg;
	size_t received, request_length;

	if (client == NULL || client->owner != getpid() ||
	    client->channel == NULL || payload_length >
	    NETWORKCMP_MAX_MESSAGE - sizeof(struct networkcmp_msg) ||
	    (payload_length != 0 && payload == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	msg = &request.wire.msg;
	if (networkcmp_message_init(msg, opcode, 0) == -1)
		return (-1);
	if (payload_length != 0)
		memcpy(msg + 1, payload, payload_length);
	request_length = sizeof(*msg) + payload_length;
	NETWORKCMP_PROBE_SEND(opcode, (uint32_t)request_length,
	    (uint32_t)nfds, 0);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = msg;
	outgoing.length = request_length;
	outgoing.fds = fds;
	outgoing.nfds = nfds;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(*reply);
	options.timeout_ms = 30000;
	if (service_session_call(client->channel, &outgoing, &incoming,
	    &options) == -1) {
		NETWORKCMP_PROBE_REJECT(opcode, 0, errno);
		return (-1);
	}
	received = incoming.length;
	msg = &reply->wire.msg;
	if (incoming.nfds != 0 ||
	    networkcmp_validate_message(msg, received,
	    NETWORKCMP_MESSAGE_REPLY) == -1 ||
	    networkcmp_validate_fds(msg, incoming.nfds,
	    NETWORKCMP_MESSAGE_REPLY) == -1 || msg->opcode != opcode) {
		errno = EPROTO;
		NETWORKCMP_PROBE_REJECT(opcode, (uint32_t)received, EPROTO);
		return (-1);
	}
	NETWORKCMP_PROBE_RECEIVE(opcode, (uint32_t)received,
	    (uint32_t)incoming.nfds, 0);
	if (msg->status != 0) {
		errno = -msg->status;
		return (-1);
	}
	*reply_length = (size_t)received;
	return (0);
}

static int
networkcmp_rpc(struct networkcmp_client *client, uint16_t opcode,
    const void *payload,
    size_t payload_length, union networkcmp_buffer *reply, size_t *reply_length)
{

	return (networkcmp_rpc_fds(client, opcode, payload, payload_length,
	    NULL, 0, reply, reply_length));
}

int
networkcmp_hello(struct networkcmp_client *client,
    struct networkcmp_hello_reply *reply_value)
{

	return (networkcmp_negotiate(client, NULL, reply_value));
}

int
networkcmp_negotiate(struct networkcmp_client *client,
    const struct networkcmp_preferences *preferences,
    struct networkcmp_hello_reply *reply_value)
{
	union networkcmp_buffer reply;
	struct networkcmp_hello request;
	size_t length;

	if (reply_value == NULL ||
	    (preferences != NULL && (preferences->reserved != 0 ||
	    (preferences->tx_ring_size != 0 &&
	    !networkcmp_ring_size_valid(preferences->tx_ring_size)) ||
	    (preferences->rx_ring_size != 0 &&
	    !networkcmp_ring_size_valid(preferences->rx_ring_size)) ||
	    preferences->max_datagram >
	    NETWORKCMP_RING_MAX_SIZE - sizeof(uint32_t)))) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.min_version = NETWORKCMP_ABI_VERSION;
	request.max_version = NETWORKCMP_ABI_VERSION;
	request.features = NETWORKCMP_FEATURE_TCP | NETWORKCMP_FEATURE_UDP |
	    NETWORKCMP_FEATURE_IPV6 | NETWORKCMP_FEATURE_SHM_RINGS |
	    NETWORKCMP_FEATURE_QUIC_DATAGRAM | NETWORKCMP_FEATURE_DNS;
	if (preferences != NULL) {
		request.preferred_tx_ring_size = preferences->tx_ring_size;
		request.preferred_rx_ring_size = preferences->rx_ring_size;
		request.preferred_max_datagram = preferences->max_datagram;
	}
	if (networkcmp_rpc(client, NETWORKCMP_OP_HELLO, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

int
networkcmp_client_open(const struct networkcmp_preferences *preferences,
    struct networkcmp_client **clientp) __no_lock_analysis
{
	struct networkcmp_client *client;
	struct service_context *service;
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
	if (service_acquire(&service) == -1)
		goto fail;
	if (service_local_component_open(service, NETWORKCMP_INTERFACE,
	    NETWORKCMP_INTERFACE_VERSION, &fd) == -1) {
		error = errno;
		service_release(service);
		errno = error;
		goto fail;
	}
	service_release(service);
	if (service_session_create(fd, &client->channel) == -1) {
		error = errno;
		close(fd);
		errno = error;
		goto fail;
	}
	client->owner = getpid();
	if (networkcmp_negotiate(client, preferences, &client->limits) == -1)
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
	struct service_session *channel;

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
	networkcmp_process_client = NULL;
	channel = client->channel;
	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
	service_session_close(channel);
	free(client);
}

static void
networkcmp_flatten_fds(const struct shmring_fds *rings, int fds[SHMRING_NFDS])
{

	fds[0] = rings->config_fd;
	fds[1] = rings->data_fd;
	fds[2] = rings->head_fd;
	fds[3] = rings->tail_fd;
}

int
networkcmp_attach_io(struct networkcmp_client *client,
    struct networkcmp_handle socket, uint32_t socket_type,
    struct networkcmp_io **iop)
{
	union networkcmp_buffer reply;
	struct networkcmp_ring_request request;
	struct shmring_fds tx_producer, tx_consumer;
	struct shmring_fds rx_producer, rx_consumer;
	struct networkcmp_io *io;
	int fds[NETWORKCMP_RING_FDS];
	uint32_t max_record, mode;
	size_t length;
	int error, rx_mutex_ready, tx_mutex_ready;

	if (client == NULL || iop == NULL ||
	    (socket_type != NETWORKCMP_SOCK_STREAM &&
	    socket_type != NETWORKCMP_SOCK_DGRAM) ||
	    (client->limits.features & NETWORKCMP_FEATURE_SHM_RINGS) == 0) {
		errno = EINVAL;
		return (-1);
	}
	*iop = NULL;
	mode = socket_type == NETWORKCMP_SOCK_STREAM ?
	    SHMRING_MODE_STREAM : SHMRING_MODE_RECORD;
	max_record = mode == SHMRING_MODE_RECORD ?
	    client->limits.max_datagram : 0;
	memset(&tx_producer, -1, sizeof(tx_producer));
	memset(&tx_consumer, -1, sizeof(tx_consumer));
	memset(&rx_producer, -1, sizeof(rx_producer));
	memset(&rx_consumer, -1, sizeof(rx_consumer));
	io = calloc(1, sizeof(*io));
	if (io == NULL)
		return (-1);
	tx_mutex_ready = 0;
	rx_mutex_ready = 0;
	if (shmring_create(client->limits.tx_ring_size, mode, max_record,
	    socket.generation, &tx_producer, &tx_consumer) == -1 ||
	    shmring_create(client->limits.rx_ring_size, mode, max_record,
	    socket.generation, &rx_producer, &rx_consumer) == -1 ||
	    shmring_open(&io->tx, &tx_producer, SHMRING_ROLE_PRODUCER) == -1 ||
	    shmring_open(&io->rx, &rx_consumer, SHMRING_ROLE_CONSUMER) == -1)
		goto fail;
	networkcmp_flatten_fds(&tx_consumer, fds);
	networkcmp_flatten_fds(&rx_producer, fds + SHMRING_NFDS);
	memset(&request, 0, sizeof(request));
	request.socket = socket;
	request.tx_mode = mode;
	request.rx_mode = mode;
	if (networkcmp_rpc_fds(client, NETWORKCMP_OP_ATTACH_RINGS,
	    &request, sizeof(request), fds, nitems(fds), &reply, &length) == -1)
		goto fail;
	error = pthread_mutex_init(&io->tx_lock, NULL);
	if (error != 0) {
		errno = error;
		goto fail;
	}
	tx_mutex_ready = 1;
	error = pthread_mutex_init(&io->rx_lock, NULL);
	if (error != 0) {
		errno = error;
		goto fail;
	}
	rx_mutex_ready = 1;
	io->socket_type = socket_type;
	shmring_fds_close(&tx_producer);
	shmring_fds_close(&tx_consumer);
	shmring_fds_close(&rx_producer);
	shmring_fds_close(&rx_consumer);
	*iop = io;
	return (0);

fail:
	error = errno;
	if (rx_mutex_ready)
		(void)pthread_mutex_destroy(&io->rx_lock);
	if (tx_mutex_ready)
		(void)pthread_mutex_destroy(&io->tx_lock);
	shmring_close(io->tx);
	shmring_close(io->rx);
	free(io);
	shmring_fds_close(&tx_producer);
	shmring_fds_close(&tx_consumer);
	shmring_fds_close(&rx_producer);
	shmring_fds_close(&rx_consumer);
	errno = error;
	return (-1);
}

ssize_t
networkcmp_write(struct networkcmp_io *io, const void *buffer, size_t length)
    __no_lock_analysis
{
	ssize_t result;
	int error;

	if (io == NULL || io->socket_type != NETWORKCMP_SOCK_STREAM) {
		errno = EINVAL;
		return (-1);
	}
	error = pthread_mutex_lock(&io->tx_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = shmring_write(io->tx, buffer, length);
	error = errno;
	(void)pthread_mutex_unlock(&io->tx_lock);
	errno = error;
	return (result);
}

ssize_t
networkcmp_read(struct networkcmp_io *io, void *buffer, size_t capacity)
    __no_lock_analysis
{
	ssize_t result;
	int error;

	if (io == NULL || io->socket_type != NETWORKCMP_SOCK_STREAM) {
		errno = EINVAL;
		return (-1);
	}
	error = pthread_mutex_lock(&io->rx_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = shmring_read(io->rx, buffer, capacity);
	error = errno;
	(void)pthread_mutex_unlock(&io->rx_lock);
	errno = error;
	return (result);
}

int
networkcmp_send_datagram(struct networkcmp_io *io, const void *buffer,
    size_t length) __no_lock_analysis
{
	int result, error;

	if (io == NULL || io->socket_type != NETWORKCMP_SOCK_DGRAM) {
		errno = EINVAL;
		return (-1);
	}
	error = pthread_mutex_lock(&io->tx_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = shmring_write_record(io->tx, buffer, length);
	error = errno;
	(void)pthread_mutex_unlock(&io->tx_lock);
	errno = error;
	return (result);
}

ssize_t
networkcmp_recv_datagram(struct networkcmp_io *io, void *buffer,
    size_t capacity) __no_lock_analysis
{
	ssize_t result;
	int error;

	if (io == NULL || io->socket_type != NETWORKCMP_SOCK_DGRAM) {
		errno = EINVAL;
		return (-1);
	}
	error = pthread_mutex_lock(&io->rx_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = shmring_read_record(io->rx, buffer, capacity);
	error = errno;
	(void)pthread_mutex_unlock(&io->rx_lock);
	errno = error;
	return (result);
}

void
networkcmp_io_close(struct networkcmp_io *io)
{

	if (io == NULL)
		return;
	(void)pthread_mutex_destroy(&io->tx_lock);
	(void)pthread_mutex_destroy(&io->rx_lock);
	shmring_close(io->tx);
	shmring_close(io->rx);
	free(io);
}

int
networkcmp_socket(struct networkcmp_client *client, uint32_t family,
    uint32_t type, uint32_t protocol, uint32_t flags,
    struct networkcmp_handle *socket)
{
	union networkcmp_buffer reply;
	struct networkcmp_socket_request request;
	const struct networkcmp_handle_reply *result;
	size_t length;

	if (socket == NULL || family < NETWORKCMP_AF_INET4 ||
	    family > NETWORKCMP_AF_INET6 || type < NETWORKCMP_SOCK_STREAM ||
	    type > NETWORKCMP_SOCK_DGRAM) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.family = family;
	request.type = type;
	request.protocol = protocol;
	request.flags = flags;
	if (networkcmp_rpc(client, NETWORKCMP_OP_SOCKET, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	result = (const void *)(&reply.wire.msg + 1);
	*socket = result->socket;
	return (0);
}

static int
networkcmp_endpoint_rpc(struct networkcmp_client *client, uint16_t opcode,
    struct networkcmp_handle socket,
    const struct networkcmp_endpoint *endpoint)
{
	union networkcmp_buffer reply;
	struct networkcmp_endpoint_request request;
	size_t length;

	if (endpoint == NULL ||
	    (endpoint->family != NETWORKCMP_AF_INET4 &&
	    endpoint->family != NETWORKCMP_AF_INET6)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.socket = socket;
	request.endpoint = *endpoint;
	return (networkcmp_rpc(client, opcode, &request, sizeof(request),
	    &reply, &length));
}

int
networkcmp_bind(struct networkcmp_client *client,
    struct networkcmp_handle socket,
    const struct networkcmp_endpoint *endpoint)
{

	return (networkcmp_endpoint_rpc(client, NETWORKCMP_OP_BIND, socket,
	    endpoint));
}

int
networkcmp_connect(struct networkcmp_client *client,
    struct networkcmp_handle socket,
    const struct networkcmp_endpoint *endpoint)
{

	return (networkcmp_endpoint_rpc(client, NETWORKCMP_OP_CONNECT, socket,
	    endpoint));
}

int
networkcmp_connect_status(struct networkcmp_client *client,
    struct networkcmp_handle socket)
{
	union networkcmp_buffer reply;
	struct networkcmp_close_request request;
	size_t length;

	memset(&request, 0, sizeof(request));
	request.socket = socket;
	return (networkcmp_rpc(client, NETWORKCMP_OP_CONNECT_STATUS, &request,
	    sizeof(request), &reply, &length));
}

int
networkcmp_listen(struct networkcmp_client *client,
    struct networkcmp_handle socket, uint32_t backlog)
{
	union networkcmp_buffer reply;
	struct networkcmp_listen_request request;
	size_t length;

	memset(&request, 0, sizeof(request));
	request.socket = socket;
	request.backlog = backlog;
	return (networkcmp_rpc(client, NETWORKCMP_OP_LISTEN, &request,
	    sizeof(request), &reply, &length));
}

int
networkcmp_accept(struct networkcmp_client *client,
    struct networkcmp_handle socket,
    struct networkcmp_handle *accepted)
{
	union networkcmp_buffer reply;
	struct networkcmp_close_request request;
	const struct networkcmp_handle_reply *result;
	size_t length;

	if (accepted == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.socket = socket;
	if (networkcmp_rpc(client, NETWORKCMP_OP_ACCEPT, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	result = (const void *)(&reply.wire.msg + 1);
	*accepted = result->socket;
	return (0);
}

int
networkcmp_setopt(struct networkcmp_client *client,
    struct networkcmp_handle socket, uint32_t level, uint32_t option,
    const void *value, size_t value_length)
{
	union networkcmp_buffer request, reply;
	struct networkcmp_setopt_request *setopt;
	size_t length;

	if (value_length > NETWORKCMP_MAX_MESSAGE -
	    sizeof(struct networkcmp_msg) - sizeof(*setopt) ||
	    (value_length != 0 && value == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	setopt = (void *)request.wire.payload;
	setopt->socket = socket;
	setopt->level = level;
	setopt->option = option;
	setopt->value_length = (uint32_t)value_length;
	if (value_length != 0)
		memcpy(setopt + 1, value, value_length);
	return (networkcmp_rpc(client, NETWORKCMP_OP_SETOPT, setopt,
	    sizeof(*setopt) + value_length, &reply, &length));
}

int
networkcmp_shutdown(struct networkcmp_client *client,
    struct networkcmp_handle socket, uint32_t how)
{
	union networkcmp_buffer reply;
	struct networkcmp_shutdown_request request;
	size_t length;

	memset(&request, 0, sizeof(request));
	request.socket = socket;
	request.how = how;
	return (networkcmp_rpc(client, NETWORKCMP_OP_SHUTDOWN, &request,
	    sizeof(request), &reply, &length));
}

int
networkcmp_close_socket(struct networkcmp_client *client,
    struct networkcmp_handle socket)
{
	union networkcmp_buffer reply;
	struct networkcmp_close_request request;
	size_t length;

	memset(&request, 0, sizeof(request));
	request.socket = socket;
	return (networkcmp_rpc(client, NETWORKCMP_OP_CLOSE, &request,
	    sizeof(request), &reply, &length));
}

ssize_t
networkcmp_send_inline(struct networkcmp_client *client,
    struct networkcmp_handle socket,
    const void *buffer, size_t length)
{
	union networkcmp_buffer request, reply;
	struct networkcmp_inline_request *io;
	const struct networkcmp_inline_reply *result;
	size_t reply_length;

	if (buffer == NULL || length == 0 || length > NETWORKCMP_INLINE_MAX) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	io = (void *)request.wire.payload;
	io->socket = socket;
	io->length = (uint32_t)length;
	memcpy(io + 1, buffer, length);
	if (networkcmp_rpc(client, NETWORKCMP_OP_SEND, io,
	    sizeof(*io) + length,
	    &reply, &reply_length) == -1)
		return (-1);
	result = (const void *)(&reply.wire.msg + 1);
	if (result->length > length) {
		errno = EPROTO;
		return (-1);
	}
	return ((ssize_t)result->length);
}

ssize_t
networkcmp_recv_inline(struct networkcmp_client *client,
    struct networkcmp_handle socket, void *buffer, size_t capacity,
    uint32_t timeout_ms, uint32_t *flags)
{
	union networkcmp_buffer reply;
	struct networkcmp_inline_request request;
	const struct networkcmp_inline_reply *result;
	struct timespec deadline, now, pause;
	size_t reply_length;
	int64_t remaining;

	if (buffer == NULL || capacity == 0 || capacity > NETWORKCMP_INLINE_MAX ||
	    timeout_ms > NETWORKCMP_IO_TIMEOUT_MAX) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.socket = socket;
	request.length = (uint32_t)capacity;
	request.timeout_ms = 0;
	if (timeout_ms != 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
			return (-1);
		deadline.tv_sec += timeout_ms / 1000;
		deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
		if (deadline.tv_nsec >= 1000000000L) {
			deadline.tv_sec++;
			deadline.tv_nsec -= 1000000000L;
		}
	}
	for (;;) {
		if (networkcmp_rpc(client, NETWORKCMP_OP_RECV, &request,
		    sizeof(request), &reply, &reply_length) == 0)
			break;
		if (errno != EAGAIN || timeout_ms == 0)
			return (-1);
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			return (-1);
		remaining = (deadline.tv_sec - now.tv_sec) * 1000000000LL +
		    deadline.tv_nsec - now.tv_nsec;
		if (remaining <= 0) {
			errno = ETIMEDOUT;
			return (-1);
		}
		pause.tv_sec = 0;
		pause.tv_nsec = MIN(remaining, 10000000LL);
		while (nanosleep(&pause, &pause) == -1)
			if (errno != EINTR)
				return (-1);
	}
	result = (const void *)(&reply.wire.msg + 1);
	if (result->length > capacity) {
		errno = EPROTO;
		return (-1);
	}
	memcpy(buffer, result + 1, result->length);
	if (flags != NULL)
		*flags = result->flags;
	return ((ssize_t)result->length);
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
	if (networkcmp_rpc(client, NETWORKCMP_OP_RESOLVE, resolve,
	    sizeof(*resolve) + host_length + service_length, &reply,
	    &length) == -1)
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
