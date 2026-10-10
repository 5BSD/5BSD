/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>

#include <errno.h>
#include <libservice.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "network_state_protocol.h"

struct network_state_client {
	struct service_session *session;
	pthread_mutex_t lock;
	pid_t owner;
};
static int state_lock(struct network_state_client *client)
    __trylocks_exclusive(0, client->lock);
static int
state_lock(struct network_state_client *client) __no_lock_analysis
{
	int error = pthread_mutex_lock(&client->lock);
	if (error != 0)
		errno = error;
	return (error);
}
static int
header_valid(const struct network_state_header *h)
{
	return (h->magic == NETWORK_STATE_MAGIC && h->version == 1 &&
	    h->opcode == 1 && h->reserved == 0 && h->status <= 0 &&
	    h->status >= -ELAST);
}
int
network_state_validate_request(const void *data, size_t length)
{
	struct network_state_request r;
	if (data == NULL || length != sizeof(r))
		return (errno = EPROTO, -1);
	memcpy(&r, data, sizeof(r));
	if (!header_valid(&r.header) || r.header.status != 0 || r.reserved != 0)
		return (errno = EPROTO, -1);
	return (0);
}
int
network_state_validate_reply(const void *data, size_t length)
{
	struct network_state_reply r = { 0 };
	uint32_t last = 0;
	if (data == NULL || length < sizeof(r.header) || length > sizeof(r))
		return (errno = EPROTO, -1);
	memcpy(&r, data, length);
	if (!header_valid(&r.header))
		return (errno = EPROTO, -1);
	if (r.header.status != 0)
		return (length == sizeof(r.header) ? 0 : (errno = EPROTO, -1));
	if (length < NETWORK_STATE_REPLY_SIZE(0) || r.state.epoch == 0 ||
	    r.state.generation == 0 ||
	    r.state.count > NETWORK_STATE_MAX_INTERFACES ||
	    length != NETWORK_STATE_REPLY_SIZE(r.state.count) ||
	    r.state.source_error < 0 || r.state.source_error > ELAST ||
	    (r.state.source_error != 0 && r.state.count != 0))
		return (errno = EPROTO, -1);
	for (size_t i = 0; i < r.state.count; i++) {
		const struct network_state_interface *e =
		    &r.state.interfaces[i];
		size_t n = strnlen(e->name, sizeof(e->name));
		if (e->index <= last || e->link_state > NETWORK_STATE_LINK_UP ||
		    memcmp(e->reserved, (uint8_t[3]) { 0 }, 3) != 0 || n == 0 ||
		    n == sizeof(e->name) ||
		    memcmp(e->name + n, (char[16]) { 0 },
			sizeof(e->name) - n) != 0)
			return (errno = EPROTO, -1);
		for (size_t j = 0; j < i; j++)
			if (memcmp(e->name, r.state.interfaces[j].name,
				sizeof(e->name)) == 0)
				return (errno = EPROTO, -1);
		last = e->index;
	}
	return (0);
}
static int
connect_client(struct network_state_client *client)
{
	int fd, error;
	if (service_open(NETWORK_STATE_INTERFACE, &fd) == -1)
		return (-1);
	if (service_harden_fd(fd, 0) == -1 ||
	    service_session_create(fd, &client->session) == -1) {
		error = errno;
		close(fd);
		return (errno = error, -1);
	}
	/* The session owns a duplicate of this descriptor. */
	(void)close(fd);
	return (0);
}
int
network_state_open(struct network_state_client **out)
{
	struct network_state_client *client;
	int error;
	if (out == NULL)
		return (errno = EINVAL, -1);
	*out = NULL;
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (-1);
	client->owner = getpid();
	error = pthread_mutex_init(&client->lock, NULL);
	if (error != 0) {
		free(client);
		return (errno = error, -1);
	}
	if (connect_client(client) == -1) {
		error = errno;
		pthread_mutex_destroy(&client->lock);
		free(client);
		return (errno = error, -1);
	}
	*out = client;
	return (0);
}
int
network_state_watch(struct network_state_client *client,
    struct network_state_snapshot *out, uint32_t timeout_ms)
{
	struct network_state_request request = {
		.header = { .magic = NETWORK_STATE_MAGIC,
		    .version = 1,
		    .opcode = 1 },
		.timeout_ms = timeout_ms
	};
	struct network_state_reply reply = { 0 };
	struct service_message outgoing = { .size = sizeof(outgoing),
		.data = &request,
		.length = sizeof(request) };
	struct service_reply incoming = { .size = sizeof(incoming),
		.data = &reply,
		.capacity = sizeof(reply) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int result, error;
	bool server_timeout = false;
	if (client == NULL || out == NULL)
		return (errno = EINVAL, -1);
	if (client->owner != getpid())
		return (errno = ECHILD, -1);
	options.timeout_ms = timeout_ms == NETWORK_STATE_TIMEOUT_INFINITE ?
	    SERVICE_CLIENT_TIMEOUT_INFINITE :
	    (uint32_t)MIN((uint64_t)timeout_ms + 5000, UINT32_MAX - 1);
	if (state_lock(client) != 0)
		return (-1);
	result = client->session == NULL ? connect_client(client) : 0;
	if (result == 0)
		result = service_session_call(client->session, &outgoing,
		    &incoming, &options);
	if (result == 0 &&
	    (incoming.nfds != 0 ||
		network_state_validate_reply(&reply, incoming.length) == -1))
		result = (errno = EPROTO, -1);
	if (result == 0 && reply.header.status != 0) {
		server_timeout = reply.header.status == -EAGAIN;
		result = (errno = -reply.header.status, -1);
	}
	error = result == -1 ? errno : 0;
	if (result == 0)
		*out = reply.state;
	/* EAGAIN is a completed server timeout. Any other failure resets the
	 * stream. */
	if (result == -1 && !server_timeout && client->session != NULL) {
		service_session_close(client->session);
		client->session = NULL;
	}
	pthread_mutex_unlock(&client->lock);
	return (errno = error, result);
}
void
network_state_close(struct network_state_client *client)
{
	if (client == NULL)
		return;
	if (client->owner == getpid()) {
		if (client->session != NULL)
			service_session_close(client->session);
		pthread_mutex_destroy(&client->lock);
	}
	free(client);
}
