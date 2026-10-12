/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>

#include <errno.h>
#include <fidl/bsd.network.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <libservice.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "network_state_protocol.h"

struct network_state_client {
	struct fidl_bsd_connection *connection;
	pthread_mutex_t lock;
	pid_t owner;
	bool negotiated;
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
/*
 * network_state_validate_request() and network_state_validate_reply() check
 * the pre-FIDL NST1 records (network_state_protocol.h) and are kept for ABI
 * compatibility; the client and provider use bsd.network.v1 NetworkState.
 */
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
struct watch_call {
	bool done, malformed;
	int error;
	struct network_state_snapshot *out;
};

static void
info_reply(void *context, int error, struct bsd_network_v1_ProtocolInfo *value)
{
	struct watch_call *call = context;
	call->done = true;
	call->error = error;
	if (error == 0 && (value == NULL ||
	    value->wire_version != NETWORK_STATE_WIRE_VERSION)) {
		call->malformed = true;
		call->error = EPROTONOSUPPORT;
	}
}

/* The same snapshot rules the pre-FIDL reply validator enforced. */
static bool
snapshot_valid(const struct bsd_network_v1_Snapshot *r)
{
	uint32_t last = 0;
	if (r->epoch == 0 || r->generation == 0 ||
	    r->interfaces_size > NETWORK_STATE_MAX_INTERFACES ||
	    r->source_error < 0 || r->source_error > ELAST ||
	    (r->source_error != 0 && r->interfaces_size != 0))
		return (false);
	for (size_t i = 0; i < r->interfaces_size; i++) {
		const struct bsd_network_v1_Interface *e = &r->interfaces[i];
		if (e->index <= last || e->link_state > NETWORK_STATE_LINK_UP ||
		    e->name_size == 0 || e->name_size >= 16 ||
		    memchr(e->name, '\0', e->name_size) != NULL)
			return (false);
		for (size_t j = 0; j < i; j++)
			if (r->interfaces[j].name_size == e->name_size &&
			    memcmp(r->interfaces[j].name, e->name,
			    e->name_size) == 0)
				return (false);
		last = e->index;
	}
	return (true);
}

static void
watch_reply(void *context, int error,
    struct bsd_network_v1_NetworkState_Watch_Result *value)
{
	struct watch_call *call = context;
	const struct bsd_network_v1_Snapshot *r;
	call->done = true;
	call->error = error;
	if (error != 0)
		return;
	if (value == NULL || (value->tag !=
	    bsd_network_v1_NetworkState_Watch_Result_err_tag &&
	    value->tag != bsd_network_v1_NetworkState_Watch_Result_response_tag))
		goto malformed;
	if (value->tag == bsd_network_v1_NetworkState_Watch_Result_err_tag) {
		if (value->value.err == 0 || value->value.err > ELAST)
			goto malformed;
		call->error = (int)value->value.err;
		return;
	}
	r = &value->value.response;
	if (!snapshot_valid(r))
		goto malformed;
	memset(call->out, 0, sizeof(*call->out));
	call->out->epoch = r->epoch;
	call->out->generation = r->generation;
	call->out->source_error = r->source_error;
	call->out->count = (uint32_t)r->interfaces_size;
	for (size_t i = 0; i < r->interfaces_size; i++) {
		struct network_state_interface *e = &call->out->interfaces[i];
		e->index = r->interfaces[i].index;
		e->flags = r->interfaces[i].flags;
		e->mtu = r->interfaces[i].mtu;
		e->link_state = r->interfaces[i].link_state;
		memcpy(e->name, r->interfaces[i].name,
		    r->interfaces[i].name_size);
	}
	return;
malformed:
	call->malformed = true;
	call->error = EPROTO;
}

static int
connect_client(struct network_state_client *client)
{
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	int fd, error;
	if (service_open(NETWORK_STATE_INTERFACE, &fd) == -1)
		return (-1);
	options.max_pending_requests = 1;
	options.max_queued_fds = 0;
	error = service_harden_fd(fd, 0) == -1 ? errno :
	    fidl_bsd_connection_create_with_options(fd, FIDL_BSD_CLIENT,
	    &options, &client->connection);
	if (error != 0) {
		close(fd);
		client->connection = NULL;
		return (errno = error, -1);
	}
	client->negotiated = false;
	return (0);
}

static void
disconnect(struct network_state_client *client)
{
	if (client->connection != NULL)
		fidl_bsd_connection_destroy(client->connection);
	client->connection = NULL;
	client->negotiated = false;
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

/* Wait for one completion; an infinite deadline blocks in the poll. */
static int
wait_call(struct network_state_client *client, const bool *done,
    const struct timespec *deadline)
{
	int error;
	if (deadline != NULL)
		return (fidl_bsd_sync_wait(client->connection, done, deadline));
	while (!*done) {
		error = fidl_bsd_connection_poll(client->connection, -1);
		if (error != 0 && !*done)
			return (error);
	}
	return (0);
}

int
network_state_watch(struct network_state_client *client,
    struct network_state_snapshot *out, uint32_t timeout_ms)
{
	struct bsd_network_v1_WatchRequest request = { timeout_ms };
	struct fidl_bsd_empty empty = { 0 };
	struct watch_call info = { 0 }, call = { .out = out };
	struct timespec deadline, *deadlinep;
	uint32_t txid;
	int result, error;
	bool server_timeout = false;
	if (client == NULL || out == NULL)
		return (errno = EINVAL, -1);
	if (client->owner != getpid())
		return (errno = ECHILD, -1);
	/* The provider answers EAGAIN when timeout_ms elapses; allow 5 s. */
	deadlinep = NULL;
	if (timeout_ms != NETWORK_STATE_TIMEOUT_INFINITE) {
		error = fidl_bsd_sync_deadline(&deadline,
		    (uint32_t)MIN((uint64_t)timeout_ms + 5000, UINT32_MAX - 1));
		if (error != 0)
			return (errno = error, -1);
		deadlinep = &deadline;
	}
	if (state_lock(client) != 0)
		return (-1);
	result = client->connection == NULL ? connect_client(client) : 0;
	error = result == -1 ? errno : 0;
	if (error == 0 && !client->negotiated) {
		error = bsd_network_v1_NetworkState_GetProtocolInfo(
		    client->connection, &empty, info_reply, &info, &txid);
		if (error == 0)
			error = wait_call(client, &info.done, deadlinep);
		if (error == 0)
			error = info.error;
		client->negotiated = error == 0;
	}
	if (error == 0) {
		error = bsd_network_v1_NetworkState_Watch(client->connection,
		    &request, watch_reply, &call, &txid);
		if (error == 0)
			error = wait_call(client, &call.done, deadlinep);
		if (error == 0 && call.error != 0) {
			error = call.error;
			server_timeout = !call.malformed && error == EAGAIN;
		}
	}
	/* EAGAIN is a completed server timeout. Any other failure resets the
	 * stream. */
	if (error != 0 && !server_timeout)
		disconnect(client);
	pthread_mutex_unlock(&client->lock);
	if (error != 0)
		return (errno = error, -1);
	return (0);
}

void
network_state_close(struct network_state_client *client)
{
	if (client == NULL)
		return;
	if (client->owner == getpid()) {
		disconnect(client);
		pthread_mutex_destroy(&client->lock);
	}
	free(client);
}
