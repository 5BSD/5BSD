/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libpowercmp: C application API for system.Power, using the generated
 * bsd.power.v1 bindings (powercmp.fidl) over a native capability channel.
 */
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.power.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <libservice.h>
#include <service_runtime.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "powercmp.h"

#define POWERCMP_CALL_TIMEOUT_MS 5000

struct powercmp_client {
	struct fidl_bsd_connection *connection;
	pid_t owner;
	bool negotiated;
	int terminal_error;
};

struct completion {
	bool done, malformed;
	int error;
	uint32_t value;
};

/* A lost/ambiguous RPC drops the connection and hence every session lease.
 * Keep the error on the handle: callers cannot accidentally reuse or reopen it.
 */
static int
client_disconnect(struct powercmp_client *client, int error)
{
	if (client->connection != NULL) {
		fidl_bsd_connection_destroy(client->connection);
		client->connection = NULL;
	}
	client->terminal_error = error != 0 ? error : EIO;
	return (errno = client->terminal_error, -1);
}

static void
malformed(struct completion *result)
{
	result->malformed = true;
	result->error = EPROTO;
}

static void
domain_error(struct completion *result, uint32_t error)
{
	if (error == 0 || error > ELAST)
		malformed(result);
	else
		result->error = (int)error;
}

static void
info_reply(void *context, int error, struct bsd_power_v1_ProtocolInfo *value)
{
	struct completion *result = context;
	result->done = true;
	result->error = error;
	if (!error &&
	    (value == NULL || value->wire_version != POWERCMP_WIRE_VERSION)) {
		result->malformed = true;
		result->error = EPROTONOSUPPORT;
	}
}

static void
states_reply(void *context, int error, struct bsd_power_v1_SleepStates *value)
{
	struct completion *result = context;
	result->done = true;
	result->error = error;
	if (error)
		return;
	/* Only S1..S5 exist; any other bit is a malformed reply. */
	if (value == NULL || (value->supported & ~UINT32_C(0x3e)) != 0)
		malformed(result);
	else
		result->value = value->supported;
}

static void
count_reply(void *context, int error, struct bsd_power_v1_InhibitorCount *value)
{
	struct completion *result = context;
	result->done = true;
	result->error = error;
	if (error)
		return;
	if (value == NULL)
		malformed(result);
	else
		result->value = value->count;
}

/* Empty-success results: check the tag; the error is an errno value. */
#define RESULT_REPLY(name, type)                                        \
	static void name(void *context, int error, struct type *value)  \
	{                                                               \
		struct completion *result = context;                    \
		result->done = true;                                    \
		result->error = error;                                  \
		if (error)                                              \
			return;                                         \
		if (value == NULL)                                      \
			malformed(result);                              \
		else if (value->tag == type##_err_tag)                  \
			domain_error(result, value->value.err);         \
		else if (value->tag != type##_response_tag)             \
			malformed(result);                              \
	}
RESULT_REPLY(suspend_reply, bsd_power_v1_Power_Suspend_Result)
RESULT_REPLY(inhibit_reply, bsd_power_v1_Power_Inhibit_Result)
RESULT_REPLY(uninhibit_reply, bsd_power_v1_Power_Uninhibit_Result)

/*
 * Wait for one completion.  Transport failures, timeouts and malformed
 * replies make the handle terminal; application errors keep the session.
 */
static int
finish(struct powercmp_client *client, int error, struct completion *result,
    const struct timespec *deadline)
{
	if (error == 0)
		error = fidl_bsd_sync_wait(client->connection, &result->done,
		    deadline);
	if (error != 0)
		return (client_disconnect(client, error));
	if (result->malformed)
		return (client_disconnect(client, result->error));
	/* A call failed by the transport (the peer closed) ends the session. */
	if (result->error != 0 &&
	    fidl_bsd_connection_error(client->connection) != 0)
		return (client_disconnect(client, result->error));
	if (result->error != 0)
		return (errno = result->error, -1);
	return (0);
}

static int
begin(struct powercmp_client *client, struct timespec *deadline)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t timeout_ms = POWERCMP_CALL_TIMEOUT_MS, txid;
	int error;

	if (client == NULL)
		return (errno = EINVAL, -1);
	if (client->owner != getpid())
		return (errno = ECHILD, -1);
	if (client->terminal_error != 0)
		return (errno = client->terminal_error, -1);
	/* A caller's service_budget_begin(3) bounds the whole operation. */
	if (service_budget_timeout(&timeout_ms) == -1)
		return (-1);
	if ((error = fidl_bsd_sync_deadline(deadline, timeout_ms)) != 0)
		return (errno = error, -1);
	if (client->negotiated)
		return (0);
	error = bsd_power_v1_Power_GetProtocolInfo(client->connection, &empty,
	    info_reply, &result, &txid);
	if (finish(client, error, &result, deadline) == -1)
		return (-1);
	client->negotiated = true;
	return (0);
}

int
powercmp_client_create(int fd, struct powercmp_client **clientp)
{
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct powercmp_client *client;
	int error, owned;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (-1);
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned < 0 || cap_xfer_limit(owned, CAP_XFER_NONE) == -1 ||
	    cap_cloexec_limit(owned, CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		if (owned >= 0)
			(void)close(owned);
		free(client);
		return (errno = error, -1);
	}
	options.max_pending_requests = 1;
	options.max_queued_messages = 2;
	options.max_queued_bytes = 1024;
	options.max_queued_fds = 0;
	error = fidl_bsd_connection_create_with_options(owned, FIDL_BSD_CLIENT,
	    &options, &client->connection);
	if (error != 0) {
		(void)close(owned);
		free(client);
		return (errno = error, -1);
	}
	(void)close(fd);
	client->owner = getpid();
	*clientp = client;
	return (0);
}

int
powercmp_client_open(struct powercmp_client **clientp)
{
	int error, fd;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	if (service_open(POWERCMP_INTERFACE, &fd) == -1)
		return (-1);
	if (powercmp_client_create(fd, clientp) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	return (0);
}

void
powercmp_client_close(struct powercmp_client *client)
{

	if (client == NULL)
		return;
	/* Locked close-on-fork descriptors may have been reused in a child. */
	if (client->owner == getpid() && client->connection != NULL)
		fidl_bsd_connection_destroy(client->connection);
	free(client);
}

int
powercmp_states(struct powercmp_client *client, uint32_t *supported)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;
	uint32_t txid;

	if (supported == NULL)
		return (errno = EINVAL, -1);
	if (begin(client, &deadline) == -1)
		return (-1);
	if (finish(client, bsd_power_v1_Power_States(client->connection,
	    &empty, states_reply, &result, &txid), &result, &deadline) == -1)
		return (-1);
	*supported = result.value;
	return (0);
}

int
powercmp_suspend(struct powercmp_client *client, uint32_t state)
{
	struct completion result = { 0 };
	struct bsd_power_v1_SleepState value = { state };
	struct timespec deadline;
	uint32_t txid;

	if (state < 1 || state > 5)
		return (errno = EINVAL, -1);
	if (begin(client, &deadline) == -1)
		return (-1);
	return (finish(client, bsd_power_v1_Power_Suspend(client->connection,
	    &value, suspend_reply, &result, &txid), &result, &deadline));
}

int
powercmp_inhibit(struct powercmp_client *client)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;
	uint32_t txid;

	if (begin(client, &deadline) == -1)
		return (-1);
	return (finish(client, bsd_power_v1_Power_Inhibit(client->connection,
	    &empty, inhibit_reply, &result, &txid), &result, &deadline));
}

int
powercmp_uninhibit(struct powercmp_client *client)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;
	uint32_t txid;

	if (begin(client, &deadline) == -1)
		return (-1);
	return (finish(client, bsd_power_v1_Power_Uninhibit(client->connection,
	    &empty, uninhibit_reply, &result, &txid), &result, &deadline));
}

int
powercmp_inhibitors(struct powercmp_client *client, uint32_t *count)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;
	uint32_t txid;

	if (count == NULL)
		return (errno = EINVAL, -1);
	if (begin(client, &deadline) == -1)
		return (-1);
	if (finish(client, bsd_power_v1_Power_Inhibitors(client->connection,
	    &empty, count_reply, &result, &txid), &result, &deadline) == -1)
		return (-1);
	*count = result.value;
	return (0);
}
