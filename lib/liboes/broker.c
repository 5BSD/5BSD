/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * oes_client_create_brokered(3): obtain a notify-mode OES client from the
 * system.OES broker over bsd.oes.v1 (oes_broker.fidl): one session, negotiated,
 * one OpenNotify, closed again.  The whole exchange is bounded by five seconds
 * (or an enclosing service_budget_begin(3)).
 */
#include <errno.h>
#include <fidl/bsd.oes.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <libservice.h>
#include <service_runtime.h>
#include <stdbool.h>
#include <unistd.h>

#include "liboes.h"
#include "oes_broker_protocol.h"

struct broker_call {
	bool done, malformed;
	int error;
	int status;
	int fd;
};

static void
broker_info(void *context, int error, struct bsd_oes_v1_ProtocolInfo *value)
{
	struct broker_call *call = context;

	call->done = true;
	call->error = error;
	if (!error && (value == NULL || value->wire_version != OES_BROKER_VERSION))
		call->error = EPROTONOSUPPORT;
}

static void
broker_notify(void *context, int error,
    struct bsd_oes_v1_Broker_OpenNotify_Result *value)
{
	struct broker_call *call = context;

	call->done = true;
	call->error = error;
	if (error)
		return;
	if (value == NULL)
		call->malformed = true;
	else if (value->tag == bsd_oes_v1_Broker_OpenNotify_Result_err_tag) {
		if (value->value.err == 0 || value->value.err > ELAST)
			call->malformed = true;
		else
			call->status = (int)value->value.err;
	} else if (value->tag !=
	    bsd_oes_v1_Broker_OpenNotify_Result_response_tag)
		call->malformed = true;
	else {
		call->fd = fidl_bsd_take_fd(&value->value.response.client);
		if (call->fd < 0)
			call->malformed = true;
	}
}

/* Wait for one call; 0, or -1 with errno for a transport or protocol fault. */
static int
broker_wait(struct fidl_bsd_connection *connection, int error,
    struct broker_call *call, const struct timespec *deadline)
{

	if (error == 0)
		error = fidl_bsd_sync_wait(connection, &call->done, deadline);
	if (error == 0 && call->error != 0)
		error = call->error;
	if (error == 0 && call->malformed)
		error = EPROTO;
	if (error != 0) {
		if (call->fd >= 0) {
			(void)close(call->fd);
			call->fd = -1;
		}
		return (errno = error, -1);
	}
	return (0);
}

oes_client_t *
oes_client_create_brokered(void)
{
	struct fidl_bsd_connection *connection = NULL;
	struct fidl_bsd_empty empty = { 0 };
	struct broker_call info = { .fd = -1 }, notify = { .fd = -1 };
	struct timespec deadline;
	oes_client_t *client = NULL;
	uint32_t timeout_ms = 5000, txid;
	int channel_fd = -1, error, saved;
	bool own_budget;

	own_budget = service_budget_begin(5000) == 0;
	if (!own_budget && errno != EBUSY)
		return (NULL);
	if (service_budget_timeout(&timeout_ms) == -1)
		goto done;
	if ((error = fidl_bsd_sync_deadline(&deadline, timeout_ms)) != 0) {
		errno = error;
		goto done;
	}
	if (service_open(OES_BROKER_ENDPOINT, &channel_fd) == -1)
		goto done;
	/* The connection consumes channel_fd only on success. */
	if ((error = fidl_bsd_connection_create(channel_fd, FIDL_BSD_CLIENT,
	    &connection)) != 0) {
		connection = NULL;
		errno = error;
		goto done;
	}
	channel_fd = -1;
	if (broker_wait(connection, bsd_oes_v1_Broker_GetProtocolInfo(
	    connection, &empty, broker_info, &info, &txid), &info,
	    &deadline) == -1)
		goto done;
	if (broker_wait(connection, bsd_oes_v1_Broker_OpenNotify(connection,
	    &empty, broker_notify, &notify, &txid), &notify, &deadline) == -1)
		goto done;
	if (notify.status != 0) {
		errno = notify.status;
		goto done;
	}
	client = oes_client_adopt_fd(notify.fd);
	if (client != NULL)
		notify.fd = -1;
done:
	saved = errno;
	if (notify.fd >= 0)
		(void)close(notify.fd);
	if (connection != NULL)
		fidl_bsd_connection_destroy(connection);
	if (channel_fd >= 0)
		(void)close(channel_fd);
	if (own_budget)
		service_budget_end();
	errno = saved;
	return (client);
}
