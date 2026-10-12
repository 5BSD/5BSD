/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The system.OES broker session (bsd.oes.v1, lib/liboes/oes_broker.fidl): an
 * admitted client negotiates and makes one OpenNotify, answered with a fresh
 * notify-mode OES descriptor; the session then ends.  The whole session is
 * bounded by five seconds.
 */
#include <sys/types.h>

#include <errno.h>
#include <fidl/bsd.oes.v1/c/bsd.h>
#include <oes_broker_protocol.h>
#include <service_runtime.h>
#include <stdbool.h>
#include <unistd.h>

#include "oes_factory.h"

struct oes_factory_session {
	int rootfd;
	bool negotiated;
	bool done;
	int send_error;
};

static void
oes_factory_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct oes_factory_session *state = argument;
	struct bsd_oes_v1_ProtocolInfo info = { OES_BROKER_VERSION };
	int error;

	error = bsd_oes_v1_Broker_GetProtocolInfo_reply(connection, request,
	    &info);
	if (error != 0)
		state->send_error = error;
	else
		state->negotiated = true;
}

static void
oes_factory_request(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct oes_factory_session *state = argument;
	struct bsd_oes_v1_Broker_OpenNotify_Result reply = {
		.tag = bsd_oes_v1_Broker_OpenNotify_Result_response_tag
	};
	int error, fd;

	/* One grant per session, and only after negotiation. */
	if (!state->negotiated || state->done) {
		fidl_bsd_connection_close(connection, EPROTO);
		return;
	}
	state->done = true;
	fd = bsdfilesystem_oes_open_notify(state->rootfd);
	if (fd == -1) {
		reply.tag = bsd_oes_v1_Broker_OpenNotify_Result_err_tag;
		reply.value.err = errno > 0 && errno <= ELAST ? (uint32_t)errno :
		    EIO;
	} else
		reply.value.response.client = fd;
	error = bsd_oes_v1_Broker_OpenNotify_reply(connection, request, &reply);
	if (error != 0)
		state->send_error = error;
	/* The bindings send their own duplicate. */
	if (fd >= 0)
		(void)close(fd);
}

/* Consumes session_fd on every outcome. rootfd is borrowed. Admission must
 * already have been enforced by the caller. */
int
bsdfilesystem_oes_serve(int rootfd, int session_fd)
{
	static const struct bsd_oes_v1_Broker_server handlers = {
		.GetProtocolInfo = oes_factory_info,
		.OpenNotify = oes_factory_request
	};
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct oes_factory_session state = { .rootfd = rootfd };
	struct fidl_bsd_connection *connection;
	uint64_t deadline = service_monotime_ms() + 5000;
	int result = 1;

	/* Sequential header-only requests; one descriptor out. */
	options.max_pending_requests = 1;
	options.max_queued_messages = 1;
	options.max_queued_bytes = sizeof(struct oes_broker_message);
	options.max_queued_fds = 1;
	if (fidl_bsd_connection_create_with_options(session_fd, FIDL_BSD_SERVER,
	    &options, &connection) != 0) {
		(void)close(session_fd);
		return (1);
	}
	if (bsd_oes_v1_Broker_bind(connection, &handlers, &state) != 0)
		goto done;
	for (;;) {
		uint64_t now = service_monotime_ms();

		if (state.send_error != 0)
			break;
		/* Granted and flushed: the session is complete. */
		if (state.done && fidl_bsd_connection_wants_write(connection) == 0) {
			result = 0;
			break;
		}
		if (now >= deadline ||
		    fidl_bsd_connection_poll(connection,
		    (int)(deadline - now)) != 0)
			break;
	}
done:
	fidl_bsd_connection_destroy(connection);
	return (result);
}
