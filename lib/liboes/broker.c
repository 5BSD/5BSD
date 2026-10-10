/* SPDX-License-Identifier: BSD-2-Clause */
#include <errno.h>
#include <libservice.h>
#include <service_runtime.h>
#include <unistd.h>

#include "liboes.h"
#include "oes_broker_protocol.h"

oes_client_t *
oes_client_create_brokered(void)
{
	struct service_session *session = NULL;
	struct oes_broker_message request = { .magic = OES_BROKER_MAGIC,
		.version = OES_BROKER_VERSION,
		.operation = OES_BROKER_OPEN_NOTIFY };
	struct oes_broker_message response;
	struct service_message outgoing = { .size = sizeof(outgoing),
		.data = &request,
		.length = sizeof(request) };
	struct service_reply incoming = { .size = sizeof(incoming),
		.data = &response,
		.capacity = sizeof(response) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	oes_client_t *client = NULL;
	int channel_fd = -1, received_fd = -1, saved;
	bool own_budget;

	own_budget = service_budget_begin(5000) == 0;
	if (!own_budget && errno != EBUSY)
		return (NULL);
	if (service_open(OES_BROKER_ENDPOINT, &channel_fd) == -1)
		goto done;
	/* The session consumes channel_fd only on success. */
	if (service_session_create(channel_fd, &session) == -1)
		goto done;
	channel_fd = -1;
	incoming.fds = &received_fd;
	incoming.fd_capacity = 1;
	options.timeout_ms = 5000;
	if (service_session_call(session, &outgoing, &incoming, &options) == -1)
		goto done;
	if (oes_broker_validate(&response, incoming.length, incoming.nfds,
		true) == -1)
		goto done;
	if (response.status != 0) {
		errno = response.status;
		goto done;
	}
	client = oes_client_adopt_fd(received_fd);
	if (client != NULL)
		received_fd = -1;
done:
	saved = errno;
	if (received_fd >= 0)
		(void)close(received_fd);
	if (session != NULL)
		service_session_close(session);
	if (channel_fd >= 0)
		(void)close(channel_fd);
	if (own_budget)
		service_budget_end();
	errno = saved;
	return (client);
}
