/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <channel.h>
#include <errno.h>
#include <oes_broker_protocol.h>
#include <service_runtime.h>
#include <stdbool.h>
#include <unistd.h>

#include "oes_factory.h"

struct oes_factory_session {
	int rootfd;
	bool done;
	int send_error;
};

static void
oes_factory_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	struct oes_factory_session *state = argument;
	struct oes_broker_message reply = { .magic = OES_BROKER_MAGIC,
		.version = OES_BROKER_VERSION,
		.operation = OES_BROKER_OPEN_NOTIFY };
	struct channel_outgoing outgoing = CHANNEL_OUTGOING_INITIALIZER(&reply,
	    sizeof(reply));
	int fd = -1;

	if (state->done) {
		channel_message_free(message);
		return;
	}
	state->done = true;
	if (oes_broker_validate(channel_message_data(message),
		channel_message_length(message),
		channel_message_fd_count(message), false) == -1)
		reply.status = EPROTO;
	else {
		fd = bsdfilesystem_oes_open_notify(state->rootfd);
		if (fd == -1)
			reply.status = errno > 0 && errno <= ELAST ? errno :
								     EIO;
		else {
			outgoing.fds = &fd;
			outgoing.nfds = 1;
		}
	}
	if (channel_send_reply(message, &outgoing) == -1)
		state->send_error = errno != 0 ? errno : EIO;
	/* send_reply retains its own attachment reference on success. */
	if (fd >= 0)
		(void)close(fd);
	channel_message_free(message);
}

/* Consumes session_fd on every outcome. rootfd is borrowed. Admission must
 * already have passed the system.oes endpoint requirement. One grant/session.
 */
int
bsdfilesystem_oes_serve(int rootfd, int session_fd)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct oes_factory_session state = { .rootfd = rootfd };
	struct channel *channel;
	uint64_t deadline = service_monotime_ms() + 5000;
	int ready, wants_write, result = 1;

	options.max_pending_requests = 1;
	options.max_queued_messages = 1;
	options.max_queued_bytes = sizeof(struct oes_broker_message);
	options.max_queued_fds = 1;
	if (channel_create(session_fd, &options, &channel) == -1) {
		(void)close(session_fd);
		return (1);
	}
	if (channel_set_request_handler(channel, oes_factory_request, &state) ==
	    -1)
		goto done;
	for (;;) {
		uint64_t now = service_monotime_ms();
		wants_write = channel_wants_write(channel);
		if (wants_write == -1 || state.send_error != 0)
			break;
		if (state.done && !wants_write) {
			result = 0;
			break;
		}
		if (now >= deadline)
			break;
		ready = channel_wait(channel, wants_write,
		    (int)(deadline - now));
		if (ready <= 0)
			break;
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
	}
done:
	channel_destroy(channel);
	return (result);
}
