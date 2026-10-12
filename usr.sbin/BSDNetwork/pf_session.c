/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The PF endpoint belongs to BSDNetwork, but its sessions use dedicated
 * workers.  The parent requests /dev/pf from BSDFilesystem.  Each worker
 * inherits only a descriptor narrowed to one read-only state-export ioctl
 * and one transfer to its client.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>

#include "pf_protocol.h"
#include "pf_session.h"

struct pf_request_state {
	int pf_fd;
	int open_error;
	bool done;
};

int
network_pf_open(struct service_context *context)
{
	static const unsigned long commands[] = { PF_MONITOR_GETSTATES };
	cap_rights_t rights;
	int fd, error;

	if (context == NULL)
		return (errno = ENODEV, -1);
	if (service_open_isolated(context, "/dev/pf",
	    SERVICE_OPEN_READ | SERVICE_OPEN_IOCTL, 0, &fd) == -1)
		return (-1);
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_IOCTL);
	if (cap_rights_limit(fd, &rights) == -1 ||
	    cap_ioctls_limit(fd, commands, nitems(commands)) == -1 ||
	    cap_fcntls_limit(fd, 0) == -1 ||
	    service_harden_fd(fd, SERVICE_HARDEN_XFER_ONCE |
	    SERVICE_HARDEN_CLOFORK_ONCE) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	return (fd);
}

static void
pf_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	struct pf_request_state *state;
	struct pf_monitor_message input, reply;
	struct channel_outgoing outgoing;

	state = argument;
	if (state->done) {
		channel_message_free(message);
		return;
	}
	state->done = true;
	memset(&reply, 0, sizeof(reply));
	reply.magic = PF_MONITOR_MAGIC;
	reply.error = EINVAL;
	if (channel_message_length(message) == sizeof(input) &&
	    channel_message_fd_count(message) == 0) {
		memcpy(&input, channel_message_data(message), sizeof(input));
		if (input.magic == PF_MONITOR_MAGIC && input.error == 0)
			reply.error = state->pf_fd >= 0 ? 0 : state->open_error;
	}
	outgoing = (struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply));
	if (reply.error == 0) {
		outgoing.fds = &state->pf_fd;
		outgoing.nfds = 1;
	}
	(void)channel_send_reply(message, &outgoing);
	if (state->pf_fd >= 0) {
		(void)close(state->pf_fd);
		state->pf_fd = -1;
	}
	channel_message_free(message);
}

int
network_pf_serve(int session_fd, int pf_fd, int open_error)
{
	struct channel_options options;
	struct pf_request_state state;
	struct channel *channel;
	struct timespec started, now;
	long elapsed;
	int ready, result;

	options = (struct channel_options)
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	options.max_queued_messages = 2;
	options.max_queued_fds = 1;
	options.max_queued_bytes = 1024;
	if (channel_create(session_fd, &options, &channel) == -1) {
		(void)close(session_fd);
		if (pf_fd >= 0)
			(void)close(pf_fd);
		return (1);
	}
	state = (struct pf_request_state){
	    .pf_fd = pf_fd,
	    .open_error = open_error != 0 ? open_error : EIO,
	};
	result = 1;
	if (channel_set_request_handler(channel, pf_request, &state) == -1 ||
	    clock_gettime(CLOCK_MONOTONIC, &started) == -1)
		goto done;
	for (;;) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			break;
		elapsed = (now.tv_sec - started.tv_sec) * 1000 +
		    (now.tv_nsec - started.tv_nsec) / 1000000;
		if (elapsed >= 5000)
			break;
		ready = channel_wait(channel, channel_wants_write(channel) > 0,
		    5000 - elapsed);
		if (ready <= 0)
			break;
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
	}
	result = state.done ? 0 : 1;
done:
	if (state.pf_fd >= 0)
		(void)close(state.pf_fd);
	channel_destroy(channel);
	return (result);
}
