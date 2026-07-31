/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/socket.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>

#include "tracecmp.h"
#include "tracecmp_probes.h"

#define	TRACECMP_PROVIDER_NAME	TRACECMP_INTERFACE

union tracecmp_buffer {
	max_align_t align;
	uint8_t bytes[TRACECMP_MAX_MESSAGE];
};

static void
audit_policy(const char *label, const char *operation, int error)
{

	(void)audit_submit((short)AUE_TRACECMP_POLICY, getuid(), (char)error,
	    error != 0, "client=%s operation=%s result=%d", label, operation,
	    error);
}

static int
harden_channel(int fd)
{

	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

struct worker_state {
	struct tracecmp_stats	stats;
	const char		*client_label;
	int			 terminal_error;
};

static int
send_reply(struct channel_message *request_message,
    const struct tracecmp_msg *request, int error, const void *payload,
    size_t payload_length, int attached_fd)
{
	union tracecmp_buffer buffer;
	struct tracecmp_msg *reply;
	const int *fds;
	size_t nfds;

	memset(&buffer, 0, sizeof(buffer));
	reply = (void *)buffer.bytes;
	if (tracecmp_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1)
		return (-1);
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	fds = attached_fd >= 0 ? &attached_fd : NULL;
	nfds = attached_fd >= 0 ? 1 : 0;
	if (tracecmp_validate_message(reply,
	    sizeof(*reply) + (error == 0 ? payload_length : 0),
	    TRACECMP_MESSAGE_REPLY) == -1 ||
	    tracecmp_validate_fds(reply, nfds, TRACECMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = reply,
		.length = sizeof(*reply) +
		    (error == 0 ? payload_length : 0),
		.fds = fds,
		.nfds = nfds
	    }));
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *request_message, void *argument)
{
	struct worker_state *state;
	struct tracecmp_hello_reply hello;
	const struct tracecmp_msg *message;
	size_t length;
	int error;

	state = argument;
	message = channel_message_data(request_message);
	length = channel_message_length(request_message);
	if (tracecmp_validate_message(message, length,
	    TRACECMP_MESSAGE_REQUEST) == -1 ||
	    tracecmp_validate_fds(message,
	    channel_message_fd_count(request_message),
	    TRACECMP_MESSAGE_REQUEST) == -1) {
		state->terminal_error = EPROTO;
		channel_message_free(request_message);
		return;
	}

	error = 0;
	switch (message->opcode) {
	case TRACECMP_OP_HELLO:
		memset(&hello, 0, sizeof(hello));
		hello.version = TRACECMP_ABI_VERSION;
		hello.features = 0;
		if (send_reply(request_message, message, 0, &hello,
		    sizeof(hello), -1) == -1)
			state->terminal_error = errno;
		break;
	case TRACECMP_OP_OPEN:
		error = EACCES;
		break;
	case TRACECMP_OP_STATS:
		if (send_reply(request_message, message, 0, &state->stats,
		    sizeof(state->stats), -1) == -1)
			state->terminal_error = errno;
		break;
	default:
		state->terminal_error = EPROTO;
		break;
	}
	if (error != 0) {
		state->stats.rejected++;
		audit_policy(state->client_label, "request-denied", error);
		TRACECMPD_PROBE_REJECT(
		    __DECONST(char *, state->client_label),
		    message->opcode, error);
		if (send_reply(request_message, message, error, NULL, 0, -1) ==
		    -1)
			state->terminal_error = errno;
	}
	channel_message_free(request_message);
}

static int
worker(int fd, int barrier, const char *client_label,
    uint64_t instance_id __unused)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct worker_state state;
	struct channel *channel;
	struct pollfd descriptor;
	char byte;
	int error, result, wants_write;

	memset(&state, 0, sizeof(state));
	state.client_label = client_label;
	if (service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1)
		error = errno;
	else {
		service_worker_drop_inherited_authority();
		error = cap_enter() == -1 ? errno : 0;
	}
	if (write(barrier, &error, sizeof(error)) != sizeof(error) ||
	    error != 0)
		return (1);
	if (read(barrier, &byte, 1) != 1)
		return (1);
	close(barrier);

	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, handle_request, &state) ==
	    -1) {
		channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel_fd(channel);
		descriptor.events = POLLIN | (wants_write ? POLLOUT : 0);
		do {
			result = poll(&descriptor, 1, -1);
		} while (result == -1 && errno == EINTR);
		if (result == -1)
			break;
		if ((descriptor.revents & POLLOUT) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((descriptor.revents &
		    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
		if (state.terminal_error != 0) {
			errno = state.terminal_error;
			break;
		}
	}
	channel_destroy(channel);
	return (0);
}

static int
start_session(int fd, const char *peer_label)
{
	static uint64_t next_instance;
	char byte;
	int syncfd[2], pd, child_error, error;
	ssize_t n;
	pid_t pid;
	uint64_t instance_id;

	instance_id = ++next_instance;
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd) == -1) {
		error = errno;
		goto reject;
	}
	if (harden_channel(fd) == -1 ||
	    cap_xfer_limit(syncfd[0], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(syncfd[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(syncfd[0], CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		goto reject;
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		goto reject;
	}
	if (pid == 0) {
		close(syncfd[0]);
		_exit(worker(fd, syncfd[1], peer_label, instance_id));
	}
	close(syncfd[1]);
	n = read(syncfd[0], &child_error, sizeof(child_error));
	if (n != sizeof(child_error) || child_error != 0) {
		error = n == sizeof(child_error) ? child_error : EIO;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		goto reject;
	}
	close(pd);
	byte = 1;
	(void)write(syncfd[0], &byte, 1);
	close(syncfd[0]);
	audit_policy(peer_label, "session-bootstrap", 0);
	TRACECMPD_PROBE_SESSION(__DECONST(char *, peer_label),
	    instance_id, 0);
	return (0);

reject:
	audit_policy(peer_label, "session-bootstrap", error);
	TRACECMPD_PROBE_SESSION(__DECONST(char *, peer_label),
	    instance_id, error);
	errno = error;
	return (-1);
}

int
main(void)
{
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	openlog("tracecmp", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, TRACECMP_PROVIDER_NAME,
	    &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (start_session(fd, identity.client_label) == -1)
			syslog(LOG_WARNING, "session for %s rejected: %m",
			    identity.client_label);
		close(fd);
	}

fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
