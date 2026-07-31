/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Private-component bootstrap lifecycle over libchannel.
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>

#include "component_session.h"
#include "libservice.h"

#define	COMPONENT_BOOTSTRAP_TIMEOUT_MS	2000

_Static_assert(SERVICE_COMPONENT_MEMBER_PROCDESC ==
    COMPONENT_SESSION_MEMBER_PROCDESC, "component member ABI drift");
_Static_assert(SERVICE_COMPONENT_MEMBER_COALITION ==
    COMPONENT_SESSION_MEMBER_COALITION, "component member ABI drift");

struct service_component_bootstrap {
	struct channel		*channel;
	struct channel_message	*message;
	struct component_session_bootstrap header;
};

struct receive_state {
	struct channel_message	*message;
	int			 error;
};

static void
receive_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	struct receive_state *state;

	state = argument;
	if (state->message != NULL) {
		state->error = EPROTO;
		channel_message_free(message);
		return;
	}
	state->message = message;
}

static int
remaining_timeout(const struct timespec *deadline)
{
	struct timespec now;
	int64_t milliseconds;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (-1);
	milliseconds = (deadline->tv_sec - now.tv_sec) * 1000 +
	    (deadline->tv_nsec - now.tv_nsec + 999999) / 1000000;
	if (milliseconds <= 0) {
		errno = ETIMEDOUT;
		return (-1);
	}
	if (milliseconds > COMPONENT_BOOTSTRAP_TIMEOUT_MS)
		milliseconds = COMPONENT_BOOTSTRAP_TIMEOUT_MS;
	return ((int)milliseconds);
}

static int
pump_until_request(struct channel *channel, struct receive_state *state)
{
	struct pollfd descriptor;
	struct timespec deadline;
	int result, timeout;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
		return (-1);
	deadline.tv_sec += COMPONENT_BOOTSTRAP_TIMEOUT_MS / 1000;
	deadline.tv_nsec +=
	    (COMPONENT_BOOTSTRAP_TIMEOUT_MS % 1000) * 1000000;
	if (deadline.tv_nsec >= 1000000000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000;
	}
	while (state->message == NULL && state->error == 0) {
		timeout = remaining_timeout(&deadline);
		if (timeout == -1)
			return (-1);
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel_fd(channel);
		descriptor.events = POLLIN;
		do {
			result = poll(&descriptor, 1, timeout);
		} while (result == -1 && errno == EINTR);
		if (result == 0) {
			errno = ETIMEDOUT;
			return (-1);
		}
		if (result == -1)
			return (-1);
		if ((descriptor.revents &
		    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0 &&
		    channel_dispatch(channel) == -1)
			return (-1);
	}
	if (state->error != 0) {
		errno = state->error;
		return (-1);
	}
	return (0);
}

int
service_component_accept(int fd,
    struct service_component_bootstrap **bootstrapp)
{
	struct channel_options channel_options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct component_session_bootstrap message;
	struct service_component_bootstrap *bootstrap;
	struct receive_state state;
	const void *payload;
	size_t length;
	int error, owned;

	if (fd < 0 || bootstrapp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*bootstrapp = NULL;
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned == -1)
		return (-1);
	bootstrap = calloc(1, sizeof(*bootstrap));
	if (bootstrap == NULL) {
		close(owned);
		return (-1);
	}
	if (channel_create(owned, &channel_options, &bootstrap->channel) == -1) {
		error = errno;
		close(owned);
		free(bootstrap);
		errno = error;
		return (-1);
	}
	memset(&state, 0, sizeof(state));
	if (channel_set_request_handler(bootstrap->channel, receive_request,
	    &state) == -1 ||
	    pump_until_request(bootstrap->channel, &state) == -1)
		goto fail;
	bootstrap->message = state.message;
	state.message = NULL;
	payload = channel_message_data(bootstrap->message);
	length = channel_message_length(bootstrap->message);
	if (length > sizeof(message) ||
	    channel_message_fd_count(bootstrap->message) >
	    COMPONENT_SESSION_RESOURCE_MAX)
		goto protocol;
	memset(&message, 0, sizeof(message));
	memcpy(&message, payload, length);
	if (length != sizeof(message) ||
	    channel_message_token(bootstrap->message) == 0 ||
	    message.magic != COMPONENT_SESSION_MAGIC ||
	    message.version != COMPONENT_SESSION_VERSION ||
	    message.header_size != sizeof(message) ||
	    message.reserved[0] != 0 || message.reserved[1] != 0 ||
	    message.reserved[2] != 0 || message.reserved[3] != 0 ||
	    message.name[0] == '\0' ||
	    memchr(message.name, '\0', sizeof(message.name)) == NULL ||
	    message.interface[0] == '\0' ||
	    memchr(message.interface, '\0', sizeof(message.interface)) == NULL ||
	    message.interface_version[0] == '\0' ||
	    memchr(message.interface_version, '\0',
	    sizeof(message.interface_version)) == NULL ||
	    message.client_label[0] == '\0' ||
	    memchr(message.client_label, '\0',
	    sizeof(message.client_label)) == NULL)
		goto protocol;
	bootstrap->header = message;
	*bootstrapp = bootstrap;
	return (0);

protocol:
	errno = EPROTO;
fail:
	error = errno;
	if (state.message != NULL)
		channel_message_free(state.message);
	service_component_abort(bootstrap);
	errno = error;
	return (-1);
}

static int
service_component_respond(struct service_component_bootstrap *bootstrap,
    int status, uint32_t member_type, int member_fd)
{
	struct component_session_reply reply;
	struct pollfd descriptor;
	struct timespec deadline;
	const int *fds;
	size_t nfds;
	int result, timeout;

	if (bootstrap == NULL || bootstrap->message == NULL || status < 0 ||
	    (status == 0 && member_fd < 0) ||
	    (status == 0 &&
	    member_type != COMPONENT_SESSION_MEMBER_PROCDESC &&
	    member_type != COMPONENT_SESSION_MEMBER_COALITION) ||
	    (status != 0 && member_fd >= 0)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&reply, 0, sizeof(reply));
	reply.magic = COMPONENT_SESSION_MAGIC;
	reply.version = COMPONENT_SESSION_VERSION;
	reply.header_size = sizeof(reply);
	reply.status = status;
	reply.member_type = status == 0 ? member_type : 0;
	reply.instance_id = bootstrap->header.instance_id;
	fds = status == 0 ? &member_fd : NULL;
	nfds = status == 0 ? 1 : 0;
	if (channel_send_reply(bootstrap->message,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = &reply,
		.length = sizeof(reply),
		.fds = fds,
		.nfds = nfds
	    }) == -1)
		goto fail;
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
		goto fail;
	deadline.tv_sec += COMPONENT_BOOTSTRAP_TIMEOUT_MS / 1000;
	deadline.tv_nsec +=
	    (COMPONENT_BOOTSTRAP_TIMEOUT_MS % 1000) * 1000000;
	if (deadline.tv_nsec >= 1000000000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000;
	}
	while (channel_wants_write(bootstrap->channel) == 1) {
		timeout = remaining_timeout(&deadline);
		if (timeout == -1)
			goto fail;
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel_fd(bootstrap->channel);
		descriptor.events = POLLOUT;
		do {
			result = poll(&descriptor, 1, timeout);
		} while (result == -1 && errno == EINTR);
		if (result == 0) {
			errno = ETIMEDOUT;
			goto fail;
		}
		if (result == -1 || channel_flush(bootstrap->channel) == -1)
			goto fail;
	}
	service_component_abort(bootstrap);
	return (0);

fail:
	result = errno;
	service_component_abort(bootstrap);
	errno = result;
	return (-1);
}

const char *
service_component_name(const struct service_component_bootstrap *bootstrap)
{

	return (bootstrap != NULL ? bootstrap->header.name : NULL);
}

const char *
service_component_interface(
    const struct service_component_bootstrap *bootstrap)
{

	return (bootstrap != NULL ? bootstrap->header.interface : NULL);
}

const char *
service_component_interface_version(
    const struct service_component_bootstrap *bootstrap)
{

	return (bootstrap != NULL ? bootstrap->header.interface_version : NULL);
}

const char *
service_component_client_label(
    const struct service_component_bootstrap *bootstrap)
{

	return (bootstrap != NULL ? bootstrap->header.client_label : NULL);
}

uint64_t
service_component_instance_id(
    const struct service_component_bootstrap *bootstrap)
{

	return (bootstrap != NULL ? bootstrap->header.instance_id : 0);
}

size_t
service_component_resource_count(
    const struct service_component_bootstrap *bootstrap)
{

	return (bootstrap != NULL ?
	    channel_message_fd_count(bootstrap->message) : 0);
}

int
service_component_take_resource(struct service_component_bootstrap *bootstrap,
    size_t slot)
{

	if (bootstrap == NULL || bootstrap->message == NULL ||
	    slot >= channel_message_fd_count(bootstrap->message)) {
		errno = EINVAL;
		return (-1);
	}
	return (channel_message_take_fd(bootstrap->message, slot));
}

int
service_component_complete(struct service_component_bootstrap *bootstrap,
    enum service_component_member_type member_type, int member_fd)
{

	return (service_component_respond(bootstrap, 0, member_type,
	    member_fd));
}

int
service_component_fail(struct service_component_bootstrap *bootstrap,
    int error)
{

	if (error <= 0 || error > ELAST) {
		errno = EINVAL;
		return (-1);
	}
	return (service_component_respond(bootstrap, error, 0, -1));
}

void
service_component_abort(struct service_component_bootstrap *bootstrap)
{

	if (bootstrap == NULL)
		return;
	if (bootstrap->message != NULL)
		channel_message_free(bootstrap->message);
	if (bootstrap->channel != NULL)
		channel_destroy(bootstrap->channel);
	explicit_bzero(bootstrap, sizeof(*bootstrap));
	free(bootstrap);
}
