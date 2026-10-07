/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <channel.h>
#include <libservice.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include "controller_protocol.h"

struct controller_client {
	struct channel *channel;
	service_rights_t rights;
	uintptr_t timer;
	bool replied;
	bool retired;
};
static struct controller_client clients[16];
static int queue;
static uintptr_t next_timer = 1;

/* Only a stamped session grant authorizes privileged controller access. */
static int
controller_validate(service_rights_t rights,
    const struct blued_controller_request *request)
{
	size_t i, len;

	if (!service_rights_allow(rights, BLUED_CONTROLLER_OPEN))
		return (EACCES);
	len = strnlen(request->adapter, sizeof(request->adapter));
	if (request->magic != BLUED_CONTROLLER_MAGIC || request->reserved != 0 ||
	    len == 0 || len == sizeof(request->adapter))
		return (EINVAL);
	for (i = 0; i < len; i++)
		if (!isalnum((unsigned char)request->adapter[i]) &&
		    request->adapter[i] != '_' && request->adapter[i] != '-')
			return (EINVAL);
	return (0);
}

/* Validated admission, then delegate only the already-bound controller. */
static int
controller_open(service_rights_t granted,
    const struct blued_controller_request *request)
{
	cap_rights_t rights;
	const unsigned long commands[] = {
	    SIOC_HCI_RAW_NODE_GET_CON_LIST, SIOC_HCI_RAW_NODE_INIT };
	int fd, error;

	error = controller_validate(granted, request);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	fd = bt_devopen(request->adapter);
	if (fd < 0)
		return (-1);
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_IOCTL,
	    CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_FCNTL, CAP_FSTAT);
	if (cap_rights_limit(fd, &rights) == -1 ||
	    cap_ioctls_limit(fd, commands, 2) == -1 ||
	    cap_fcntls_limit(fd, CAP_FCNTL_GETFL | CAP_FCNTL_SETFL) == -1 ||
	    service_harden_fd(fd, SERVICE_HARDEN_XFER_ONCE) == -1) {
		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	return (fd);
}

static void
controller_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	struct controller_client *client = argument;
	struct blued_controller_request request;
	struct blued_controller_reply reply = { BLUED_CONTROLLER_MAGIC, EPROTO };
	struct channel_outgoing out = CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply));
	int fd = -1;

	if (client->replied) {
		channel_message_free(message);
		return;
	}
	client->replied = true;
	if (channel_message_length(message) == sizeof(request) &&
	    channel_message_fd_count(message) == 0) {
		memcpy(&request, channel_message_data(message), sizeof(request));
		fd = controller_open(client->rights, &request);
		reply.error = fd < 0 ? errno : 0;
	}
	if (fd >= 0) {
		out.fds = &fd;
		out.nfds = 1;
	}
	(void)channel_send_reply(message, &out);
	if (fd >= 0)
		close(fd);
	channel_message_free(message);
}

static void
controller_close(struct controller_client *client)
{
	struct kevent ev;

	if (client->channel == NULL)
		return;
	EV_SET(&ev, client->timer, EVFILT_TIMER, EV_DELETE, 0, 0, client);
	(void)kevent(queue, &ev, 1, NULL, 0, NULL);
	channel_destroy(client->channel);
	client->channel = NULL;
	client->retired = true;
}

static void
controller_accept(struct service_listener *listener)
{
	struct service_identity id = { .size = sizeof(id) };
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct controller_client *client = NULL;
	struct kevent ev[2];
	size_t i;
	int fd;

	if (service_listener_accept(listener, &id, &fd) == -1)
		return;
	/* SwitchBoard checks the anointment; also honor attenuated session rights. */
	if (!service_rights_allow(id.rights, BLUED_CONTROLLER_OPEN)) {
		close(fd);
		return;
	}
	for (i = 0; i < sizeof(clients) / sizeof(clients[0]); i++)
		if (clients[i].channel == NULL && !clients[i].retired) {
			client = &clients[i];
			break;
		}
	if (client == NULL) {
		close(fd);
		return;
	}
	memset(client, 0, sizeof(*client));
	client->rights = id.rights;
	client->timer = next_timer++;
	options.max_queued_messages = 2;
	options.max_queued_bytes = 1024;
	options.max_queued_fds = 1;
	if (channel_create(fd, &options, &client->channel) == -1) {
		close(fd);
		return;
	}
	EV_SET(&ev[0], channel_fd(client->channel), EVFILT_READ,
	    EV_ADD, 0, 0, client);
	EV_SET(&ev[1], client->timer, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
	    0, 2000, client);
	if (channel_set_request_handler(client->channel, controller_request, client) == -1 ||
	    kevent(queue, ev, 2, NULL, 0, NULL) == -1)
		controller_close(client);
}

/* Nonblocking step, validated with actual channels and transferred sockets. */
static void
controller_event(struct controller_client *client, const struct kevent *event)
{
	struct kevent change;
	int wants_write;

	if (client->channel == NULL)
		return;
	if ((event->flags & (EV_EOF | EV_ERROR)) != 0 ||
	    event->filter == EVFILT_TIMER)
		goto close;
	if (event->filter == EVFILT_READ && channel_dispatch(client->channel) == -1)
		goto close;
	if (channel_flush(client->channel) == -1)
		goto close;
	wants_write = channel_wants_write(client->channel);
	if (wants_write < 0)
		goto close;
	/* Keep the reply transport alive until the peer closes or times out. */
	EV_SET(&change, channel_fd(client->channel), EVFILT_WRITE,
	    wants_write ? EV_ADD | EV_ENABLE : EV_DELETE, 0, 0, client);
	if (kevent(queue, &change, 1, NULL, 0, NULL) != -1 ||
	    (!wants_write && errno == ENOENT))
		return;
close:
	controller_close(client);
}

int
main(void)
{
	struct service_context *context;
	struct service_provider *provider;
	struct service_listener *listener;
	struct kevent changes[2], events[32];
	size_t j;
	int i, n, supervisor;

	queue = kqueue();
	if (queue < 0 || service_acquire(&context) == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, BLUED_CONTROLLER_SERVICE, &listener) == -1)
		err(1, "Bluetooth controller broker startup");
	supervisor = service_supervisor_fd(context);
	if (supervisor < 0)
		err(1, "Bluetooth controller supervisor");
	EV_SET(&changes[0], service_listener_fd(listener), EVFILT_READ, EV_ADD,
	    0, 0, &listener);
	EV_SET(&changes[1], supervisor, EVFILT_READ, EV_ADD, 0, 0, &supervisor);
	if (kevent(queue, changes, 2, NULL, 0, NULL) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		err(1, "Bluetooth controller broker readiness");
	for (;;) {
		n = kevent(queue, NULL, 0, events, 32, NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err(1, "Bluetooth controller broker events");
		}
		for (j = 0; j < sizeof(clients) / sizeof(clients[0]); j++)
			clients[j].retired = false;
		for (i = 0; i < n; i++) {
			/* Do not orphan a privileged broker or spin on a dead listener. */
			if (events[i].udata == &supervisor ||
			    (events[i].udata == &listener &&
			    (events[i].flags & (EV_EOF | EV_ERROR)) != 0)) {
				for (j = 0; j < sizeof(clients) / sizeof(clients[0]); j++)
					controller_close(&clients[j]);
				service_provider_destroy(provider);
				service_release(context);
				close(queue);
				return (0);
			}
			if (events[i].udata == &listener) {
				controller_accept(listener);
				continue;
			}
			for (j = 0; j < sizeof(clients) / sizeof(clients[0]); j++)
				if (events[i].udata == &clients[j])
					controller_event(&clients[j], &events[i]);
		}
	}
}
