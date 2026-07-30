/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <net/netmap_user.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libnetmap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>
#include <netmap_bearer.h>

#include "netmapd_policy.h"
#include "netmapd_probes.h"

union bearer_buffer {
	max_align_t align;
	struct {
		struct netmap_bearer_msg message;
		uint8_t payload[NETMAP_BEARER_MAX_MESSAGE -
		    sizeof(struct netmap_bearer_msg)];
	} wire;
};

static int dev_directory = -1;

static void
audit_bearer(const char *label, const char *interface, int error)
{

	(void)audit_submit((short)AUE_NETMAPD_BEARER, getuid(), (char)error,
	    error != 0, "client=%s interface=%s result=%d", label, interface,
	    error);
}

static int
send_reply(int fd, const struct netmap_bearer_msg *request, int error,
    const void *payload, size_t payload_length, int bearer_fd)
{
	union bearer_buffer buffer;
	struct netmap_bearer_msg *reply;
	const int *fds;
	size_t nfds;

	memset(&buffer, 0, sizeof(buffer));
	reply = &buffer.wire.message;
	reply->magic = NETMAP_BEARER_MAGIC;
	reply->version = NETMAP_BEARER_VERSION;
	reply->opcode = request->opcode;
	reply->flags = NETMAP_BEARER_MSG_F_REPLY;
	reply->length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	reply->request_id = request->request_id;
	reply->status = error == 0 ? 0 : -error;
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	fds = bearer_fd >= 0 ? &bearer_fd : NULL;
	nfds = bearer_fd >= 0 ? 1 : 0;
	if (netmapd_validate_message(reply, reply->length, nfds) == -1)
		return (-1);
	return (service_send_fds(fd, reply, reply->length, fds, nfds));
}

static int
limit_bearer_fd(int fd)
{
	static const cap_ioctl_t ioctls[] = {
	    NIOCTXSYNC, NIOCRXSYNC
	};
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_EVENT, CAP_FCNTL, CAP_FSTAT, CAP_IOCTL,
	    CAP_MMAP_RW);
	if (cap_rights_limit(fd, &rights) == -1 ||
	    cap_fcntls_limit(fd, CAP_FCNTL_GETFL) == -1 ||
	    cap_ioctls_limit(fd, ioctls, nitems(ioctls)) == -1)
		return (-1);
	return (0);
}

static int
create_bearer(int client_fd, const char *label,
    const struct netmap_bearer_msg *message)
{
	const struct netmap_bearer_create *request;
	struct netmap_bearer_reply reply;
	struct nmport_d *port;
	char portspec[128], mode[3];
	uint64_t bearer_id;
	int device_fd, fd, error, length;

	request = (const void *)(message + 1);
	if (netmapd_validate_create(request) == -1) {
		error = errno;
		goto reject;
	}
	mode[0] = '\0';
	if ((request->flags & (NETMAP_BEARER_F_RX | NETMAP_BEARER_F_TX)) ==
	    NETMAP_BEARER_F_RX)
		strlcpy(mode, "/R", sizeof(mode));
	else if ((request->flags &
	    (NETMAP_BEARER_F_RX | NETMAP_BEARER_F_TX)) ==
	    NETMAP_BEARER_F_TX)
		strlcpy(mode, "/T", sizeof(mode));
	if (request->slots != 0)
		length = snprintf(portspec, sizeof(portspec), "%s%s@conf:slots=%u",
		    request->interface, mode, request->slots);
	else
		length = snprintf(portspec, sizeof(portspec), "%s%s",
		    request->interface, mode);
	if (length < 0 || (size_t)length >= sizeof(portspec)) {
		error = ENAMETOOLONG;
		goto reject;
	}
	port = nmport_prepare(portspec);
	if (port == NULL) {
		error = errno;
		goto reject;
	}
	device_fd = openat(dev_directory, "netmap", O_RDWR | O_CLOEXEC);
	if (device_fd == -1 ||
	    nmport_register_fd(port, device_fd) == -1 ||
	    nmport_mmap(port) == -1) {
		error = errno;
		if (device_fd >= 0)
			close(device_fd);
		nmport_close(port);
		goto reject;
	}
	close(device_fd);
	fd = fcntl(port->fd, F_DUPFD_CLOEXEC, 0);
	if (fd == -1 || limit_bearer_fd(fd) == -1) {
		error = errno;
		if (fd >= 0)
			close(fd);
		nmport_close(port);
		goto reject;
	}
	arc4random_buf(&bearer_id, sizeof(bearer_id));
	if (bearer_id == 0)
		bearer_id = 1;
	memset(&reply, 0, sizeof(reply));
	reply.bearer_id = bearer_id;
	reply.generation = 1;
	reply.mapping_offset = port->reg.nr_offset;
	reply.mapping_size = port->reg.nr_memsize;
	reply.queue_count = (port->last_rx_ring >= port->first_rx_ring ?
	    port->last_rx_ring - port->first_rx_ring + 1 : 0);
	reply.slot_count = port->reg.nr_rx_slots;
	reply.first_tx_ring = port->first_tx_ring;
	reply.last_tx_ring = port->last_tx_ring;
	reply.first_rx_ring = port->first_rx_ring;
	reply.last_rx_ring = port->last_rx_ring;
	error = send_reply(client_fd, message, 0, &reply, sizeof(reply), fd) ==
	    -1 ? errno : 0;
	close(fd);
	nmport_close(port);
	audit_bearer(label, request->interface, error);
	NETMAPD_PROBE_BEARER(label, request->interface, bearer_id, error);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);

reject:
	audit_bearer(label, request->interface, error);
	NETMAPD_PROBE_BEARER(label, request->interface, 0, error);
	return (send_reply(client_fd, message, error, NULL, 0, -1));
}

static void
handle_client(int fd, const char *label)
{
	union bearer_buffer buffer;
	size_t nfds;
	ssize_t received;

	for (;;) {
		nfds = 0;
		received = service_recv_fds(fd, &buffer, sizeof(buffer), NULL,
		    &nfds);
		if (received == -1)
			break;
		if (netmapd_validate_message(&buffer.wire.message,
		    (size_t)received, nfds) == -1) {
			audit_bearer(label, "(malformed)", EPROTO);
			break;
		}
		NETMAPD_PROBE_REQUEST(label, buffer.wire.message.opcode,
		    buffer.wire.message.length);
		switch (buffer.wire.message.opcode) {
		case NETMAP_BEARER_OP_HELLO:
			if (send_reply(fd, &buffer.wire.message, 0, NULL, 0,
			    -1) == -1)
				return;
			break;
		case NETMAP_BEARER_OP_CREATE:
			if (create_bearer(fd, label, &buffer.wire.message) == -1)
				return;
			break;
		default:
			if (send_reply(fd, &buffer.wire.message, EOPNOTSUPP,
			    NULL, 0, -1) == -1)
				return;
			break;
		}
	}
}

int
main(void)
{
	cap_rights_t dev_rights;
	char label[COMPONENT_SESSION_LABEL_MAX];
	int fd;

	openlog("netmapd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (service_init() == -1 ||
	    service_authorize_capabilities() == -1 ||
	    (dev_directory = open("/dev", O_RDONLY | O_DIRECTORY |
	    O_CLOEXEC)) == -1 ||
	    service_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1 ||
	    service_register(NETMAPD_PROVIDER) == -1) {
		syslog(LOG_ERR, "initialization: %m");
		return (1);
	}
	cap_rights_init(&dev_rights, CAP_EVENT, CAP_FCNTL, CAP_FSTAT, CAP_IOCTL,
	    CAP_LOOKUP, CAP_MMAP_RW, CAP_READ, CAP_WRITE);
	if (cap_rights_limit(dev_directory, &dev_rights) == -1 ||
	    cap_enter() == -1 || service_ready() == -1) {
		syslog(LOG_ERR, "capability sandbox: %m");
		return (1);
	}
	for (;;) {
		fd = service_accept(label, sizeof(label));
		if (fd == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "service_accept: %m");
			return (1);
		}
		handle_client(fd, label);
		close(fd);
	}
}
