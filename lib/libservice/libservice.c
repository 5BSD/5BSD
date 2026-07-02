/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice — client library for services managed by serviced(8).
 *
 * Wraps mac_capability ioctls into a clean API.  Services link against this
 * library and never include mac_capability headers.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_capprotect_proto.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libservice.h"
#include "serviced_svc_proto.h"

static int pair_fd = -1;
static int capprotect_fd = -1;
static uint64_t next_token = 1;

/*
 * Pending notification queue.  Notifications (SVC_OP_NEW_CLIENT)
 * can arrive while we're waiting for an RPC reply.  We queue them
 * here and deliver them from service_accept().
 */
#define	PENDING_MAX	256

struct pending_notify {
	struct svc_new_client_msg msg;
	int	fd;
};

static struct pending_notify pending[PENDING_MAX];
static int npending;

static void
queue_notification(const struct svc_new_client_msg *msg, int fd)
{

	if (npending < PENDING_MAX) {
		pending[npending].msg = *msg;
		pending[npending].fd = fd;
		npending++;
	} else {
		/* Queue full — drop the notification. */
		if (fd >= 0)
			close(fd);
	}
}

/*
 * Send a request and wait for the reply.
 * Notifications that arrive before the reply are queued.
 */
static int
rpc(const void *req, uint32_t reqlen, int *reply_fd)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	union {
		struct svc_reply rpl;
		struct svc_new_client_msg notify;
	} buf;
	uint64_t token;
	int fd;

	if (pair_fd < 0) {
		errno = ENOTCONN;
		return (-1);
	}

	token = next_token++;

	memset(&sa, 0, sizeof(sa));
	sa.payload = req;
	sa.payload_len = reqlen;
	sa.reply_token = token;

	if (ioctl(pair_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1)
		return (-1);

	for (;;) {
		uint32_t op;

		fd = -1;
		memset(&ra, 0, sizeof(ra));
		ra.payload = &buf;
		ra.payload_len = sizeof(buf);
		ra.fds = &fd;
		ra.nfds = 1;

		if (ioctl(pair_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}

		/* Check if this is our reply (matching token). */
		if (ra.reply_token == token) {
			if (reply_fd != NULL)
				*reply_fd = fd;
			else if (fd >= 0)
				close(fd);

			if (buf.rpl.status != 0) {
				errno = buf.rpl.status;
				return (-1);
			}
			return (0);
		}

		/*
		 * Not our reply — check if it's a notification.
		 * Queue it for service_accept().
		 */
		if (ra.payload_len >= sizeof(uint32_t)) {
			memcpy(&op, &buf, sizeof(op));
			if (op == SVC_OP_NEW_CLIENT) {
				queue_notification(&buf.notify, fd);
				continue;
			}
		}

		/* Unknown message — discard. */
		if (fd >= 0)
			close(fd);
	}
}

int
service_init(void)
{
	const char *s;

	s = getenv("ORACLED_PAIR_FD");
	if (s == NULL) {
		errno = ENOENT;
		return (-1);
	}
	pair_fd = (int)strtol(s, NULL, 10);
	if (pair_fd < 0) {
		pair_fd = -1;
		errno = EINVAL;
		return (-1);
	}
	s = getenv("ORACLED_CAPPROTECT_FD");
	if (s != NULL && s[0] != '\0') {
		capprotect_fd = (int)strtol(s, NULL, 10);
		if (capprotect_fd < 0)
			capprotect_fd = -1;
	}
	return (0);
}

int
service_pair_fd(void)
{

	return (pair_fd);
}

int
service_protect(uint32_t flags)
{
	struct mac_capability_call_args call;
	struct cp_request req;

	if (capprotect_fd < 0) {
		errno = ENOTSUP;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);

	if (ioctl(capprotect_fd, MAC_CAPABILITY_CALL, &call) == -1)
		return (-1);
	return (0);
}

int
service_ready(void)
{
	struct svc_req_hdr req;

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_READY;
	return (rpc(&req, sizeof(req), NULL));
}

int
service_register(const char *name)
{
	struct svc_register_req req;

	if (strlen(name) > SERVICED_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_REGISTER;
	strlcpy(req.name, name, sizeof(req.name));
	return (rpc(&req, sizeof(req), NULL));
}

int
service_unregister(const char *name)
{
	struct svc_unregister_req req;

	if (strlen(name) > SERVICED_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_UNREGISTER;
	strlcpy(req.name, name, sizeof(req.name));
	return (rpc(&req, sizeof(req), NULL));
}

int
service_lookup(const char *name)
{
	struct svc_lookup_req req;
	int fd;

	if (strlen(name) > SERVICED_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_LOOKUP;
	strlcpy(req.name, name, sizeof(req.name));

	if (rpc(&req, sizeof(req), &fd) == -1)
		return (-1);
	if (fd < 0) {
		errno = EIO;
		return (-1);
	}
	return (fd);
}

int
service_accept(char *client_label, size_t labelsz)
{
	struct mac_capability_recvmsg_args ra;
	struct svc_new_client_msg msg;
	int client_fd;

	if (pair_fd < 0) {
		errno = ENOTCONN;
		return (-1);
	}

	/* Check pending queue first (notifications queued during rpc). */
	if (npending > 0) {
		struct pending_notify *pn;

		pn = &pending[0];
		if (client_label != NULL && labelsz > 0)
			strlcpy(client_label, pn->msg.client_label, labelsz);
		client_fd = pn->fd;

		/* Shift queue down. */
		npending--;
		if (npending > 0)
			memmove(&pending[0], &pending[1],
			    (size_t)npending * sizeof(pending[0]));
		return (client_fd);
	}

	/* No pending — block on the pair fd. */
	for (;;) {
		uint32_t op;

		client_fd = -1;
		memset(&ra, 0, sizeof(ra));
		ra.payload = &msg;
		ra.payload_len = sizeof(msg);
		ra.fds = &client_fd;
		ra.nfds = 1;

		if (ioctl(pair_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}

		if (ra.payload_len >= sizeof(uint32_t)) {
			memcpy(&op, &msg, sizeof(op));
			if (op == SVC_OP_NEW_CLIENT)
				break;
		}

		/* Not a notification — discard. */
		if (client_fd >= 0)
			close(client_fd);
	}

	if (client_label != NULL && labelsz > 0)
		strlcpy(client_label, msg.client_label, labelsz);

	return (client_fd);
}

int
service_send(int fd, const void *data, size_t len)
{
	struct mac_capability_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = data;
	sa.payload_len = (uint32_t)len;

	if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1)
		return (-1);
	return (0);
}

ssize_t
service_recv(int fd, void *buf, size_t bufsz, int *peer_fd)
{
	struct mac_capability_recvmsg_args ra;
	int pfd;

	pfd = -1;
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = (uint32_t)bufsz;
	if (peer_fd != NULL) {
		ra.fds = &pfd;
		ra.nfds = 1;
	}

	for (;;) {
		if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == 0)
			break;
		if (errno == EINTR)
			continue;
		return (-1);
	}

	if (peer_fd != NULL)
		*peer_fd = pfd;
	return ((ssize_t)ra.payload_len);
}
