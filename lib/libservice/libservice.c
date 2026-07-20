/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice — client library for services managed by serviced(8).
 *
 * Wraps common mac_capability lifecycle and transport ioctls into a clean API.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>
#include <dev/mac_capability/mac_capability_system_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libservice.h"
#include "serviced_svc_proto.h"

_Static_assert(SERVICE_PROTECT_PTRACE == CP_SF_PTRACE, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_SIGNAL == CP_SF_SIGNAL, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_VISIBLE == CP_SF_VISIBLE, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_WAIT == CP_SF_WAIT, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_SIGKILL == CP_SF_SIGKILL, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_SIGCONT == CP_SF_SIGCONT, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_SCHED == CP_SF_SCHED, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_CORE == CP_SF_CORE, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_KTRACE == CP_SF_KTRACE, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOPRIVS == CP_SF_NOPRIVS, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOFORK == CP_SF_NOFORK, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOIPC == CP_SF_NOIPC, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOFDRECV == CP_SF_NOFDRECV, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOEXEC == CP_SF_NOEXEC, "capprotect ABI");
_Static_assert(SERVICE_PROTECT_NOSOCK == CP_SF_NOSOCK, "capprotect ABI");

static int pair_fd = -1;
static int capprotect_fd = -1;
static uint64_t next_token = 1;

#define	SERVICE_CAPABILITY_MAX	4
struct service_capability_entry {
	char name[16];
	int fd;
};
static struct service_capability_entry capability_fds[SERVICE_CAPABILITY_MAX];
static unsigned ncapability_fds;

/*
 * Isolation authorization is a descriptor lease: the kernel revokes it when
 * the last reference to the activation token closes.  Keep private,
 * close-on-exec duplicates after consuming the descriptors supplied by
 * serviced.  They intentionally remain open until process exit.
 */
#define	SERVICE_TOKEN_MAX	128
static int activated_token_fds[SERVICE_TOKEN_MAX];
static unsigned nactivated_token_fds;

static bool
service_capability_name_valid(const char *name)
{

	return (strcmp(name, "mount") == 0 || strcmp(name, "node") == 0 ||
	    strcmp(name, "accounting") == 0 || strcmp(name, "identity") == 0);
}

static int
parse_capability_fds(void)
{
	struct mac_capability_info_args info;
	const char *value, *errstr;
	char *copy, *cursor, *entry, *equals;
	unsigned i;
	int fd, error;

	ncapability_fds = 0;
	value = getenv("ORACLED_CAPABILITY_FDS");
	if (value == NULL || value[0] == '\0')
		return (0);
	copy = strdup(value);
	if (copy == NULL)
		return (-1);
	cursor = copy;
	while ((entry = strsep(&cursor, ",")) != NULL) {
		equals = strchr(entry, '=');
		if (equals == NULL || equals == entry || equals[1] == '\0' ||
		    strchr(equals + 1, '=') != NULL ||
		    ncapability_fds == SERVICE_CAPABILITY_MAX)
			goto invalid;
		*equals++ = '\0';
		if (!service_capability_name_valid(entry))
			goto invalid;
		for (i = 0; i < ncapability_fds; i++)
			if (strcmp(capability_fds[i].name, entry) == 0)
				goto invalid;
		fd = (int)strtonum(equals, 0, INT_MAX, &errstr);
		if (errstr != NULL || fcntl(fd, F_GETFD) == -1)
			goto invalid;
		memset(&info, 0, sizeof(info));
		if (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == -1 ||
		    strncmp(info.name, entry, sizeof(info.name)) != 0)
			goto invalid;
		strlcpy(capability_fds[ncapability_fds].name, entry,
		    sizeof(capability_fds[ncapability_fds].name));
		capability_fds[ncapability_fds++].fd = fd;
	}
	free(copy);
	return (0);

invalid:
	error = errno;
	free(copy);
	ncapability_fds = 0;
	errno = error == ENOMEM ? ENOMEM : EINVAL;
	return (-1);
}

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
		memset(&buf, 0, sizeof(buf));
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
			/* Reject a reply too short to hold a status word,
			 * rather than reading uninitialized memory. */
			if (ra.payload_len != sizeof(buf.rpl)) {
				if (fd >= 0)
					close(fd);
				errno = EPROTO;
				return (-1);
			}
			if (ra.nfds != (uint32_t)(buf.rpl.status == 0 &&
			    reply_fd != NULL ? 1 : 0)) {
				if (fd >= 0)
					close(fd);
				errno = EPROTO;
				return (-1);
			}
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
		if (ra.payload_len == sizeof(buf.notify) && ra.nfds == 1 &&
		    buf.notify.flags == 0 &&
		    strnlen(buf.notify.client_label,
		    sizeof(buf.notify.client_label)) <
		    sizeof(buf.notify.client_label)) {
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
	struct mac_capability_info_args info;
	const char *s;
	const char *errstr;

	pair_fd = -1;
	capprotect_fd = -1;
	ncapability_fds = 0;
	s = getenv("ORACLED_CHANNEL_FD");
	if (s == NULL) {
		errno = ENOENT;
		return (-1);
	}
	/*
	 * Validate strictly: a malformed value must not silently resolve to
	 * fd 0 (stdin) and have every RPC target the wrong descriptor.
	 * strtonum() rejects non-numeric, empty, and out-of-range input.
	 */
	pair_fd = (int)strtonum(s, 0, INT_MAX, &errstr);
	if (errstr != NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&info, 0, sizeof(info));
	if (fcntl(pair_fd, F_GETFD) == -1) {
		pair_fd = -1;
		errno = EINVAL;
		return (-1);
	}
	if (ioctl(pair_fd, MAC_CAPABILITY_GETINFO, &info) == -1 ||
	    strcmp(info.name, "channel") != 0) {
		pair_fd = -1;
		errno = EINVAL;
		return (-1);
	}
	s = getenv("ORACLED_CAPPROTECT_FD");
	if (s != NULL && s[0] != '\0') {
		capprotect_fd = (int)strtonum(s, 0, INT_MAX, &errstr);
		if (errstr != NULL || fcntl(capprotect_fd, F_GETFD) == -1) {
			capprotect_fd = -1;
			errno = EINVAL;
			return (-1);
		}
		memset(&info, 0, sizeof(info));
		if (ioctl(capprotect_fd, MAC_CAPABILITY_GETINFO, &info) == -1 ||
		    strcmp(info.name, "capprotect") != 0) {
			capprotect_fd = -1;
			errno = EINVAL;
			return (-1);
		}
	}
	if (parse_capability_fds() != 0) {
		pair_fd = -1;
		capprotect_fd = -1;
		return (-1);
	}
	return (0);
}

int
service_channel_fd(void)
{

	return (pair_fd);
}

int
service_capability_fd(const char *name)
{
	unsigned i;

	if (pair_fd < 0) {
		errno = ENOTCONN;
		return (-1);
	}
	if (name == NULL || !service_capability_name_valid(name)) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < ncapability_fds; i++) {
		if (strcmp(capability_fds[i].name, name) == 0)
			return (capability_fds[i].fd);
	}
	errno = ENOENT;
	return (-1);
}

int
service_authorize_capabilities(void)
{
	struct mac_capability_call_args call;
	struct mac_capability_info_args info;
	struct fi_request req;
	struct fi_reply reply;
	struct sys_request sysreq;
	const char *value, *errstr;
	char *copy, *cursor, *field;
	int fds[SERVICE_TOKEN_MAX], owned_fds[SERVICE_TOKEN_MAX];
	bool system_token[SERVICE_TOKEN_MAX];
	unsigned i, j, nfds;
	int error;

	value = getenv("ORACLED_TOKEN_FDS");
	if (value == NULL || value[0] == '\0')
		return (0);
	copy = strdup(value);
	if (copy == NULL)
		return (-1);
	cursor = copy;
	nfds = 0;
	while ((field = strsep(&cursor, ",")) != NULL) {
		if (field[0] == '\0' || nfds == nitems(fds) ||
		    nactivated_token_fds + nfds == SERVICE_TOKEN_MAX) {
			errno = EINVAL;
			goto fail;
		}
		fds[nfds] = (int)strtonum(field, 0, INT_MAX, &errstr);
		memset(&info, 0, sizeof(info));
		if (errstr != NULL || fcntl(fds[nfds], F_GETFD) == -1 ||
		    ioctl(fds[nfds], MAC_CAPABILITY_GETINFO, &info) == -1 ||
		    (strcmp(info.name, "isolation") != 0 &&
		    strcmp(info.name, "system") != 0)) {
			errno = EINVAL;
			goto fail;
		}
		for (j = 0; j < nfds; j++) {
			if (fds[j] == fds[nfds]) {
				errno = EINVAL;
				goto fail;
			}
		}
		for (j = 0; j < nactivated_token_fds; j++) {
			if (activated_token_fds[j] == fds[nfds]) {
				errno = EINVAL;
				goto fail;
			}
		}
		system_token[nfds] = strcmp(info.name, "system") == 0;
		nfds++;
	}
	free(copy);
	for (i = 0; i < nfds; i++) {
		owned_fds[i] = fcntl(fds[i], F_DUPFD_CLOEXEC, 0);
		if (owned_fds[i] == -1) {
			error = errno;
			while (i > 0)
				(void)close(owned_fds[--i]);
			errno = error;
			return (-1);
		}
	}

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_AUTHORIZE;
	memset(&sysreq, 0, sizeof(sysreq));
	sysreq.op = SYS_OP_AUTHORIZE;
	for (i = 0; i < nfds; i++) {
		memset(&reply, 0, sizeof(reply));
		memset(&call, 0, sizeof(call));
		call.req = system_token[i] ? (const void *)&sysreq : &req;
		call.req_len = system_token[i] ? sizeof(sysreq) : sizeof(req);
		if (!system_token[i]) {
			call.reply = &reply;
			call.reply_len = sizeof(reply);
		}
		if (ioctl(owned_fds[i], MAC_CAPABILITY_CALL, &call) == -1) {
			error = errno;
			goto consume;
		}
	}
	error = 0;

consume:
	/*
	 * Activation handles are bootstrap authority, not runtime service
	 * descriptors.  Consume the complete validated list.  Successful private
	 * references are close-on-exec, so a later program image cannot inherit
	 * them and reactivate under another program nonce.
	 */
	for (i = 0; i < nfds; i++) {
		(void)close(fds[i]);
		if (error == 0)
			activated_token_fds[nactivated_token_fds++] =
			    owned_fds[i];
		else
			(void)close(owned_fds[i]);
	}
	(void)unsetenv("ORACLED_TOKEN_FDS");
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
fail:
	free(copy);
	return (-1);
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

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
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

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
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

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
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

		if (ra.payload_len == sizeof(msg) && ra.nfds == 1 &&
		    msg.flags == 0 &&
		    strnlen(msg.client_label, sizeof(msg.client_label)) <
		    sizeof(msg.client_label)) {
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

	if (len > UINT32_MAX || (data == NULL && len != 0)) {
		errno = EINVAL;
		return (-1);
	}
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

	if (bufsz > UINT32_MAX || (buf == NULL && bufsz != 0)) {
		errno = EINVAL;
		return (-1);
	}
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
