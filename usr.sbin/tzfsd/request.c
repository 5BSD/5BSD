/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) request loop.  Runs entirely in capability mode: every handle is
 * derived/created/cloned/destroyed from the retained parent handles, and the
 * granted handle rides SCM_RIGHTS back to the client.
 *
 * Dataset keys are opaque, single-level names derived by the trusted bundle
 * parser.  tzfsd never accepts a user-facing role or path.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <trustedzfs.h>

#include "tzfsd.h"

/* A claim name must be a single, safe path component. */
static bool
valid_dataset(const char *name)
{

	if (memchr(name, '\0', TZFSD_NAME_MAX) == NULL)
		return (false);
	if (name[0] == '\0' || strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0)
		return (false);
	if (strchr(name, '/') != NULL)
		return (false);
	return (true);
}

static bool
all_zero(const void *buf, size_t len)
{
	const unsigned char *p = buf;
	size_t i;

	for (i = 0; i < len; i++)
		if (p[i] != 0)
			return (false);
	return (true);
}

/* Reject malformed and ambiguous protocol messages before dispatch. */
static bool
valid_request(const struct tzfsd_request *rq)
{

	if (!all_zero(rq->_reserved, sizeof(rq->_reserved)) ||
	    memchr(rq->dataset, '\0', sizeof(rq->dataset)) == NULL ||
	    memchr(rq->session, '\0', sizeof(rq->session)) == NULL)
		return (false);
	switch (rq->op) {
	case TZFSD_OP_REQUEST:
		return (rq->session[0] == '\0');
	case TZFSD_OP_RELEASE:
		return (rq->flags == 0 && rq->rights == 0 && rq->lifetime == 0 &&
		    rq->session[0] == '\0');
	case TZFSD_OP_PING:
		return (rq->flags == 0 && rq->rights == 0 && rq->lifetime == 0 &&
		    rq->dataset[0] == '\0' && rq->session[0] == '\0');
	case TZFSD_OP_BEGIN_SESSION:
		return (rq->flags == 0 && rq->rights == 0 && rq->lifetime == 0 &&
		    rq->dataset[0] == '\0' && rq->session[0] != '\0');
	default:
		return (rq->flags == 0 && rq->rights == 0 && rq->lifetime == 0 &&
		    rq->dataset[0] == '\0' && rq->session[0] == '\0');
	}
}

/* Send a fixed reply, optionally with one SCM_RIGHTS fd. */
static void
send_reply(int c, const void *reply, size_t rlen, int passfd)
{
	struct msghdr msg;
	struct iovec iov;
	union {
		struct cmsghdr align;
		char buf[CMSG_SPACE(sizeof(int))];
	} cbuf;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = __DECONST(void *, reply);
	iov.iov_len = rlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (passfd != -1) {
		struct cmsghdr *cmsg;

		memset(&cbuf, 0, sizeof(cbuf));
		msg.msg_control = cbuf.buf;
		msg.msg_controllen = sizeof(cbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &passfd, sizeof(int));
	}
	(void)sendmsg(c, &msg, MSG_NOSIGNAL);
}

static void
reply_status(int c, int status)
{
	struct tzfsd_reply rp;

	memset(&rp, 0, sizeof(rp));
	rp.status = status;
	send_reply(c, &rp, sizeof(rp), -1);
}

/*
 * Produce a rights-limited handle for a REQUEST.  Returns the granted fd (>=0)
 * and fills dataset[]/dsz for audit, or -1 with errno set.
 */
static int
grant(struct tzfsd_state *st, const struct tzfsd_request *rq, char *dataset,
    size_t dsz)
{
	struct tzfsd_config *cfg = &st->cfg;
	int parent_fd, leaf_fd, granted;
	const char *parent_name;
	char parent_buf[TZFSD_MAXPATH];

	if (rq->lifetime > TZFSD_LEASE) {
		errno = EINVAL;
		return (-1);
	}
	if ((rq->rights & ~ZH_ALL_RIGHTS) != 0 || rq->rights == 0 ||
	    (rq->flags & ~ZHF_SUBTREE) != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (!valid_dataset(rq->dataset)) {
		errno = EINVAL;
		return (-1);
	}

	if (rq->lifetime == TZFSD_BOOT) {
		parent_fd = st->boot_fd;
		(void)snprintf(parent_buf, sizeof(parent_buf), "%s/%s",
		    cfg->ephemeral, st->boot_name);
		parent_name = parent_buf;
	} else if (rq->lifetime == TZFSD_LEASE) {
		if (st->lease_fd == -1) {
			errno = ENXIO;
			return (-1);
		}
		parent_fd = st->lease_fd;
		(void)snprintf(parent_buf, sizeof(parent_buf), "%s/%s",
		    cfg->ephemeral, st->lease_name);
		parent_name = parent_buf;
	} else {
		parent_fd = st->persistent_fd;
		parent_name = cfg->persistent;
	}

	/* Bare dataset claim: open-or-create the leaf. */
	leaf_fd = tzfsd_ensure_path(parent_fd, rq->dataset, ZH_ALL_RIGHTS);
	if (leaf_fd == -1)
		return (-1);

	/*
	 * Set the dataset root's owner to the requesting service so it can write
	 * its own storage once it mounts the handle lazily — serviced no longer
	 * mounts (and chowns) on the service's behalf.  This runs on the
	 * full-rights leaf (before the ioctl ceiling is applied to the delivered
	 * handle): a rights-limited handle would be denied ZFD_UNMOUNT, stranding
	 * the transient mount and making the consumer's later mount fail EINVAL.
	 * The ownership persists in the dataset.  Failure is fatal to the mint —
	 * unwritable storage must not be delivered as if it were usable.
	 */
	if (rq->owner_uid != 0 && (rq->rights & ZH_MOUNT) != 0) {
		int dfd = tzfs_mount(leaf_fd, false);

		if (dfd == -1 ||
		    fchown(dfd, rq->owner_uid, rq->owner_gid) == -1) {
			int saved = errno;

			if (dfd != -1)
				(void)close(dfd);
			(void)tzfs_unmount(leaf_fd);
			(void)close(leaf_fd);
			errno = saved;
			return (-1);
		}
		(void)close(dfd);
		(void)tzfs_unmount(leaf_fd);
	}

	/*
	 * Re-open from the retained parent so both rights and subtree scope are
	 * exactly those requested.  The provisioning leaf is always subtree-
	 * capable and deriving it would accidentally preserve that authority.
	 */
	(void)close(leaf_fd);
	granted = tzfs_openat(parent_fd, rq->dataset, rq->rights, rq->flags);
	if (granted == -1)
		return (-1);
	/* Add a monotonic Capsicum ioctl ceiling before SCM_RIGHTS transfer. */
	if (tzfs_limit_dataset_ioctls_by_rights(granted, rq->rights,
	    rq->flags) == -1) {
		int saved = errno;

		(void)close(granted);
		errno = saved;
		return (-1);
	}

	(void)snprintf(dataset, dsz, "%s/%s", parent_name, rq->dataset);
	return (granted);
}

static void
handle_request(struct tzfsd_state *st, int c, const struct tzfsd_request *rq)
{
	struct tzfsd_reply rp;
	int handle;

	memset(&rp, 0, sizeof(rp));
	handle = grant(st, rq, rp.dataset, sizeof(rp.dataset));
	if (handle == -1) {
		rp.status = errno;
		rp.dataset[0] = '\0';
		send_reply(c, &rp, sizeof(rp), -1);
		syslog(LOG_INFO, "REQUEST dataset=%s life=%u -> %s",
		    rq->dataset, rq->lifetime, strerror(rp.status));
		return;
	}
	rp.status = 0;
	send_reply(c, &rp, sizeof(rp), handle);
	(void)close(handle);
	syslog(LOG_INFO, "REQUEST %s life=%u -> granted",
	    rp.dataset, rq->lifetime);
}

static void
handle_release(struct tzfsd_state *st, int c, const struct tzfsd_request *rq)
{
	int rc;

	if (!valid_dataset(rq->dataset)) {
		reply_status(c, EINVAL);
		return;
	}
	if (st->lease_fd == -1) {
		reply_status(c, ENXIO);
		return;
	}
	rc = tzfsd_destroy_tree(st->lease_fd, rq->dataset);
	if (rc == -1 && errno != ENOENT) {
		reply_status(c, errno);
		return;
	}
	reply_status(c, 0);
	syslog(LOG_INFO, "RELEASE %s -> ok", rq->dataset);
}

static void
handle_conn(struct tzfsd_state *st, int c)
{
	struct tzfsd_request rq;
	ssize_t n;

	for (;;) {
		n = recv(c, &rq, sizeof(rq), 0);
		if (n <= 0)
			return;
		if ((size_t)n != sizeof(rq)) {
			reply_status(c, EPROTO);
			continue;
		}
		if (!valid_request(&rq)) {
			reply_status(c, EINVAL);
			continue;
		}
		switch (rq.op) {
		case TZFSD_OP_REQUEST:
			handle_request(st, c, &rq);
			break;
		case TZFSD_OP_RELEASE:
			handle_release(st, c, &rq);
			break;
		case TZFSD_OP_PING:
			reply_status(c, 0);
			break;
		case TZFSD_OP_BEGIN_SESSION:
			if (tzfsd_session_begin(st, rq.session) == -1)
				reply_status(c, errno);
			else
				reply_status(c, 0);
			break;
		default:
			reply_status(c, EOPNOTSUPP);
			break;
		}
	}
}

void
tzfsd_serve(struct tzfsd_state *st)
{

	for (;;) {
		pid_t pid;
		int c = accept4(st->listen_fd, NULL, NULL, SOCK_CLOEXEC);

		if (c == -1) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			syslog(LOG_ERR, "accept: %m");
			return;
		}
		pid = fork();
		if (pid == -1) {
			syslog(LOG_ERR, "fork: %m");
			(void)close(c);
			continue;
		}
		if (pid == 0) {
			(void)close(st->listen_fd);
			handle_conn(st, c);
			(void)close(c);
			_exit(0);
		}
		(void)close(c);
	}
}
