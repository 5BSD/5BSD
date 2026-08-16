/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) request loop.  Runs entirely in capability mode: every handle is
 * derived/created/cloned/destroyed from the retained parent handles, and the
 * granted handle rides SCM_RIGHTS back to the client.
 *
 * Phase 2 uses single-level claim names (no '/').  Per-bundle namespacing
 * (bundle-id/claim, authenticated from the peer rather than claimed) lands
 * with the serviced integration in Phase 3.
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
valid_name(const char *name)
{

	if (name[0] == '\0' || strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0)
		return (false);
	if (strchr(name, '/') != NULL)
		return (false);
	if (memchr(name, '\0', TZFSD_NAME_MAX) == NULL)
		return (false);
	return (true);
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

	if (rq->lifetime != TZFSD_PERSISTENT &&
	    rq->lifetime != TZFSD_EPHEMERAL) {
		errno = EINVAL;
		return (-1);
	}
	if ((rq->rights & ~ZH_ALL_RIGHTS) != 0 || rq->rights == 0 ||
	    (rq->flags & ~ZHF_SUBTREE) != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (!valid_name(rq->name)) {
		errno = EINVAL;
		return (-1);
	}
	if (memchr(rq->flavor, '\0', sizeof(rq->flavor)) == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (rq->lifetime == TZFSD_EPHEMERAL) {
		parent_fd = st->ephemeral_fd;
		parent_name = cfg->ephemeral;
	} else {
		parent_fd = st->persistent_fd;
		parent_name = cfg->persistent;
	}

	if (rq->flavor[0] == '\0') {
		/* Bare dataset claim: open-or-create the leaf. */
		leaf_fd = tzfsd_ensure_path(parent_fd, rq->name, ZH_ALL_RIGHTS);
		if (leaf_fd == -1)
			return (-1);
	} else {
		/* Flavor clone: templates/<flavor>@ready -> parent/<name>. */
		struct tzfsd_flavor_def *f = tzfsd_flavor_find(cfg, rq->flavor);
		int origin_fd;

		if (f == NULL || !f->available) {
			errno = ENOENT;
			return (-1);
		}
		origin_fd = tzfs_openat(st->templates_fd, rq->flavor,
		    ZH_CLONE_SRC, 0);
		if (origin_fd == -1)
			return (-1);
		leaf_fd = tzfs_clone(parent_fd, origin_fd,
		    TZFSD_TEMPLATE_SNAP, rq->name);
		(void)close(origin_fd);
		if (leaf_fd == -1)
			return (-1);
	}

	/*
	 * Re-open from the retained parent so both rights and subtree scope are
	 * exactly those requested.  The provisioning leaf is always subtree-
	 * capable and deriving it would accidentally preserve that authority.
	 */
	(void)close(leaf_fd);
	granted = tzfs_openat(parent_fd, rq->name, rq->rights, rq->flags);
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

	(void)snprintf(dataset, dsz, "%s/%s", parent_name, rq->name);
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
		syslog(LOG_INFO, "REQUEST name=%s flavor=%s life=%u -> %s",
		    rq->name, rq->flavor[0] ? rq->flavor : "-", rq->lifetime,
		    strerror(rp.status));
		return;
	}
	rp.status = 0;
	send_reply(c, &rp, sizeof(rp), handle);
	(void)close(handle);
	syslog(LOG_INFO, "REQUEST %s flavor=%s life=%u -> granted",
	    rp.dataset, rq->flavor[0] ? rq->flavor : "-", rq->lifetime);
}

static void
handle_release(struct tzfsd_state *st, int c, const struct tzfsd_request *rq)
{
	int rc;

	if (!valid_name(rq->name)) {
		reply_status(c, EINVAL);
		return;
	}
	rc = tzfs_destroy(st->ephemeral_fd, rq->name);
	if (rc == -1 && errno != ENOENT) {
		reply_status(c, errno);
		return;
	}
	reply_status(c, 0);
	syslog(LOG_INFO, "RELEASE %s -> ok", rq->name);
}

static void
handle_list(struct tzfsd_state *st, int c)
{
	struct tzfsd_flavor_list rl;
	unsigned i;

	memset(&rl, 0, sizeof(rl));
	rl.status = 0;
	for (i = 0; i < st->cfg.nflavors && rl.count < TZFSD_MAX_FLAVORS; i++) {
		struct tzfsd_flavor_def *f = &st->cfg.flavors[i];

		if (!f->available)
			continue;
		(void)strlcpy(rl.flavors[rl.count].name, f->name,
		    sizeof(rl.flavors[rl.count].name));
		rl.flavors[rl.count].is_default = f->is_default ? 1 : 0;
		rl.count++;
	}
	send_reply(c, &rl, sizeof(rl), -1);
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
		switch (rq.op) {
		case TZFSD_OP_REQUEST:
			handle_request(st, c, &rq);
			break;
		case TZFSD_OP_RELEASE:
			handle_release(st, c, &rq);
			break;
		case TZFSD_OP_LIST_FLAVORS:
			handle_list(st, c);
			break;
		case TZFSD_OP_PING:
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
		int c = accept(st->listen_fd, NULL, NULL);

		if (c == -1) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			syslog(LOG_ERR, "accept: %m");
			return;
		}
		handle_conn(st, c);
		(void)close(c);
	}
}
