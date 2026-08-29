/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libtzfsd — client to the tzfsd(8) storage daemon.  See tzfsd.h.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <trustedzfs.h>

#include "tzfsd.h"

#define	TZFSD_MAX_REPLY_FDS	16

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

int
tzfsd_connect(void)
{
	struct sockaddr_un sun;
	int fd;

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd == -1)
		return (-1);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, TZFSD_SOCK_PATH, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		(void)close(fd);
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		int serrno = errno;
		(void)close(fd);
		errno = serrno;
		return (-1);
	}
	return (fd);
}

/* Send exactly one request datagram. */
static int
send_request(int chan, const struct tzfsd_request *rq)
{
	ssize_t n;

	n = send(chan, rq, sizeof(*rq), MSG_NOSIGNAL);
	if (n == -1)
		return (-1);
	if (n != (ssize_t)sizeof(*rq)) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * Receive exactly one reply datagram of rlen bytes.  If fdp != NULL, extract a
 * single SCM_RIGHTS fd into *fdp (or leave it -1 if none arrived).  Any fd on a
 * short/malformed reply is closed rather than leaked.
 */
static int
recv_reply(int chan, void *reply, size_t rlen, int *fdp)
{
	struct msghdr msg;
	struct iovec iov;
	union {
		struct cmsghdr align;
		char buf[CMSG_SPACE(sizeof(int) * TZFSD_MAX_REPLY_FDS)];
	} cbuf;
	struct cmsghdr *cmsg;
	ssize_t n;
	int got[TZFSD_MAX_REPLY_FDS];
	size_t i, nfds = 0;
	bool malformed = false;

	if (fdp != NULL)
		*fdp = -1;
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = reply;
	iov.iov_len = rlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(&cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf.buf;
	msg.msg_controllen = sizeof(cbuf.buf);
	n = recvmsg(chan, &msg, MSG_CMSG_CLOEXEC);
	if (n == -1)
		return (-1);
	if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
		malformed = true;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		size_t bytes, count;

		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len < CMSG_LEN(0)) {
			malformed = true;
			continue;
		}
		bytes = cmsg->cmsg_len - CMSG_LEN(0);
		if (bytes == 0 || bytes % sizeof(int) != 0) {
			malformed = true;
			continue;
		}
		count = bytes / sizeof(int);
		if (count > TZFSD_MAX_REPLY_FDS - nfds) {
			malformed = true;
			count = TZFSD_MAX_REPLY_FDS - nfds;
		}
		memcpy(&got[nfds], CMSG_DATA(cmsg), count * sizeof(int));
		nfds += count;
	}
	if (n != (ssize_t)rlen || malformed ||
	    (fdp == NULL && nfds != 0) || (fdp != NULL && nfds > 1)) {
		for (i = 0; i < nfds; i++)
			(void)close(got[i]);
		errno = EPROTO;
		return (-1);
	}
	if (fdp != NULL && nfds == 1)
		*fdp = got[0];
	return (0);
}

int
tzfsd_request(int chan, const struct tzfsd_req *req, struct tzfsd_grant *out)
{
	struct tzfsd_request rq;
	struct tzfsd_reply rp;
	int handle = -1;

	if (req == NULL || out == NULL) {
		errno = EINVAL;
		return (-1);
	}
	out->handle_fd = -1;
	out->dataset[0] = '\0';
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_REQUEST;
	rq.flags = req->flags;
	rq.rights = req->rights;
	rq.lifetime = req->lifetime;
	rq.owner_uid = req->owner_uid;
	rq.owner_gid = req->owner_gid;
	if (strlcpy(rq.flavor, req->flavor, sizeof(rq.flavor)) >=
	    sizeof(rq.flavor) ||
	    strlcpy(rq.dataset, req->dataset, sizeof(rq.dataset)) >=
	    sizeof(rq.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (send_request(chan, &rq) == -1)
		return (-1);
	if (recv_reply(chan, &rp, sizeof(rp), &handle) == -1)
		return (-1);
	if (rp._reserved != 0 ||
	    memchr(rp.dataset, '\0', sizeof(rp.dataset)) == NULL ||
	    rp.status < 0 || rp.status > ELAST ||
	    (rp.status == 0 && rp.dataset[0] == '\0') ||
	    (rp.status != 0 && (rp.dataset[0] != '\0' || handle != -1))) {
		if (handle != -1)
			(void)close(handle);
		errno = EPROTO;
		return (-1);
	}
	if (rp.status != 0) {
		if (handle != -1)
			(void)close(handle);
		errno = rp.status;
		return (-1);
	}
	if (handle == -1) {
		/* Success without a handle is a protocol violation. */
		errno = EPROTO;
		return (-1);
	}
	out->handle_fd = handle;
	(void)strlcpy(out->dataset, rp.dataset, sizeof(out->dataset));
	return (0);
}

int
tzfsd_release(int chan, const char *dataset)
{
	struct tzfsd_request rq;
	struct tzfsd_reply rp;

	if (dataset == NULL || dataset[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_RELEASE;
	if (strlcpy(rq.dataset, dataset, sizeof(rq.dataset)) >=
	    sizeof(rq.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (send_request(chan, &rq) == -1)
		return (-1);
	if (recv_reply(chan, &rp, sizeof(rp), NULL) == -1)
		return (-1);
	if (rp._reserved != 0 || rp.dataset[0] != '\0' || rp.status < 0 ||
	    rp.status > ELAST) {
		errno = EPROTO;
		return (-1);
	}
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
tzfsd_list_flavors(int chan, struct tzfsd_flavor_info *list, size_t max)
{
	struct tzfsd_request rq;
	struct tzfsd_flavor_list rl;
	uint32_t i, n;

	if (list == NULL && max != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_LIST_FLAVORS;
	if (send_request(chan, &rq) == -1)
		return (-1);
	if (recv_reply(chan, &rl, sizeof(rl), NULL) == -1)
		return (-1);
	if (rl.status < 0 || rl.status > ELAST ||
	    rl.count > TZFSD_MAX_FLAVORS ||
	    (rl.status != 0 && rl.count != 0)) {
		errno = EPROTO;
		return (-1);
	}
	if (rl.status != 0) {
		errno = rl.status;
		return (-1);
	}
	n = rl.count;
	for (i = 0; i < n; i++) {
		if (memchr(rl.flavors[i].name, '\0',
		    sizeof(rl.flavors[i].name)) == NULL ||
		    rl.flavors[i].is_default > 1 ||
		    !all_zero(rl.flavors[i]._reserved,
		    sizeof(rl.flavors[i]._reserved))) {
			errno = EPROTO;
			return (-1);
		}
	}
	if ((size_t)n > max)
		n = (uint32_t)max;
	for (i = 0; i < n; i++) {
		(void)strlcpy(list[i].name, rl.flavors[i].name,
		    sizeof(list[i].name));
		list[i].is_default = rl.flavors[i].is_default ? 1 : 0;
	}
	return ((int)n);
}

int
tzfsd_ping(int chan)
{
	struct tzfsd_request rq;
	struct tzfsd_reply rp;

	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_PING;
	if (send_request(chan, &rq) == -1)
		return (-1);
	if (recv_reply(chan, &rp, sizeof(rp), NULL) == -1)
		return (-1);
	if (rp._reserved != 0 || rp.dataset[0] != '\0' || rp.status < 0 ||
	    rp.status > ELAST) {
		errno = EPROTO;
		return (-1);
	}
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
tzfsd_begin_session(int chan, const char *session)
{
	struct tzfsd_request rq;
	struct tzfsd_reply rp;

	if (session == NULL || strlen(session) != TZFSD_SESSION_MAX - 1) {
		errno = EINVAL;
		return (-1);
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_BEGIN_SESSION;
	if (strlcpy(rq.session, session, sizeof(rq.session)) >=
	    sizeof(rq.session)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (send_request(chan, &rq) == -1 ||
	    recv_reply(chan, &rp, sizeof(rp), NULL) == -1)
		return (-1);
	if (rp._reserved != 0 || rp.dataset[0] != '\0' || rp.status < 0 ||
	    rp.status > ELAST) {
		errno = EPROTO;
		return (-1);
	}
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
tzfsd_mount_dir(int handle_fd, int rdonly)
{
	return (tzfs_mount(handle_fd, rdonly != 0));
}
