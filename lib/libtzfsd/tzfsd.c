/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libtzfsd — client to the tzfsd(8) storage provider.  tzfsd is socket-free:
 * clients reach it over a held mac_capability channel obtained by name
 * (service_open(system.Storage)), and drive it with the request/reply structs
 * in tzfsd_proto.h carried as channel messages.  See tzfsd.h.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <trustedzfs.h>

#include "tzfsd.h"

struct tzfsd_client {
	struct service_session *session;
};

static struct tzfsd_client *
client_wrap(int fd)
{
	struct tzfsd_client *c;

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return (NULL);
	if (service_session_create(fd, &c->session) == -1) {
		int saved = errno;

		free(c);
		errno = saved;
		return (NULL);
	}
	return (c);
}

struct tzfsd_client *
tzfsd_connect(void)
{
	struct tzfsd_client *c;
	int fd;

	if (service_open(TZFSD_SERVICE_NAME, &fd) == -1)
		return (NULL);
	c = client_wrap(fd);
	if (c == NULL) {
		int saved = errno;

		(void)close(fd);
		errno = saved;
	}
	return (c);
}

struct tzfsd_client *
tzfsd_adopt(int channel_fd)
{

	return (client_wrap(channel_fd));
}

void
tzfsd_close(struct tzfsd_client *c)
{

	if (c == NULL)
		return;
	service_session_close(c->session);
	free(c);
}

/*
 * Send one request over the channel and receive the fixed tzfsd_reply.  If
 * fdp != NULL, a single granted fd may ride back in *fdp (else any fd is a
 * protocol violation).  Validates reply framing before returning.
 */
static int
tzfsd_call(struct tzfsd_client *c, const struct tzfsd_request *rq,
    struct tzfsd_reply *rp, int *fdp)
{
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int fd = -1;

	if (fdp != NULL)
		*fdp = -1;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = rq;
	outgoing.length = sizeof(*rq);
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = rp;
	incoming.capacity = sizeof(*rp);
	incoming.fds = &fd;
	incoming.fd_capacity = 1;
	if (service_session_call(c->session, &outgoing, &incoming, &options) ==
	    -1)
		return (-1);
	if (incoming.length != sizeof(*rp) || rp->_reserved != 0 ||
	    rp->status < 0 || rp->status > ELAST) {
		if (incoming.nfds != 0)
			(void)close(fd);
		errno = EPROTO;
		return (-1);
	}
	if (fdp == NULL) {
		if (incoming.nfds != 0) {
			(void)close(fd);
			errno = EPROTO;
			return (-1);
		}
		return (0);
	}
	/* A granted fd rides back only on success. */
	if ((rp->status == 0 && incoming.nfds != 1) ||
	    (rp->status != 0 && incoming.nfds != 0)) {
		if (incoming.nfds != 0)
			(void)close(fd);
		errno = EPROTO;
		return (-1);
	}
	*fdp = (incoming.nfds == 1) ? fd : -1;
	return (0);
}

int
tzfsd_request(struct tzfsd_client *c, const struct tzfsd_req *req,
    struct tzfsd_grant *out)
{
	struct tzfsd_request rq;
	struct tzfsd_reply rp;
	int handle = -1;

	if (c == NULL || req == NULL || out == NULL) {
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
	if (strlcpy(rq.dataset, req->dataset, sizeof(rq.dataset)) >=
	    sizeof(rq.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (tzfsd_call(c, &rq, &rp, &handle) == -1)
		return (-1);
	if (rp.status != 0) {
		if (handle != -1)
			(void)close(handle);
		errno = rp.status;
		return (-1);
	}
	if (handle == -1 ||
	    memchr(rp.dataset, '\0', sizeof(rp.dataset)) == NULL ||
	    rp.dataset[0] == '\0') {
		if (handle != -1)
			(void)close(handle);
		errno = EPROTO;
		return (-1);
	}
	out->handle_fd = handle;
	(void)strlcpy(out->dataset, rp.dataset, sizeof(out->dataset));
	return (0);
}

int
tzfsd_release(struct tzfsd_client *c, const char *dataset)
{
	struct tzfsd_request rq;
	struct tzfsd_reply rp;

	if (c == NULL || dataset == NULL || dataset[0] == '\0') {
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
	if (tzfsd_call(c, &rq, &rp, NULL) == -1)
		return (-1);
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
tzfsd_ping(struct tzfsd_client *c)
{
	struct tzfsd_request rq;
	struct tzfsd_reply rp;

	if (c == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = TZFSD_OP_PING;
	if (tzfsd_call(c, &rq, &rp, NULL) == -1)
		return (-1);
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
tzfsd_begin_session(struct tzfsd_client *c, const char *session)
{
	struct tzfsd_request rq;
	struct tzfsd_reply rp;

	if (c == NULL || session == NULL ||
	    strlen(session) != TZFSD_SESSION_MAX - 1) {
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
	if (tzfsd_call(c, &rq, &rp, NULL) == -1)
		return (-1);
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
