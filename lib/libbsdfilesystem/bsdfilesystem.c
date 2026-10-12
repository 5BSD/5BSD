/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libbsdfilesystem — client to the bsdfilesystem(8) storage provider.  bsdfilesystem is socket-free:
 * clients reach it over a held mac_capability channel obtained by name
 * (service_open(system.Filesystem)), and speak bsd.filesystem.v1
 * (lib/libfilesystemcmp/filesystemcmp.fidl); requests are still built and
 * replies validated in the bsdfilesystem_proto.h record shapes.  See
 * bsdfilesystem.h.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <trustedzfs.h>

#include "bsdfilesystem.h"
#include "filesystem_transact.h"

/*
 * One bsd.filesystem.v1 session.  Requests are built and replies validated in
 * the legacy record shapes; filesystem_transact.h carries them as methods.  A
 * transport failure, timeout or malformed reply poisons the session: every
 * later call fails with that error.
 */
struct bsdfilesystem_client {
	struct fs_transport	 transport;
	pid_t			 owner;	/* getpid() at open; fail-closed guard */
	int			 failed;
};

static struct bsdfilesystem_client *
client_wrap(int fd)
{
	struct bsdfilesystem_client *c;

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return (NULL);
	c->owner = getpid();
	if (fs_transport_adopt(&c->transport, fd) == -1) {
		int saved = errno;

		free(c);
		errno = saved;
		return (NULL);
	}
	return (c);
}

struct bsdfilesystem_client *
bsdfilesystem_connect(void)
{
	struct bsdfilesystem_client *c;
	int fd;

	if (service_open(BSDFILESYSTEM_SERVICE_NAME, &fd) == -1)
		return (NULL);
	c = client_wrap(fd);
	if (c == NULL) {
		int saved = errno;

		(void)close(fd);
		errno = saved;
	}
	return (c);
}

struct bsdfilesystem_client *
bsdfilesystem_adopt(int channel_fd)
{

	return (client_wrap(channel_fd));
}

void
bsdfilesystem_close(struct bsdfilesystem_client *c)
{

	if (c == NULL)
		return;
	fs_transport_drop(&c->transport);
	free(c);
}

/* Return EPROTO after closing delivered authority and poisoning the session. */
static int
protocol_error(struct bsdfilesystem_client *c, int fd)
{

	if (fd >= 0)
		(void)close(fd);
	fs_transport_drop(&c->transport);
	if (c->failed == 0)
		c->failed = EPROTO;
	return (errno = EPROTO, -1);
}

static bool
all_zero(const void *data, size_t length)
{
	const unsigned char *bytes;
	size_t i;

	bytes = data;
	for (i = 0; i < length; i++)
		if (bytes[i] != 0)
			return (false);
	return (true);
}

/*
 * Send one request over the channel and receive the fixed bsdfilesystem_reply.  If
 * fdp != NULL, a single granted fd may ride back in *fdp (else any fd is a
 * protocol violation).  Validates reply framing before returning.
 */
static int
bsdfilesystem_call(struct bsdfilesystem_client *c, const struct bsdfilesystem_request *rq,
    struct bsdfilesystem_reply *rp, int *fdp)
{
	struct {
		size_t length, nfds;
	} incoming;
	int error, fd = -1;

	if (fdp != NULL)
		*fdp = -1;
	if (c->failed != 0)
		return (errno = c->failed, -1);
	memset(rp, 0, sizeof(*rp));
	/* No bound beyond a caller's service_budget_begin(3), as before. */
	error = fs_transact(&c->transport, rq, sizeof(*rq), rp, sizeof(*rp),
	    &incoming.length, &fd, UINT32_MAX);
	if (error != 0) {
		fs_transport_drop(&c->transport);
		c->failed = error;
		return (errno = error, -1);
	}
	incoming.nfds = fd >= 0 ? 1 : 0;
	if (incoming.length != sizeof(*rp) || rp->_reserved != 0 ||
	    rp->status < 0 || rp->status > ELAST ||
	    ((rp->status != 0 || rq->op != BSDFILESYSTEM_OP_REQUEST) &&
	    !all_zero(rp->dataset, sizeof(rp->dataset))))
		return (protocol_error(c, incoming.nfds != 0 ? fd : -1));
	if (fdp == NULL) {
		if (incoming.nfds != 0)
			return (protocol_error(c, fd));
		return (0);
	}
	/* A granted fd rides back only on success. */
	if ((rp->status == 0 && incoming.nfds != 1) ||
	    (rp->status != 0 && incoming.nfds != 0))
		return (protocol_error(c, incoming.nfds != 0 ? fd : -1));
	*fdp = (incoming.nfds == 1) ? fd : -1;
	return (0);
}

int
bsdfilesystem_request_quota(struct bsdfilesystem_client *c, const struct bsdfilesystem_req *req,
    uint64_t quota, struct bsdfilesystem_grant *out)
{
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_reply rp;
	int handle = -1;

	if (c == NULL || c->owner != getpid() || req == NULL || out == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (req->dataset[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	if (memchr(req->dataset, '\0', sizeof(req->dataset)) == NULL) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	out->handle_fd = -1;
	out->dataset[0] = '\0';
	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_REQUEST;
	rq.flags = req->flags;
	rq.rights = req->rights;
	rq.quota = quota;
	rq.lifetime = req->lifetime;
	rq.owner_uid = req->owner_uid;
	rq.owner_gid = req->owner_gid;
	if (strlcpy(rq.dataset, req->dataset, sizeof(rq.dataset)) >=
	    sizeof(rq.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (bsdfilesystem_call(c, &rq, &rp, &handle) == -1)
		return (-1);
	if (rp.status != 0) {
		if (handle != -1)
			(void)close(handle);
		errno = rp.status;
		return (-1);
	}
	if (handle == -1 ||
	    memchr(rp.dataset, '\0', sizeof(rp.dataset)) == NULL ||
	    rp.dataset[0] == '\0')
		return (protocol_error(c, handle));
	out->handle_fd = handle;
	(void)strlcpy(out->dataset, rp.dataset, sizeof(out->dataset));
	return (0);
}

int
bsdfilesystem_request(struct bsdfilesystem_client *c, const struct bsdfilesystem_req *req,
    struct bsdfilesystem_grant *out)
{

	return (bsdfilesystem_request_quota(c, req, 0, out));
}

int
bsdfilesystem_release(struct bsdfilesystem_client *c, const char *dataset)
{
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_reply rp;

	if (c == NULL || c->owner != getpid() || dataset == NULL ||
	    dataset[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_RELEASE;
	if (strlcpy(rq.dataset, dataset, sizeof(rq.dataset)) >=
	    sizeof(rq.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (bsdfilesystem_call(c, &rq, &rp, NULL) == -1)
		return (-1);
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
bsdfilesystem_ping(struct bsdfilesystem_client *c)
{
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_reply rp;

	if (c == NULL || c->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_PING;
	if (bsdfilesystem_call(c, &rq, &rp, NULL) == -1)
		return (-1);
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
bsdfilesystem_begin_session(struct bsdfilesystem_client *c, const char *session)
{
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_reply rp;

	if (c == NULL || c->owner != getpid() || session == NULL ||
	    strlen(session) != BSDFILESYSTEM_SESSION_MAX - 1) {
		errno = EINVAL;
		return (-1);
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_BEGIN_SESSION;
	if (strlcpy(rq.session, session, sizeof(rq.session)) >=
	    sizeof(rq.session)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (bsdfilesystem_call(c, &rq, &rp, NULL) == -1)
		return (-1);
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
bsdfilesystem_destroy(struct bsdfilesystem_client *c, const char *dataset, uint32_t lifetime)
{
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_reply rp;

	if (c == NULL || c->owner != getpid() || dataset == NULL ||
	    dataset[0] == '\0' ||
	    (lifetime != BSDFILESYSTEM_PERSISTENT && lifetime != BSDFILESYSTEM_CACHE)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_DESTROY;
	rq.lifetime = (uint8_t)lifetime;
	if (strlcpy(rq.dataset, dataset, sizeof(rq.dataset)) >=
	    sizeof(rq.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (bsdfilesystem_call(c, &rq, &rp, NULL) == -1)
		return (-1);
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
bsdfilesystem_mount_dir(int handle_fd, int rdonly)
{

	return (tzfs_mount(handle_fd, rdonly != 0));
}
