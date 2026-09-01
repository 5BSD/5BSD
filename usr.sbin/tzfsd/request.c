/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) request loop.  tzfsd is a socket-free service_provider: it exposes
 * system.Filesystem and serves each client on its own mac_capability worker
 * channel.  Every handle is derived/created/cloned/destroyed from the retained
 * parent handles in capability mode, and the granted handle rides back to the
 * client as the reply's single SCM fd.
 *
 * Dataset keys are opaque, single-level names derived by the trusted bundle
 * parser.  tzfsd never accepts a user-facing role or path.
 */

#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sha256.h>

#include <channel.h>
#include <libservice.h>
#include <trustedzfs.h>

#include "tzfsd.h"

/*
 * Per-connection worker context: the retained-handle state (a private COW copy)
 * plus the connecting client's unforgeable label, which namespaces every leaf
 * this client can name.
 */
struct tzfs_conn {
	struct tzfsd_state	*st;
	char			client[64];	/* == service_identity.client_label */
};

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

/*
 * Derive a client's per-service namespace: a single dataset component named by
 * a hash of the connecting service's (unforgeable) label — set by serviced when
 * it brokered the channel, never by the client.  Every claim a client makes is
 * a child dataset under this namespace, so a client can only ever create or open
 * storage inside its own subtree.  It cannot name another service's storage:
 * authority is the held channel's identity, not a wire argument.
 */
static bool
derive_ns(const char *client, char *out, size_t outsz)
{
	SHA256_CTX ctx;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	char hex[25];
	unsigned i;

	if (client == NULL || client[0] == '\0')
		return (false);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, client, strlen(client));
	SHA256_Final(digest, &ctx);
	for (i = 0; i < 12; i++)
		(void)snprintf(hex + i * 2, 3, "%02x", digest[i]);
	hex[24] = '\0';
	if ((size_t)snprintf(out, outsz, "u%s", hex) >= outsz)
		return (false);
	return (true);
}

/*
 * Produce a rights-limited handle for a REQUEST from the client identified by
 * `client`.  Returns the granted fd (>=0) and fills dataset[]/dsz for audit, or
 * -1 with errno set.
 */
static int
grant(struct tzfsd_state *st, const char *client,
    const struct tzfsd_request *rq, char *dataset, size_t dsz)
{
	struct tzfsd_config *cfg = &st->cfg;
	int parent_fd, ns_fd, leaf_fd, granted;
	const char *parent_name, *claim;
	char parent_buf[TZFSD_MAXPATH];
	char ns[TZFSD_NAME_MAX];

	if (rq->lifetime > TZFSD_LEASE) {
		errno = EINVAL;
		return (-1);
	}
	if ((rq->rights & ~ZH_ALL_RIGHTS) != 0 || rq->rights == 0 ||
	    (rq->flags & ~ZHF_SUBTREE) != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (!valid_dataset(rq->dataset) ||
	    !derive_ns(client, ns, sizeof(ns))) {
		errno = EINVAL;
		return (-1);
	}
	claim = rq->dataset;

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

	/*
	 * Open-or-create the service's namespace subtree, then the claim child
	 * under it.  The client can only ever reach children of its own ns.
	 */
	ns_fd = tzfsd_ensure_path(parent_fd, ns, ZH_ALL_RIGHTS);
	if (ns_fd == -1)
		return (-1);
	leaf_fd = tzfsd_ensure_path(ns_fd, claim, ZH_ALL_RIGHTS);
	if (leaf_fd == -1) {
		int saved = errno;

		(void)close(ns_fd);
		errno = saved;
		return (-1);
	}

	/*
	 * Set the dataset root's owner to the requesting service so it can write
	 * its own storage once it mounts the handle lazily.  This runs on the
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
			(void)close(ns_fd);
			errno = saved;
			return (-1);
		}
		(void)close(dfd);
		(void)tzfs_unmount(leaf_fd);
	}

	/*
	 * Re-open the claim from its retained namespace parent so both rights and
	 * subtree scope are exactly those requested.  The provisioning leaf is
	 * always subtree-capable and deriving it would accidentally preserve that
	 * authority.
	 */
	(void)close(leaf_fd);
	granted = tzfs_openat(ns_fd, claim, rq->rights, rq->flags);
	(void)close(ns_fd);
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

	(void)snprintf(dataset, dsz, "%s/%s/%s", parent_name, ns, claim);
	return (granted);
}

/*
 * Open an isolated path descriptor for a TZFSD_OP_OPEN request from `client`.
 * Default-deny: the client's unforgeable label and the exact path must match a
 * configured policy entry that covers the requested rights.  The open is done
 * relative to the retained root fd (capsicum-legal in capability mode) and the
 * delivered fd is capped to exactly the requested rights.  Returns the fd, or
 * -1 with errno (EACCES when the policy does not grant it).
 */
static int
grant_open(struct tzfsd_state *st, const char *client,
    const struct tzfsd_open_request *rq)
{
	const struct tzfsd_config *cfg = &st->cfg;
	cap_rights_t rights;
	unsigned i;
	int flags, fd, saved;

	if (rq->rights == 0 || (rq->rights & ~TZFSD_OPEN_RIGHTS_ALL) != 0) {
		errno = EINVAL;
		return (-1);
	}
	/* Absolute, NUL-terminated, no traversal component. */
	if (rq->path[0] != '/' ||
	    memchr(rq->path, '\0', sizeof(rq->path)) == NULL ||
	    strstr(rq->path, "..") != NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (st->root_fd == -1) {
		errno = ENXIO;
		return (-1);
	}

	/* Default-deny: exact (label, path) match covering the requested rights. */
	for (i = 0; i < cfg->nopen_policy; i++) {
		const struct tzfsd_open_policy *pol = &cfg->open_policy[i];

		if (strcmp(pol->label, client) == 0 &&
		    strcmp(pol->path, rq->path) == 0 &&
		    (rq->rights & ~pol->rights) == 0)
			break;
	}
	if (i == cfg->nopen_policy) {
		errno = EACCES;
		return (-1);
	}

	if ((rq->rights & (TZFSD_OPEN_READ | TZFSD_OPEN_WRITE)) ==
	    (TZFSD_OPEN_READ | TZFSD_OPEN_WRITE))
		flags = O_RDWR;
	else if (rq->rights & TZFSD_OPEN_WRITE)
		flags = O_WRONLY;
	else
		flags = O_RDONLY;	/* read/exec/lookup all open read-only */
	flags |= O_CLOEXEC | O_NOCTTY;
	if (rq->is_dir)
		flags |= O_DIRECTORY;

	/* Relative to the retained root fd: legal in capability mode. */
	fd = openat(st->root_fd, rq->path + 1, flags);
	if (fd == -1)
		return (-1);

	cap_rights_init(&rights, 0);
	if (rq->rights & TZFSD_OPEN_READ)
		cap_rights_set(&rights, CAP_READ, CAP_SEEK, CAP_FSTAT);
	if (rq->rights & TZFSD_OPEN_WRITE)
		cap_rights_set(&rights, CAP_WRITE, CAP_SEEK, CAP_FSYNC);
	if (rq->rights & TZFSD_OPEN_EXEC)
		cap_rights_set(&rights, CAP_FEXECVE);
	if (rq->rights & TZFSD_OPEN_LOOKUP)
		cap_rights_set(&rights, CAP_LOOKUP, CAP_FSTATAT);
	if (cap_rights_limit(fd, &rights) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	return (fd);
}

/*
 * Per-client channel request handler.  arg is this worker's tzfsd_state (its
 * own copy of the retained handles, plus per-connection lease state).  The
 * reply is a fixed tzfsd_reply; a granted handle rides back as its single fd.
 */
static void
tzfs_request(struct channel *ch __unused, struct channel_message *m, void *arg)
{
	struct tzfs_conn *conn = arg;
	struct tzfsd_state *st = conn->st;
	const struct tzfsd_request *rq;
	struct tzfsd_reply rp;
	struct channel_outgoing out;
	int handle = -1;

	memset(&rp, 0, sizeof(rp));

	if (channel_message_fd_count(m) != 0) {
		rp.status = EPROTO;
		goto reply;
	}

	/*
	 * TZFSD_OP_OPEN carries its own, larger request struct; dispatch it by
	 * its distinct length before the storage-shaped requests.
	 */
	if (channel_message_length(m) == sizeof(struct tzfsd_open_request)) {
		const struct tzfsd_open_request *orq = channel_message_data(m);

		if (orq->op == TZFSD_OP_OPEN) {
			handle = grant_open(st, conn->client, orq);
			if (handle == -1) {
				rp.status = errno;
				syslog(LOG_INFO, "OPEN rights=%#x -> %s",
				    orq->rights, strerror(rp.status));
			} else {
				syslog(LOG_INFO, "OPEN %s rights=%#x -> granted",
				    orq->path, orq->rights);
			}
			goto reply;
		}
	}

	if (channel_message_length(m) != sizeof(*rq)) {
		rp.status = EPROTO;
		goto reply;
	}
	rq = channel_message_data(m);
	if (!valid_request(rq)) {
		rp.status = EINVAL;
		goto reply;
	}

	switch (rq->op) {
	case TZFSD_OP_REQUEST:
		handle = grant(st, conn->client, rq, rp.dataset,
		    sizeof(rp.dataset));
		if (handle == -1) {
			rp.status = errno;
			rp.dataset[0] = '\0';
			syslog(LOG_INFO, "REQUEST claim=%s life=%u -> %s",
			    rq->dataset, rq->lifetime, strerror(rp.status));
		} else {
			syslog(LOG_INFO, "REQUEST %s life=%u -> granted",
			    rp.dataset, rq->lifetime);
		}
		break;
	case TZFSD_OP_RELEASE: {
		/* Destroy the caller's own claim under its lease namespace. */
		char ns[TZFSD_NAME_MAX];
		int ns_fd;

		if (!valid_dataset(rq->dataset) ||
		    !derive_ns(conn->client, ns, sizeof(ns))) {
			rp.status = EINVAL;
			break;
		}
		if (st->lease_fd == -1) {
			rp.status = ENXIO;
			break;
		}
		ns_fd = tzfs_openat(st->lease_fd, ns, ZH_ALL_RIGHTS, ZHF_SUBTREE);
		if (ns_fd == -1) {
			/* No namespace => nothing to release (idempotent). */
			if (errno != ENOENT)
				rp.status = errno;
			break;
		}
		if (tzfsd_destroy_tree(ns_fd, rq->dataset) == -1 &&
		    errno != ENOENT)
			rp.status = errno;
		else
			syslog(LOG_INFO, "RELEASE %s/%s -> ok", ns, rq->dataset);
		(void)close(ns_fd);
		break;
	}
	case TZFSD_OP_PING:
		rp.status = 0;
		break;
	case TZFSD_OP_BEGIN_SESSION:
		if (tzfsd_session_begin(st, rq->session) == -1)
			rp.status = errno;
		break;
	default:
		rp.status = EOPNOTSUPP;
		break;
	}

reply:
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &rp;
	out.length = sizeof(rp);
	if (handle != -1 && rp.status == 0) {
		out.fds = &handle;
		out.nfds = 1;
	}
	(void)channel_send_reply(m, &out);
	if (handle != -1)
		(void)close(handle);
	channel_message_free(m);
}

/*
 * Serve one client on its own worker channel until the channel closes.  Runs in
 * a pdfork'd worker with its own copy of st (so its lease state is private).
 */
static int
tzfs_worker(struct tzfsd_state *st, int fd, const char *client)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel = NULL;
	struct tzfs_conn conn;
	int ready, wants_write;

	conn.st = st;
	(void)strlcpy(conn.client, client, sizeof(conn.client));

	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, tzfs_request, &conn) == -1) {
		channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1 ||
		    (ready = channel_wait(channel, wants_write, -1)) == -1 ||
		    ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1) ||
		    ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1))
			break;
	}
	channel_destroy(channel);
	return (0);
}

/*
 * Expose system.Filesystem and dispatch each accepted client on its own pdfork'd
 * worker.  Enters capability mode before serving; returns -1 only on setup
 * failure (never on success).
 */
int
tzfsd_serve(struct tzfsd_state *st)
{
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, TZFSD_SERVICE_NAME, &listener) ==
	    -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (-1);

	for (;;) {
		pid_t pid;
		int pd;

		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1)
			return (-1);
		pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
		if (pid == -1) {
			syslog(LOG_ERR, "pdfork: %m");
			(void)close(fd);
			continue;
		}
		if (pid == 0)
			_exit(tzfs_worker(st, fd, id.client_label));
		(void)close(fd);
		(void)close(pd);
	}
}
