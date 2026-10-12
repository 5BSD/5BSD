/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The system.Filesystem client: service_storage_*(3), service_open_config(3)
 * and service_open_isolated(3) over bsd.filesystem.v1 (filesystemcmp.fidl).
 * Each call builds its request in the legacy record shape and validates the
 * legacy-shaped reply exactly as before; filesystem_transact.h carries them
 * as the schema's methods.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/zfshandle.h>
#include <trustedzfs.h>

#include <libservice.h>
#include <bsdfilesystem_proto.h>
#include "filesystem_transact.h"
#include "filesystemcmp.h"

static bool
service_provider_status_valid(int32_t status)
{

	return (status >= 0 && status <= ELAST);
}

static bool
service_provider_all_zero(const void *data, size_t length)
{
	const unsigned char *bytes = data;
	size_t i;

	for (i = 0; i < length; i++)
		if (bytes[i] != 0)
			return (false);
	return (true);
}

static bool
service_provider_component_valid(const char *name, size_t capacity)
{
	size_t length;

	length = strnlen(name, capacity);
	if (length == 0 || length == capacity ||
	    (length == 1 && name[0] == '.') ||
	    (length == 2 && name[0] == '.' && name[1] == '.') ||
	    memchr(name, '/', length) != NULL)
		return (false);
	return (true);
}

/*
 * One process-wide bsd.filesystem.v1 session, opened by name on first use and
 * shared by every call; calls are serialized on it.  A session that failed --
 * a transport error, a timeout or a malformed reply -- is dropped and the next
 * call opens a fresh one (which also replaces a session to a provider that
 * died or was relaunched; the provider's per-session mount anchors go with
 * it).  A session inherited across fork or pdfork belongs to the parent and is
 * abandoned without being closed.
 */
static pthread_mutex_t fs_lock = PTHREAD_MUTEX_INITIALIZER;
static struct fs_transport fs_session;

/* Open or reuse the session.  Caller holds fs_lock. */
static int
fs_session_locked(void)
{

	if (fs_session.connection != NULL && fs_session.owner != getpid()) {
		/* Never close an inherited session: it is the parent's. */
		fs_session.connection = NULL;
		fs_session.negotiated = false;
	}
	if (fs_session.connection != NULL)
		return (0);
	return (fs_transport_open(&fs_session));
}

/* Make sure a session can be opened before building a request. */
static int
fs_session_open(void)
{
	int rc;

	pthread_mutex_lock(&fs_lock);
	rc = fs_session_locked();
	pthread_mutex_unlock(&fs_lock);
	return (rc);
}

/* Drop the session after a failure; the next call opens a fresh one. */
static void
fs_session_fail(void)
{

	pthread_mutex_lock(&fs_lock);
	fs_transport_drop(&fs_session);
	pthread_mutex_unlock(&fs_lock);
}

/*
 * One request/reply in the legacy shapes, as service_session_call(3) did:
 * -1 with errno when no valid reply arrived (the session is then dropped).
 */
static int
fs_session_call(const struct service_message *outgoing,
    struct service_reply *incoming, const struct service_call_options *options)
{
	size_t length;
	int error, fd;

	pthread_mutex_lock(&fs_lock);
	if (fs_session_locked() == -1) {
		error = errno;
		pthread_mutex_unlock(&fs_lock);
		return (errno = error, -1);
	}
	error = fs_transact(&fs_session, outgoing->data, outgoing->length,
	    incoming->data, incoming->capacity, &length, &fd,
	    options->timeout_ms);
	if (error == 0 && fd >= 0 && incoming->fd_capacity < 1) {
		(void)close(fd);
		error = EPROTO;
	}
	if (error != 0)
		fs_transport_drop(&fs_session);
	pthread_mutex_unlock(&fs_lock);
	if (error != 0)
		return (errno = error, -1);
	incoming->length = length;
	incoming->nfds = fd >= 0 ? 1 : 0;
	if (fd >= 0)
		incoming->fds[0] = fd;
	return (0);
}

static int
service_provider_protocol_error(int fd)
{

	if (fd >= 0)
		(void)close(fd);
	fs_session_fail();
	errno = EPROTO;
	return (-1);
}


/*
 * Open this service's storage claim and return its mounted directory root.
 * bsdfilesystem is a socket-free provider: libservice opens a system.Filesystem channel by
 * name (service_open) and mints the claim itself — switchboard does no storage
 * work.  bsdfilesystem namespaces the dataset by this service's unforgeable channel
 * label, so `name` is only the claim key and a service can never reach another
 * service's storage.  The handle is RETAINED for the process lifetime because
 * the anonymous mount is anchored by it — dropping it would force-unmount and
 * every access on the returned directory would fail.  The caller hardens the
 * returned directory's rights itself (an openat(2)ed file cannot exceed the
 * directory).  The channel is cached; all of a service's claims share it.
 */

int
service_storage_open(struct service_context *context, const char *name,
    int *dirfdp)
{

	/* Default (0) refquota: bsdfilesystem applies its configured default_refquota. */
	return (service_storage_open_quota(context, name, 0, dirfdp));
}

/*
 * As service_storage_open(3), but bound the persistent claim's refquota to
 * `quota` bytes (0 selects bsdfilesystem's configured default).  A too-small quota
 * (below the daemon's floor) is rejected by bsdfilesystem with EINVAL.  The delivered
 * TrustedZFS handle fd is the client's own; the daemon set CAP_XFER_ONCE, which
 * the reply-send has already consumed to NONE at this client, so it is not re-
 * delegable and no extra client-side attenuation is applied.  Returns 0 with
 * *dirfdp set, or -1 with errno.
 */
static int
storage_open_scoped(struct service_context *context, uint8_t scope,
    const char *group, const char *name, uint64_t quota, uint8_t lifetime,
    uint8_t deliver, int *dirfdp)
{
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int handle = -1;

	if (dirfdp == NULL || name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*dirfdp = -1;
	if (strnlen(name, sizeof(rq.dataset)) >= sizeof(rq.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (!service_provider_component_valid(name, sizeof(rq.dataset))) {
		errno = EINVAL;
		return (-1);
	}
	if ((scope == BSDFILESYSTEM_SCOPE_GROUP) != (group != NULL && group[0] != '\0')) {
		errno = EINVAL;
		return (-1);
	}
	if (group != NULL && group[0] != '\0' &&
	    !service_provider_component_valid(group, sizeof(rq.group))) {
		errno = EINVAL;
		return (-1);
	}
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Open the system.Filesystem channel by name once; all claims share it. */
	if (fs_session_open() == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_REQUEST;
	rq.rights = ZH_MOUNT;			/* ZH_PROPS_READ is implicit */
	/*
	 * Ask bsdfilesystem to mount the dataset and deliver the store directory itself.
	 * bsdfilesystem is ambient (outside capability mode); the ZFS mount is
	 * forbidden in a born-in-capability-mode consumer, so the consumer must
	 * never tzfs_mount(3) — it receives a ready directory descriptor.
	 */
	rq.deliver = deliver;			/* MOUNTED or MOUNTED_RO */
	rq.quota = quota;			/* 0 = bsdfilesystem's default_refquota */
	rq.lifetime = lifetime;		/* BSDFILESYSTEM_PERSISTENT or BSDFILESYSTEM_CACHE */
	rq.owner_uid = getuid();
	rq.owner_gid = getgid();
	rq.scope = scope;
	if (group != NULL && strlcpy(rq.group, group, sizeof(rq.group)) >=
	    sizeof(rq.group)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (strlcpy(rq.dataset, name, sizeof(rq.dataset)) >=
	    sizeof(rq.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	incoming.fds = &handle;
	incoming.fd_capacity = 1;
	options.timeout_ms = SERVICE_STORAGE_CALL_TIMEOUT_MS;
	if (fs_session_call(&outgoing, &incoming, &options) == -1) {
		if (errno == EMSGSIZE)
			return (service_provider_protocol_error(-1));
		/*
		 * The call itself failed -- no reply within the bound, or the
		 * transport refused the send: the worker serving this
		 * connection is gone (a provider relaunch takes its workers
		 * with it).  A provider-reported status never lands here (it
		 * comes back in the reply), so any failure here means the
		 * session is dead: mark it so the next claim opens a fresh one
		 * instead of failing on a corpse forever.
		 */
		{
			int saved = errno;

			fs_session_fail();
			errno = saved;
		}
		return (-1);
	}
	if (incoming.length != sizeof(rp) || rp._reserved != 0 ||
	    !service_provider_status_valid(rp.status) ||
	    (rp.status == 0 && (incoming.nfds != 1 ||
	    rp.dataset[0] == '\0' || memchr(rp.dataset, '\0',
	    sizeof(rp.dataset)) == NULL)) ||
	    (rp.status != 0 && (incoming.nfds != 0 ||
	    !service_provider_all_zero(rp.dataset, sizeof(rp.dataset)))))
		return (service_provider_protocol_error(incoming.nfds != 0 ? handle : -1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}

	/*
	 * bsdfilesystem already performed the mount; the delivered descriptor IS the
	 * mounted store directory, and it is itself an anchor of that mount:
	 * the store stays mounted while the caller holds this descriptor (or
	 * the provider its claim), and is unmounted when the last such holder
	 * lets go.  Nothing is retained here on the caller's behalf -- a hidden
	 * duplicate would pin the mount and make the caller's own
	 * service_storage_destroy(3) fail EBUSY.
	 */
	*dirfdp = handle;
	return (0);
}

int
service_storage_open_quota(struct service_context *context, const char *name,
    uint64_t quota, int *dirfdp)
{
	return (storage_open_scoped(context, BSDFILESYSTEM_SCOPE_UNIT, NULL, name, quota,
	    BSDFILESYSTEM_PERSISTENT, BSDFILESYSTEM_DELIVER_MOUNTED, dirfdp));
}

int
service_storage_open_cache(struct service_context *context, const char *name,
    int *dirfdp)
{
	return (storage_open_scoped(context, BSDFILESYSTEM_SCOPE_UNIT, NULL, name, 0,
	    BSDFILESYSTEM_CACHE, BSDFILESYSTEM_DELIVER_MOUNTED, dirfdp));
}

int
service_storage_open_shared(struct service_context *context, const char *name,
    int *dirfdp)
{
	return (storage_open_scoped(context, BSDFILESYSTEM_SCOPE_SHARED, NULL, name, 0,
	    BSDFILESYSTEM_PERSISTENT, BSDFILESYSTEM_DELIVER_MOUNTED, dirfdp));
}

int
service_storage_open_shared_readonly(struct service_context *context,
    const char *name, int *dirfdp)
{
	return (storage_open_scoped(context, BSDFILESYSTEM_SCOPE_SHARED, NULL, name, 0,
	    BSDFILESYSTEM_PERSISTENT, BSDFILESYSTEM_DELIVER_MOUNTED_RO, dirfdp));
}

int
service_storage_open_env(struct service_context *context, int *dirfdp)
{
	return (service_storage_open_shared_readonly(context,
	    SERVICE_STORAGE_ENV, dirfdp));
}

int
service_storage_open_group(struct service_context *context, const char *group,
    const char *name, int *dirfdp)
{
	if (group == NULL || group[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	return (storage_open_scoped(context, BSDFILESYSTEM_SCOPE_GROUP, group, name, 0,
	    BSDFILESYSTEM_PERSISTENT, BSDFILESYSTEM_DELIVER_MOUNTED, dirfdp));
}

/*
 * Reclaim (destroy) a persistent storage claim previously granted under `name`
 * via service_storage_open(3), freeing its pool space.  Symmetric with
 * service_storage_open: persistent claims are never torn down implicitly, so
 * without this the per-service tree grows without bound.  bsdfilesystem resolves the
 * claim under the CALLER's own namespace (from the connecting channel's
 * unforgeable label, exactly as the open does), so a caller can never name — and
 * thus never destroy — another label's claim.  The op carries no fd in either
 * direction.  Returns 0 once the claim is gone, or -1 with errno (ENOENT if the
 * caller has no such claim).
 */
static int
storage_destroy_scoped(struct service_context *context, uint32_t op,
    uint8_t scope, const char *group, const char *name, uint8_t lifetime)
{
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (strnlen(name, sizeof(rq.dataset)) >= sizeof(rq.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (!service_provider_component_valid(name, sizeof(rq.dataset))) {
		errno = EINVAL;
		return (-1);
	}
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Shares the system.Filesystem channel with storage/config claims. */
	if (fs_session_open() == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = op;
	rq.scope = scope;
	if (group != NULL && group[0] != '\0') {
		if (!service_provider_component_valid(group, sizeof(rq.group)) ||
		    strlcpy(rq.group, group, sizeof(rq.group)) >= sizeof(rq.group)) {
			errno = EINVAL;
			return (-1);
		}
	}
	rq.lifetime = lifetime;		/* rights/flags/quota/session zero */
	if (strlcpy(rq.dataset, name, sizeof(rq.dataset)) >=
	    sizeof(rq.dataset)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	options.timeout_ms = SERVICE_STORAGE_CALL_TIMEOUT_MS;
	if (fs_session_call(&outgoing, &incoming, &options) == -1) {
		if (errno == EMSGSIZE)
			return (service_provider_protocol_error(-1));
		/*
		 * The call itself failed -- no reply within the bound, or the
		 * transport refused the send: the worker serving this
		 * connection is gone (a provider relaunch takes its workers
		 * with it).  A provider-reported status never lands here (it
		 * comes back in the reply), so any failure here means the
		 * session is dead: mark it so the next claim opens a fresh one
		 * instead of failing on a corpse forever.
		 */
		{
			int saved = errno;

			fs_session_fail();
			errno = saved;
		}
		return (-1);
	}
	if (incoming.length != sizeof(rp) || incoming.nfds != 0 ||
	    rp._reserved != 0 || !service_provider_status_valid(rp.status) ||
	    !service_provider_all_zero(rp.dataset, sizeof(rp.dataset)))
		return (service_provider_protocol_error(-1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
service_storage_destroy(struct service_context *context, const char *name)
{
	return (storage_destroy_scoped(context, BSDFILESYSTEM_OP_DESTROY,
	    BSDFILESYSTEM_SCOPE_UNIT, NULL, name, BSDFILESYSTEM_PERSISTENT));
}

int
service_storage_destroy_cache(struct service_context *context, const char *name)
{
	return (storage_destroy_scoped(context, BSDFILESYSTEM_OP_DESTROY,
	    BSDFILESYSTEM_SCOPE_UNIT, NULL, name, BSDFILESYSTEM_CACHE));
}

int
service_storage_destroy_shared(struct service_context *context,
    const char *name)
{
	return (storage_destroy_scoped(context, BSDFILESYSTEM_OP_DESTROY,
	    BSDFILESYSTEM_SCOPE_SHARED, NULL, name, BSDFILESYSTEM_PERSISTENT));
}

int
service_storage_destroy_group(struct service_context *context,
    const char *group, const char *name)
{
	if (group == NULL || group[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	return (storage_destroy_scoped(context, BSDFILESYSTEM_OP_DESTROY,
	    BSDFILESYSTEM_SCOPE_GROUP, group, name, BSDFILESYSTEM_PERSISTENT));
}

/*
 * Drop this process's mount anchor on a persistent (or cache) UNIT claim
 * WITHOUT destroying it, so the claim can then be committed to
 * (service_storage_txn_commit(3)) or rolled back (service_storage_rollback(3)):
 * a mounted dataset cannot be swapped/rolled back (EBUSY).  Idempotent -- a
 * claim not currently anchored by this process is success.  The caller should
 * close any delivered directory fd for the claim first.
 */
int
service_storage_release(struct service_context *context, const char *name)
{
	return (storage_destroy_scoped(context, BSDFILESYSTEM_OP_UNMOUNT,
	    BSDFILESYSTEM_SCOPE_UNIT, NULL, name, BSDFILESYSTEM_PERSISTENT));
}

int
service_storage_release_cache(struct service_context *context, const char *name)
{
	return (storage_destroy_scoped(context, BSDFILESYSTEM_OP_UNMOUNT,
	    BSDFILESYSTEM_SCOPE_UNIT, NULL, name, BSDFILESYSTEM_CACHE));
}

int
service_storage_release_shared(struct service_context *context,
    const char *name)
{
	return (storage_destroy_scoped(context, BSDFILESYSTEM_OP_UNMOUNT,
	    BSDFILESYSTEM_SCOPE_SHARED, NULL, name, BSDFILESYSTEM_PERSISTENT));
}

int
service_storage_release_group(struct service_context *context,
    const char *group, const char *name)
{
	if (group == NULL || group[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	return (storage_destroy_scoped(context, BSDFILESYSTEM_OP_UNMOUNT,
	    BSDFILESYSTEM_SCOPE_GROUP, group, name, BSDFILESYSTEM_PERSISTENT));
}

/*
 * Report one of the caller's own persistent claims' live usage (bytes referenced,
 * refquota ceiling, bytes still writable).  Data-only in both directions, scoped
 * to the caller's own label-derived namespace, so it can never observe another
 * label's storage.  Returns 0 with *out filled, or -1 with errno (ENOENT if the
 * claim does not exist).  Shares the system.Filesystem channel.
 */
int
service_storage_stat(struct service_context *context, const char *name,
    struct service_storage_stat_result *out)
{
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_stat_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;

	if (name == NULL || out == NULL ||
	    strnlen(name, sizeof(rq.dataset)) >= sizeof(rq.dataset) ||
	    !service_provider_component_valid(name, sizeof(rq.dataset))) {
		errno = EINVAL;
		return (-1);
	}
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (fs_session_open() == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_STAT_CLAIM;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	(void)strlcpy(rq.dataset, name, sizeof(rq.dataset));
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	options.timeout_ms = SERVICE_STORAGE_CALL_TIMEOUT_MS;
	if (fs_session_call(&outgoing, &incoming, &options) == -1) {
		int saved = errno;

		fs_session_fail();
		errno = saved;
		return (-1);
	}
	if (incoming.length != sizeof(rp) || incoming.nfds != 0 ||
	    rp._reserved != 0 || !service_provider_status_valid(rp.status))
		return (service_provider_protocol_error(-1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	out->used = rp.used;
	out->refquota = rp.refquota;
	out->available = rp.available;
	return (0);
}

/*
 * Raise or lower one of the caller's own persistent claims' refquota after the
 * mint (quota bytes; 0 removes the ceiling).  Same floor and authority as the
 * original claim.  Returns 0, or -1 with errno (EINVAL below the floor, ENOENT
 * if the claim does not exist).
 */
int
service_storage_set_quota(struct service_context *context, const char *name,
    uint64_t quota)
{
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;

	if (name == NULL ||
	    strnlen(name, sizeof(rq.dataset)) >= sizeof(rq.dataset) ||
	    !service_provider_component_valid(name, sizeof(rq.dataset))) {
		errno = EINVAL;
		return (-1);
	}
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (fs_session_open() == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_SET_QUOTA;
	rq.lifetime = BSDFILESYSTEM_PERSISTENT;
	rq.quota = quota;
	(void)strlcpy(rq.dataset, name, sizeof(rq.dataset));
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	options.timeout_ms = SERVICE_STORAGE_CALL_TIMEOUT_MS;
	if (fs_session_call(&outgoing, &incoming, &options) == -1) {
		int saved = errno;

		fs_session_fail();
		errno = saved;
		return (-1);
	}
	if (incoming.length != sizeof(rp) || incoming.nfds != 0 ||
	    rp._reserved != 0 || !service_provider_status_valid(rp.status) ||
	    !service_provider_all_zero(rp.dataset, sizeof(rp.dataset)))
		return (service_provider_protocol_error(-1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

/*
 * Snapshot / time-travel wrappers (system.Filesystem #2).  Each carries a
 * bsdfilesystem_version_request and shares the system.Filesystem session; every op
 * is owner-scoped to the caller's own persistent claim.
 */
static int
storage_version_call(uint32_t op, const char *name, const char *version,
    uint32_t cursor, void *reply, size_t reply_len, int *fdp)
{
	struct bsdfilesystem_version_request vrq;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int handle = -1;

	if (name == NULL ||
	    strnlen(name, sizeof(vrq.dataset)) >= sizeof(vrq.dataset) ||
	    !service_provider_component_valid(name, sizeof(vrq.dataset)) ||
	    (version != NULL &&
	    strnlen(version, sizeof(vrq.version)) >= sizeof(vrq.version))) {
		errno = EINVAL;
		return (-1);
	}
	/* The public wrappers checked the caller's own context. */
	if (fs_session_open() == -1)
		return (-1);

	memset(&vrq, 0, sizeof(vrq));
	vrq.op = op;
	vrq.lifetime = BSDFILESYSTEM_PERSISTENT;
	vrq.cursor = cursor;
	(void)strlcpy(vrq.dataset, name, sizeof(vrq.dataset));
	if (version != NULL)
		(void)strlcpy(vrq.version, version, sizeof(vrq.version));
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &vrq;
	outgoing.length = sizeof(vrq);
	memset(reply, 0, reply_len);
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = reply_len;
	if (fdp != NULL) {
		incoming.fds = &handle;
		incoming.fd_capacity = 1;
	}
	options.timeout_ms = SERVICE_STORAGE_CALL_TIMEOUT_MS;
	if (fs_session_call(&outgoing, &incoming, &options) == -1) {
		int saved = errno;

		fs_session_fail();
		errno = saved;
		return (-1);
	}
	if (incoming.length != reply_len)
		return (service_provider_protocol_error(incoming.nfds != 0 ? handle : -1));
	if (fdp != NULL)
		*fdp = incoming.nfds == 1 ? handle : -1;
	else if (incoming.nfds != 0)
		return (service_provider_protocol_error(handle));
	return (0);
}

int
service_storage_snapshot(struct service_context *context, const char *name,
    char *version, size_t vsz)
{
	struct bsdfilesystem_version_reply rp;

	if (service_context_check(context) != 0 || version == NULL || vsz == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (storage_version_call(BSDFILESYSTEM_OP_SNAPSHOT, name, NULL, 0, &rp,
	    sizeof(rp), NULL) == -1)
		return (-1);
	if (rp._reserved != 0 || !service_provider_status_valid(rp.status) ||
	    memchr(rp.version, '\0', sizeof(rp.version)) == NULL)
		return (service_provider_protocol_error(-1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	if (strlcpy(version, rp.version, vsz) >= vsz) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	return (0);
}

int
service_storage_rollback(struct service_context *context, const char *name,
    const char *version)
{
	struct bsdfilesystem_reply rp;

	if (service_context_check(context) != 0 || version == NULL ||
	    version[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	if (storage_version_call(BSDFILESYSTEM_OP_ROLLBACK, name, version, 0, &rp,
	    sizeof(rp), NULL) == -1)
		return (-1);
	if (rp._reserved != 0 || !service_provider_status_valid(rp.status) ||
	    !service_provider_all_zero(rp.dataset, sizeof(rp.dataset)))
		return (service_provider_protocol_error(-1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
service_storage_open_version(struct service_context *context, const char *name,
    const char *version, int *dirfdp)
{
	struct bsdfilesystem_reply rp;
	int fd = -1;

	if (service_context_check(context) != 0 || version == NULL ||
	    version[0] == '\0' || dirfdp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (storage_version_call(BSDFILESYSTEM_OP_OPEN_VERSION, name, version, 0,
	    &rp, sizeof(rp), &fd) == -1)
		return (-1);
	if (rp._reserved != 0 || !service_provider_status_valid(rp.status) ||
	    !service_provider_all_zero(rp.dataset, sizeof(rp.dataset)) ||
	    (rp.status == 0) != (fd >= 0)) {
		if (fd >= 0)
			(void)close(fd);
		return (service_provider_protocol_error(-1));
	}
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	*dirfdp = fd;
	return (0);
}

/*
 * Atomic multi-file transactions (system.Filesystem #3).  txn_begin snapshots the
 * claim and hands back a writable mounted clone plus its txn id; the caller edits
 * the clone, then txn_commit (atomic swap) or txn_abort (discard).
 */
int
service_storage_txn_begin(struct service_context *context, const char *name,
    char *txn_id, size_t tsz, int *dirfdp)
{
	struct bsdfilesystem_version_reply rp;
	int fd = -1;

	if (service_context_check(context) != 0 || txn_id == NULL || tsz == 0 ||
	    dirfdp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (storage_version_call(BSDFILESYSTEM_OP_TXN_BEGIN, name, NULL, 0, &rp,
	    sizeof(rp), &fd) == -1)
		return (-1);
	if (rp._reserved != 0 || !service_provider_status_valid(rp.status) ||
	    memchr(rp.version, '\0', sizeof(rp.version)) == NULL ||
	    (rp.status == 0) != (fd >= 0)) {
		if (fd >= 0)
			(void)close(fd);
		return (service_provider_protocol_error(-1));
	}
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	if (strlcpy(txn_id, rp.version, tsz) >= tsz) {
		(void)close(fd);
		errno = ENAMETOOLONG;
		return (-1);
	}
	*dirfdp = fd;
	return (0);
}

static int
storage_txn_finish(uint32_t op, const char *name, const char *txn_id)
{
	struct bsdfilesystem_reply rp;

	if (txn_id == NULL || txn_id[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	if (storage_version_call(op, name, txn_id, 0, &rp, sizeof(rp),
	    NULL) == -1)
		return (-1);
	if (rp._reserved != 0 || !service_provider_status_valid(rp.status) ||
	    !service_provider_all_zero(rp.dataset, sizeof(rp.dataset)))
		return (service_provider_protocol_error(-1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	return (0);
}

int
service_storage_txn_commit(struct service_context *context, const char *name,
    const char *txn_id)
{
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (storage_txn_finish(BSDFILESYSTEM_OP_TXN_COMMIT, name, txn_id));
}

int
service_storage_txn_abort(struct service_context *context, const char *name,
    const char *txn_id)
{
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (storage_txn_finish(BSDFILESYSTEM_OP_TXN_ABORT, name, txn_id));
}

int
service_storage_list_versions(struct service_context *context, const char *name,
    char (*versions)[SERVICE_STORAGE_VERSION_MAX], size_t max, size_t *countp,
    uint32_t *cursorp)
{
	struct bsdfilesystem_versions_reply rp;
	uint32_t i;

	if (service_context_check(context) != 0 || versions == NULL ||
	    countp == NULL || cursorp == NULL || max == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (storage_version_call(BSDFILESYSTEM_OP_LIST_VERSIONS, name, NULL,
	    *cursorp, &rp, sizeof(rp), NULL) == -1)
		return (-1);
	if (rp._reserved != 0 || !service_provider_status_valid(rp.status) ||
	    rp.count > BSDFILESYSTEM_VERSIONS_MAX)
		return (service_provider_protocol_error(-1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	*countp = 0;
	for (i = 0; i < rp.count && *countp < max; i++) {
		if (memchr(rp.versions[i], '\0', BSDFILESYSTEM_NAME_MAX) == NULL)
			return (service_provider_protocol_error(-1));
		(void)strlcpy(versions[*countp], rp.versions[i],
		    SERVICE_STORAGE_VERSION_MAX);
		(*countp)++;
	}
	*cursorp = rp.next_cursor;
	return (0);
}

/*
 * Enumerate the caller's own persistent/cache claims (one page per call).  The
 * op carries no fd in either direction: bsdfilesystem walks only the caller's own
 * label-derived namespace and returns a data-only claim page, so this can never
 * observe another label's storage.  Shares the system.Filesystem channel with the
 * other storage wrappers.  Returns 0 with *countp set (and *cursorp advanced to
 * the next page, or 0 at the end), or -1 with errno.
 */
static int
storage_list_scoped(struct service_context *context, uint8_t scope,
    const char *group, struct service_storage_claim *claims, size_t max,
    size_t *countp, uint32_t *cursorp)
{
	struct bsdfilesystem_list_request rq;
	struct bsdfilesystem_list_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	uint32_t i;

	_Static_assert(SERVICE_STORAGE_LIST_MAX == BSDFILESYSTEM_LIST_MAX,
	    "public list page size must match the bsdfilesystem wire page size");

	if (claims == NULL || countp == NULL || cursorp == NULL || max == 0) {
		errno = EINVAL;
		return (-1);
	}
	*countp = 0;
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}
	/* GROUP requires a name; UNIT/SHARED must not carry one. */
	if ((scope == BSDFILESYSTEM_SCOPE_GROUP) !=
	    (group != NULL && group[0] != '\0')) {
		errno = EINVAL;
		return (-1);
	}

	/* Shares the system.Filesystem channel with storage/config claims. */
	if (fs_session_open() == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_LIST;
	rq.cursor = *cursorp;			/* flags/_reserved stay zero */
	rq.scope = scope;
	if (group != NULL && group[0] != '\0' &&
	    strlcpy(rq.group, group, sizeof(rq.group)) >= sizeof(rq.group)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	options.timeout_ms = SERVICE_STORAGE_CALL_TIMEOUT_MS;
	if (fs_session_call(&outgoing, &incoming, &options) == -1) {
		if (errno == EMSGSIZE)
			return (service_provider_protocol_error(-1));
		/*
		 * The call itself failed -- no reply within the bound, or the
		 * transport refused the send: the worker serving this
		 * connection is gone (a provider relaunch takes its workers
		 * with it).  A provider-reported status never lands here (it
		 * comes back in the reply), so any failure here means the
		 * session is dead: mark it so the next claim opens a fresh one
		 * instead of failing on a corpse forever.
		 */
		{
			int saved = errno;

			fs_session_fail();
			errno = saved;
		}
		return (-1);
	}
	/* Strict framing, errno, cursor, and entry validation. */
	if (incoming.length != sizeof(rp) || incoming.nfds != 0 ||
	    rp._reserved != 0 || !service_provider_status_valid(rp.status) ||
	    rp.count > BSDFILESYSTEM_LIST_MAX ||
	    (rp.status != 0 && (rp.count != 0 || rp.next_cursor != 0 ||
	    !service_provider_all_zero(rp.entries, sizeof(rp.entries)))) ||
	    (rp.status == 0 && ((rp.count == 0 && rp.next_cursor != 0) ||
	    (rp.next_cursor != 0 && rp.next_cursor <= rq.cursor))))
		return (service_provider_protocol_error(-1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	for (i = 0; i < rp.count; i++) {
		if (!service_provider_component_valid(rp.entries[i].name,
		    sizeof(rp.entries[i].name)) ||
		    rp.entries[i].lifetime > BSDFILESYSTEM_CACHE ||
		    !service_provider_all_zero(rp.entries[i]._reserved,
		    sizeof(rp.entries[i]._reserved)))
			return (service_provider_protocol_error(-1));
	}
	if (!service_provider_all_zero(&rp.entries[rp.count],
	    sizeof(rp.entries) - rp.count * sizeof(rp.entries[0])))
		return (service_provider_protocol_error(-1));
	/* Report the required page size without advancing past uncopied claims. */
	if (rp.count > max) {
		*countp = rp.count;
		errno = EMSGSIZE;
		return (-1);
	}
	for (i = 0; i < rp.count; i++) {
		(void)strlcpy(claims[i].name, rp.entries[i].name,
		    sizeof(claims[i].name));
		claims[i].used = rp.entries[i].used;
		claims[i].refquota = rp.entries[i].refquota;
		claims[i].lifetime = rp.entries[i].lifetime;
	}
	*countp = (size_t)i;
	*cursorp = rp.next_cursor;
	return (0);
}

int
service_storage_list(struct service_context *context,
    struct service_storage_claim *claims, size_t max, size_t *countp,
    uint32_t *cursorp)
{

	return (storage_list_scoped(context, BSDFILESYSTEM_SCOPE_UNIT, NULL,
	    claims, max, countp, cursorp));
}

int
service_storage_list_shared(struct service_context *context,
    struct service_storage_claim *claims, size_t max, size_t *countp,
    uint32_t *cursorp)
{

	return (storage_list_scoped(context, BSDFILESYSTEM_SCOPE_SHARED, NULL,
	    claims, max, countp, cursorp));
}

int
service_storage_list_group(struct service_context *context, const char *group,
    struct service_storage_claim *claims, size_t max, size_t *countp,
    uint32_t *cursorp)
{

	if (group == NULL || group[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	return (storage_list_scoped(context, BSDFILESYSTEM_SCOPE_GROUP, group,
	    claims, max, countp, cursorp));
}

/*
 * Open this service's writable configuration area and return its mounted
 * directory root.  This is the well-known "config" claim under the service's
 * per-bundle container (Data/<bundle>/<unit>/persistent/config): a place for
 * configuration files that live outside the shared UNIX directories, writable by
 * the service (and by an administrator who provisions it out of band), scoped so
 * a service only ever reaches its own config and never another's.  It is the
 * companion of the "state" storage claim; both are just named children of the
 * same per-service home, so this is a thin, discoverable wrapper over
 * service_storage_open(3).  Returns 0 with *dirfdp set, or -1 with errno.
 */
int
service_open_config(struct service_context *context, int *dirfdp)
{

	return (service_storage_open(context, "config", dirfdp));
}

/*
 * Open an existing filesystem path (a device node, a shared directory, a config
 * file) via bsdfilesystem and return a Capsicum-rights-limited descriptor.  This is how
 * a sandboxed service reaches a path it cannot name itself, with no manifest
 * declaration: bsdfilesystem applies its own per-label policy (default-deny) and opens
 * only the exact paths this service's unforgeable label is granted.  `rights` is
 * a SERVICE_OPEN_* mask; `is_dir` requires the target to be a directory.  The
 * returned descriptor is close-on-exec and carries no more than the requested
 * rights.  Returns 0 with *fdp set, or -1 with errno (EACCES if not granted).
 */
int
service_open_isolated(struct service_context *context, const char *path,
    unsigned rights, int is_dir, int *fdp)
{
	struct bsdfilesystem_open_request rq;
	struct bsdfilesystem_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int fd = -1;

	if (fdp == NULL || path == NULL || path[0] != '/' || rights == 0 ||
	    (rights & ~(unsigned)BSDFILESYSTEM_OPEN_RIGHTS_ALL) != 0) {
		errno = EINVAL;
		return (-1);
	}
	*fdp = -1;
	if (strnlen(path, sizeof(rq.path)) >= sizeof(rq.path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Shares the system.Filesystem channel with storage/config claims. */
	if (fs_session_open() == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = BSDFILESYSTEM_OP_OPEN;
	rq.rights = rights;
	rq.is_dir = is_dir ? 1 : 0;
	(void)strlcpy(rq.path, path, sizeof(rq.path));
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	incoming.fds = &fd;
	incoming.fd_capacity = 1;
	options.timeout_ms = SERVICE_STORAGE_CALL_TIMEOUT_MS;
	if (fs_session_call(&outgoing, &incoming, &options) == -1) {
		if (errno == EMSGSIZE)
			return (service_provider_protocol_error(-1));
		/*
		 * The call itself failed -- no reply within the bound, or the
		 * transport refused the send: the worker serving this
		 * connection is gone (a provider relaunch takes its workers
		 * with it).  A provider-reported status never lands here (it
		 * comes back in the reply), so any failure here means the
		 * session is dead: mark it so the next claim opens a fresh one
		 * instead of failing on a corpse forever.
		 */
		{
			int saved = errno;

			fs_session_fail();
			errno = saved;
		}
		return (-1);
	}
	if (incoming.length != sizeof(rp) || rp._reserved != 0 ||
	    !service_provider_status_valid(rp.status) ||
	    !service_provider_all_zero(rp.dataset, sizeof(rp.dataset)) ||
	    (rp.status == 0 ? incoming.nfds != 1 : incoming.nfds != 0))
		return (service_provider_protocol_error(incoming.nfds != 0 ? fd : -1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	*fdp = fd;
	return (0);
}
