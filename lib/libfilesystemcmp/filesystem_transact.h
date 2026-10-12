/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Client side of bsd.filesystem.v1 for the libraries that build their requests
 * in the legacy record shapes of bsdfilesystem_proto.h (libfilesystemcmp and
 * libbsdfilesystem).  fs_transact() sends one such record as the matching
 * method and rebuilds the legacy-shaped reply from the method's result, so the
 * callers' argument and reply validation is unchanged.  Not installed;
 * included by each library, whose copy is private to it.
 */
#ifndef _FILESYSTEM_TRANSACT_H_
#define	_FILESYSTEM_TRANSACT_H_

#include <sys/types.h>

#include <errno.h>
#include <fidl/bsd.filesystem.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <service_runtime.h>
#include <bsdfilesystem_proto.h>

struct fs_transport {
	struct fidl_bsd_connection *connection;
	pid_t			 owner;
	bool			 negotiated;
};

struct fs_completion {
	bool		 done, malformed;
	int		 error;		/* transport error, or EPROTO */
	void		*reply;		/* legacy-shaped reply buffer */
	size_t		 capacity, length;
	int		 fd;		/* delivered descriptor, or -1 */
	uint32_t	 cursor;	/* List/ListVersions request cursor */
};

/* Abandon the connection; close it only when this process opened it. */
static void __unused
fs_transport_drop(struct fs_transport *t)
{

	if (t->connection != NULL && t->owner == getpid())
		fidl_bsd_connection_destroy(t->connection);
	t->connection = NULL;
	t->owner = 0;
	t->negotiated = false;
}

/* Adopt a held channel; consumes fd only on success. */
static int __unused
fs_transport_adopt(struct fs_transport *t, int fd)
{
	int error;

	error = fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT, &t->connection);
	if (error != 0) {
		t->connection = NULL;
		return (errno = error, -1);
	}
	t->owner = getpid();
	t->negotiated = false;
	return (0);
}

static int __unused
fs_transport_open(struct fs_transport *t)
{
	int error, fd;

	if (service_open(BSDFILESYSTEM_SERVICE_NAME, &fd) == -1)
		return (-1);
	if (fs_transport_adopt(t, fd) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	return (0);
}

/* The legacy reply every method shares: { int32 status, ... }. */
static void
fs_status(struct fs_completion *c, size_t size, uint32_t err)
{

	if (size > c->capacity || err == 0 || err > ELAST) {
		c->malformed = true;
		return;
	}
	memset(c->reply, 0, size);
	*(int32_t *)c->reply = (int32_t)err;
	c->length = size;
}

/* Copy a reply string into a legacy field: no NUL inside, room for one. */
static bool
fs_field(char *out, size_t outsz, const char *in, size_t length)
{

	if (length >= outsz || (length != 0 && memchr(in, '\0', length) != NULL))
		return (false);
	if (length != 0)
		memcpy(out, in, length);
	out[length] = '\0';
	return (true);
}

static void
fs_info_reply(void *context, int error,
    struct bsd_filesystem_v1_ProtocolInfo *v)
{
	struct fs_completion *c = context;

	c->done = true;
	c->error = error;
	if (!error && (v == NULL ||
	    v->wire_version != BSDFILESYSTEM_WIRE_VERSION)) {
		c->malformed = true;
		c->error = EPROTONOSUPPORT;
	}
}

/*
 * The result of a method whose legacy reply is a status-only
 * bsdfilesystem_reply, optionally with a descriptor.
 */
#define	FS_REPLY_EMPTY(fn, method)					\
static void								\
fn(void *context, int error,						\
    struct bsd_filesystem_v1_Filesystem_##method##_Result *v)		\
{									\
	struct fs_completion *c = context;				\
									\
	c->done = true;							\
	c->error = error;						\
	if (error)							\
		return;							\
	if (v == NULL)							\
		c->malformed = true;					\
	else if (v->tag ==						\
	    bsd_filesystem_v1_Filesystem_##method##_Result_err_tag)	\
		fs_status(c, sizeof(struct bsdfilesystem_reply),	\
		    v->value.err);					\
	else if (v->tag !=						\
	    bsd_filesystem_v1_Filesystem_##method##_Result_response_tag ||	\
	    c->capacity < sizeof(struct bsdfilesystem_reply))		\
		c->malformed = true;					\
	else {								\
		memset(c->reply, 0, sizeof(struct bsdfilesystem_reply)); \
		c->length = sizeof(struct bsdfilesystem_reply);		\
	}								\
}
FS_REPLY_EMPTY(fs_release_reply, Release)
FS_REPLY_EMPTY(fs_ping_reply, Ping)
FS_REPLY_EMPTY(fs_session_reply, BeginSession)
FS_REPLY_EMPTY(fs_destroy_reply, Destroy)
FS_REPLY_EMPTY(fs_quota_reply, SetQuota)
FS_REPLY_EMPTY(fs_rollback_reply, Rollback)
FS_REPLY_EMPTY(fs_commit_reply, TxnCommit)
FS_REPLY_EMPTY(fs_abort_reply, TxnAbort)
FS_REPLY_EMPTY(fs_unmount_reply, Unmount)

#define	FS_REPLY_FD(fn, method)						\
static void								\
fn(void *context, int error,						\
    struct bsd_filesystem_v1_Filesystem_##method##_Result *v)		\
{									\
	struct fs_completion *c = context;				\
									\
	c->done = true;							\
	c->error = error;						\
	if (error)							\
		return;							\
	if (v == NULL)							\
		c->malformed = true;					\
	else if (v->tag ==						\
	    bsd_filesystem_v1_Filesystem_##method##_Result_err_tag)	\
		fs_status(c, sizeof(struct bsdfilesystem_reply),	\
		    v->value.err);					\
	else if (v->tag !=						\
	    bsd_filesystem_v1_Filesystem_##method##_Result_response_tag ||	\
	    c->capacity < sizeof(struct bsdfilesystem_reply))		\
		c->malformed = true;					\
	else {								\
		/* Retain the descriptor first so nothing can leak it. */ \
		c->fd = fidl_bsd_take_fd(&v->value.response.handle);	\
		memset(c->reply, 0, sizeof(struct bsdfilesystem_reply)); \
		c->length = sizeof(struct bsdfilesystem_reply);		\
		if (c->fd < 0)						\
			c->malformed = true;				\
	}								\
}
FS_REPLY_FD(fs_open_reply, Open)
FS_REPLY_FD(fs_open_version_reply, OpenVersion)

static void
fs_request_reply(void *context, int error,
    struct bsd_filesystem_v1_Filesystem_Request_Result *v)
{
	struct fs_completion *c = context;
	struct bsdfilesystem_reply *rp = c->reply;

	c->done = true;
	c->error = error;
	if (error)
		return;
	if (v == NULL)
		c->malformed = true;
	else if (v->tag == bsd_filesystem_v1_Filesystem_Request_Result_err_tag)
		fs_status(c, sizeof(*rp), v->value.err);
	else if (v->tag !=
	    bsd_filesystem_v1_Filesystem_Request_Result_response_tag ||
	    c->capacity < sizeof(*rp))
		c->malformed = true;
	else {
		c->fd = fidl_bsd_take_fd(&v->value.response.handle);
		memset(rp, 0, sizeof(*rp));
		c->length = sizeof(*rp);
		if (c->fd < 0 || !fs_field(rp->dataset, sizeof(rp->dataset),
		    v->value.response.dataset, v->value.response.dataset_size))
			c->malformed = true;
	}
}

static void
fs_stat_reply(void *context, int error,
    struct bsd_filesystem_v1_Filesystem_StatClaim_Result *v)
{
	struct fs_completion *c = context;
	struct bsdfilesystem_stat_reply *srp = c->reply;

	c->done = true;
	c->error = error;
	if (error)
		return;
	if (v == NULL)
		c->malformed = true;
	else if (v->tag ==
	    bsd_filesystem_v1_Filesystem_StatClaim_Result_err_tag)
		fs_status(c, sizeof(*srp), v->value.err);
	else if (v->tag !=
	    bsd_filesystem_v1_Filesystem_StatClaim_Result_response_tag ||
	    c->capacity < sizeof(*srp))
		c->malformed = true;
	else {
		memset(srp, 0, sizeof(*srp));
		srp->used = v->value.response.used;
		srp->refquota = v->value.response.refquota;
		srp->available = v->value.response.available;
		c->length = sizeof(*srp);
	}
}

static void
fs_list_reply(void *context, int error,
    struct bsd_filesystem_v1_Filesystem_List_Result *v)
{
	struct fs_completion *c = context;
	struct bsdfilesystem_list_reply *lrp = c->reply;
	const struct bsd_filesystem_v1_ClaimPage *page;
	size_t i;

	c->done = true;
	c->error = error;
	if (error)
		return;
	if (v == NULL) {
		c->malformed = true;
		return;
	}
	if (v->tag == bsd_filesystem_v1_Filesystem_List_Result_err_tag) {
		fs_status(c, sizeof(*lrp), v->value.err);
		return;
	}
	if (v->tag != bsd_filesystem_v1_Filesystem_List_Result_response_tag ||
	    c->capacity < sizeof(*lrp)) {
		c->malformed = true;
		return;
	}
	page = &v->value.response;
	memset(lrp, 0, sizeof(*lrp));
	if (page->entries_size > BSDFILESYSTEM_LIST_MAX) {
		c->malformed = true;
		return;
	}
	for (i = 0; i < page->entries_size; i++) {
		const struct bsd_filesystem_v1_ClaimEntry *e = &page->entries[i];

		if (!fs_field(lrp->entries[i].name, sizeof(lrp->entries[i].name),
		    e->name, e->name_size)) {
			c->malformed = true;
			return;
		}
		lrp->entries[i].used = e->used;
		lrp->entries[i].refquota = e->refquota;
		lrp->entries[i].lifetime = e->lifetime;
	}
	lrp->count = (uint32_t)page->entries_size;
	lrp->next_cursor = page->next_cursor;
	c->length = sizeof(*lrp);
}

static void
fs_snapshot_reply(void *context, int error,
    struct bsd_filesystem_v1_Filesystem_Snapshot_Result *v)
{
	struct fs_completion *c = context;
	struct bsdfilesystem_version_reply *vrp = c->reply;

	c->done = true;
	c->error = error;
	if (error)
		return;
	if (v == NULL)
		c->malformed = true;
	else if (v->tag == bsd_filesystem_v1_Filesystem_Snapshot_Result_err_tag)
		fs_status(c, sizeof(*vrp), v->value.err);
	else if (v->tag !=
	    bsd_filesystem_v1_Filesystem_Snapshot_Result_response_tag ||
	    c->capacity < sizeof(*vrp))
		c->malformed = true;
	else {
		memset(vrp, 0, sizeof(*vrp));
		c->length = sizeof(*vrp);
		if (!fs_field(vrp->version, sizeof(vrp->version),
		    v->value.response.version, v->value.response.version_size))
			c->malformed = true;
	}
}

static void
fs_txn_begin_reply(void *context, int error,
    struct bsd_filesystem_v1_Filesystem_TxnBegin_Result *v)
{
	struct fs_completion *c = context;
	struct bsdfilesystem_version_reply *vrp = c->reply;

	c->done = true;
	c->error = error;
	if (error)
		return;
	if (v == NULL)
		c->malformed = true;
	else if (v->tag == bsd_filesystem_v1_Filesystem_TxnBegin_Result_err_tag)
		fs_status(c, sizeof(*vrp), v->value.err);
	else if (v->tag !=
	    bsd_filesystem_v1_Filesystem_TxnBegin_Result_response_tag ||
	    c->capacity < sizeof(*vrp))
		c->malformed = true;
	else {
		c->fd = fidl_bsd_take_fd(&v->value.response.handle);
		memset(vrp, 0, sizeof(*vrp));
		c->length = sizeof(*vrp);
		if (c->fd < 0 || !fs_field(vrp->version, sizeof(vrp->version),
		    v->value.response.txn, v->value.response.txn_size))
			c->malformed = true;
	}
}

static void
fs_versions_reply(void *context, int error,
    struct bsd_filesystem_v1_Filesystem_ListVersions_Result *v)
{
	struct fs_completion *c = context;
	struct bsdfilesystem_versions_reply *vsrp = c->reply;
	const struct bsd_filesystem_v1_VersionPage *page;
	size_t i;

	c->done = true;
	c->error = error;
	if (error)
		return;
	if (v == NULL) {
		c->malformed = true;
		return;
	}
	if (v->tag == bsd_filesystem_v1_Filesystem_ListVersions_Result_err_tag) {
		fs_status(c, sizeof(*vsrp), v->value.err);
		return;
	}
	if (v->tag !=
	    bsd_filesystem_v1_Filesystem_ListVersions_Result_response_tag ||
	    c->capacity < sizeof(*vsrp)) {
		c->malformed = true;
		return;
	}
	page = &v->value.response;
	memset(vsrp, 0, sizeof(*vsrp));
	if (page->versions_size > BSDFILESYSTEM_VERSIONS_MAX) {
		c->malformed = true;
		return;
	}
	for (i = 0; i < page->versions_size; i++)
		if (!fs_field(vsrp->versions[i], sizeof(vsrp->versions[i]),
		    page->versions[i].version, page->versions[i].version_size)) {
			c->malformed = true;
			return;
		}
	vsrp->count = (uint32_t)page->versions_size;
	vsrp->next_cursor = page->next_cursor;
	c->length = sizeof(*vsrp);
}

/*
 * A record the schema cannot carry (a field the legacy rules forbid) is the
 * provider's EINVAL, answered locally; the session is unaffected.
 */
static int
fs_local_einval(struct fs_completion *c, size_t *lengthp)
{

	memset(c->reply, 0, c->capacity);
	if (c->capacity >= sizeof(int32_t))
		*(int32_t *)c->reply = EINVAL;
	*lengthp = c->capacity;
	return (0);
}

/* Wait for one completion; transport errors and malformed results fail. */
static int
fs_wait(struct fs_transport *t, int error, struct fs_completion *c,
    const struct timespec *deadline)
{

	if (error == 0)
		error = fidl_bsd_sync_wait(t->connection, &c->done, deadline);
	if (error == 0 && c->malformed)
		error = c->error != 0 ? c->error : EPROTO;
	if (error != 0 && c->fd >= 0) {
		(void)close(c->fd);
		c->fd = -1;
	}
	return (error);
}

/* A request record's strings, as the legacy validators require them. */
static bool
fs_string(const char *field, size_t capacity, const char **out, size_t *len)
{
	const char *nul = memchr(field, '\0', capacity);

	if (nul == NULL)
		return (false);
	*out = field;
	*len = (size_t)(nul - field);
	return (true);
}

static bool
fs_ref(struct bsd_filesystem_v1_ClaimRef *ref, uint8_t lifetime,
    uint8_t scope, const char *dataset, size_t dsz, const char *group,
    size_t gsz)
{

	memset(ref, 0, sizeof(*ref));
	ref->lifetime = lifetime;
	ref->scope = scope;
	return (fs_string(dataset, dsz, &ref->dataset, &ref->dataset_size) &&
	    fs_string(group, gsz, &ref->group, &ref->group_size));
}

/*
 * Send one legacy-shaped request record as its bsd.filesystem.v1 method.
 * Returns 0 with the legacy-shaped reply in reply and *lengthp and any delivered
 * descriptor in *fdp (the reply's status may be an application errno), or an
 * errno on a transport failure, timeout or malformed reply, after which the
 * caller must drop the transport.  A record this client cannot express in the
 * schema (a field the legacy rules forbid anyway) is EINVAL from here.
 */
static int __unused
fs_transact(struct fs_transport *t, const void *record, size_t rqlen,
    void *reply, size_t capacity, size_t *lengthp, int *fdp,
    uint32_t timeout_ms)
{
	struct fs_completion c = { .reply = reply, .capacity = capacity,
		.fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;
	uint32_t op, txid;
	int error;

	*lengthp = 0;
	*fdp = -1;
	if (t->connection == NULL)
		return (EPIPE);
	if (t->owner != getpid())
		return (ECHILD);
	if (rqlen < sizeof(op))
		return (EINVAL);
	memcpy(&op, record, sizeof(op));
	/* A caller's service_budget_begin(3) bounds the whole operation. */
	if (service_budget_timeout(&timeout_ms) == -1)
		return (errno);
	if ((error = fidl_bsd_sync_deadline(&deadline, timeout_ms)) != 0)
		return (error);
	if (!t->negotiated) {
		struct fs_completion info = { .fd = -1 };

		error = fs_wait(t, bsd_filesystem_v1_Filesystem_GetProtocolInfo(
		    t->connection, &empty, fs_info_reply, &info, &txid), &info,
		    &deadline);
		if (error != 0)
			return (error);
		t->negotiated = true;
	}

	if (rqlen == sizeof(struct bsdfilesystem_open_request) &&
	    op == BSDFILESYSTEM_OP_OPEN) {
		const struct bsdfilesystem_open_request *orq = record;
		struct bsd_filesystem_v1_OpenRequest m = {
			.rights = orq->rights, .is_dir = orq->is_dir != 0
		};

		if (orq->is_dir > 1 || !fs_string(orq->path, sizeof(orq->path),
		    &m.path, &m.path_size))
			return (fs_local_einval(&c, lengthp));
		error = bsd_filesystem_v1_Filesystem_Open(t->connection, &m,
		    fs_open_reply, &c, &txid);
	} else if (rqlen == sizeof(struct bsdfilesystem_list_request) &&
	    op == BSDFILESYSTEM_OP_LIST) {
		const struct bsdfilesystem_list_request *lrq = record;
		struct bsd_filesystem_v1_ListRequest m = {
			.cursor = lrq->cursor, .scope = lrq->scope
		};

		if (lrq->flags != 0 || !fs_string(lrq->group,
		    sizeof(lrq->group), &m.group, &m.group_size))
			return (fs_local_einval(&c, lengthp));
		c.cursor = lrq->cursor;
		error = bsd_filesystem_v1_Filesystem_List(t->connection, &m,
		    fs_list_reply, &c, &txid);
	} else if (rqlen == sizeof(struct bsdfilesystem_version_request)) {
		const struct bsdfilesystem_version_request *vrq = record;
		struct bsd_filesystem_v1_VersionRef ref;
		struct bsd_filesystem_v1_VersionsRequest list;

		if (!fs_ref(&ref.claim, vrq->lifetime, vrq->scope, vrq->dataset,
		    sizeof(vrq->dataset), vrq->group, sizeof(vrq->group)) ||
		    !fs_string(vrq->version, sizeof(vrq->version), &ref.version,
		    &ref.version_size))
			return (fs_local_einval(&c, lengthp));
		switch (op) {
		case BSDFILESYSTEM_OP_SNAPSHOT:
			error = bsd_filesystem_v1_Filesystem_Snapshot(
			    t->connection, &ref.claim, fs_snapshot_reply, &c,
			    &txid);
			break;
		case BSDFILESYSTEM_OP_LIST_VERSIONS:
			list.claim = ref.claim;
			list.cursor = vrq->cursor;
			error = bsd_filesystem_v1_Filesystem_ListVersions(
			    t->connection, &list, fs_versions_reply, &c, &txid);
			break;
		case BSDFILESYSTEM_OP_ROLLBACK:
			error = bsd_filesystem_v1_Filesystem_Rollback(
			    t->connection, &ref, fs_rollback_reply, &c, &txid);
			break;
		case BSDFILESYSTEM_OP_OPEN_VERSION:
			error = bsd_filesystem_v1_Filesystem_OpenVersion(
			    t->connection, &ref, fs_open_version_reply, &c,
			    &txid);
			break;
		case BSDFILESYSTEM_OP_TXN_BEGIN:
			error = bsd_filesystem_v1_Filesystem_TxnBegin(
			    t->connection, &ref.claim, fs_txn_begin_reply, &c,
			    &txid);
			break;
		case BSDFILESYSTEM_OP_TXN_COMMIT:
			error = bsd_filesystem_v1_Filesystem_TxnCommit(
			    t->connection, &ref, fs_commit_reply, &c, &txid);
			break;
		case BSDFILESYSTEM_OP_TXN_ABORT:
			error = bsd_filesystem_v1_Filesystem_TxnAbort(
			    t->connection, &ref, fs_abort_reply, &c, &txid);
			break;
		default:
			return (fs_local_einval(&c, lengthp));
		}
	} else if (rqlen == sizeof(struct bsdfilesystem_request)) {
		const struct bsdfilesystem_request *rq = record;
		struct bsd_filesystem_v1_ClaimRef ref;

		if (!fs_ref(&ref, rq->lifetime, rq->scope, rq->dataset,
		    sizeof(rq->dataset), rq->group, sizeof(rq->group)))
			return (fs_local_einval(&c, lengthp));
		switch (op) {
		case BSDFILESYSTEM_OP_REQUEST: {
			struct bsd_filesystem_v1_ClaimRequest m = {
				.flags = rq->flags, .rights = rq->rights,
				.quota = rq->quota, .lifetime = rq->lifetime,
				.deliver = rq->deliver, .scope = rq->scope,
				.owner_uid = rq->owner_uid,
				.owner_gid = rq->owner_gid,
				.dataset = ref.dataset,
				.dataset_size = ref.dataset_size,
				.group = ref.group, .group_size = ref.group_size
			};

			if (rq->session[0] != '\0')
				return (fs_local_einval(&c, lengthp));
			error = bsd_filesystem_v1_Filesystem_Request(
			    t->connection, &m, fs_request_reply, &c, &txid);
			break;
		}
		case BSDFILESYSTEM_OP_RELEASE: {
			struct bsd_filesystem_v1_Named m = {
				.dataset = ref.dataset,
				.dataset_size = ref.dataset_size
			};

			error = bsd_filesystem_v1_Filesystem_Release(
			    t->connection, &m, fs_release_reply, &c, &txid);
			break;
		}
		case BSDFILESYSTEM_OP_PING:
			error = bsd_filesystem_v1_Filesystem_Ping(t->connection,
			    &empty, fs_ping_reply, &c, &txid);
			break;
		case BSDFILESYSTEM_OP_BEGIN_SESSION: {
			struct bsd_filesystem_v1_Session m;

			if (!fs_string(rq->session, sizeof(rq->session),
			    &m.session, &m.session_size))
				return (fs_local_einval(&c, lengthp));
			error = bsd_filesystem_v1_Filesystem_BeginSession(
			    t->connection, &m, fs_session_reply, &c, &txid);
			break;
		}
		case BSDFILESYSTEM_OP_DESTROY:
			error = bsd_filesystem_v1_Filesystem_Destroy(
			    t->connection, &ref, fs_destroy_reply, &c, &txid);
			break;
		case BSDFILESYSTEM_OP_UNMOUNT:
			error = bsd_filesystem_v1_Filesystem_Unmount(
			    t->connection, &ref, fs_unmount_reply, &c, &txid);
			break;
		case BSDFILESYSTEM_OP_STAT_CLAIM:
			error = bsd_filesystem_v1_Filesystem_StatClaim(
			    t->connection, &ref, fs_stat_reply, &c, &txid);
			break;
		case BSDFILESYSTEM_OP_SET_QUOTA: {
			struct bsd_filesystem_v1_QuotaRequest m = {
				.claim = ref, .quota = rq->quota
			};

			error = bsd_filesystem_v1_Filesystem_SetQuota(
			    t->connection, &m, fs_quota_reply, &c, &txid);
			break;
		}
		default:
			return (fs_local_einval(&c, lengthp));
		}
	} else
		return (fs_local_einval(&c, lengthp));
	error = fs_wait(t, error, &c, &deadline);
	if (error != 0)
		return (error);
	*lengthp = c.length;
	*fdp = c.fd;
	return (0);
}

#endif /* !_FILESYSTEM_TRANSACT_H_ */
