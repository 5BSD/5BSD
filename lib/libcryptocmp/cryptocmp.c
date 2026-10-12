/*- SPDX-License-Identifier: BSD-2-Clause */
/*
 * system.Crypto client, using the generated bsd.crypto.v1 bindings
 * (cryptocmp.fidl) over a native capability channel.  A transport failure,
 * timeout or malformed reply makes the client terminal; application errors
 * keep it.  Received descriptors are owned by the caller only after the reply
 * validates; otherwise they are closed.
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/cryptodesc.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.crypto.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <crypto/cryptodev.h>
#include <libservice.h>
#include <service_runtime.h>
#include "cryptocmp.h"

#define	CRYPTOCMP_CALL_TIMEOUT_MS	30000

struct cryptocmp_client {
	struct fidl_bsd_connection *connection;
	pid_t owner;
	bool negotiated;
	int terminal_error;
	/*
	 * A client may be shared between threads; the connection has a single
	 * dispatch thread, so calls are serialized (begin() locks, finish()
	 * unlocks).
	 */
	pthread_mutex_t lock;
};

struct completion {
	uint32_t txid;		/* the call, for cancellation */
	bool done, malformed;
	int error;
	int fd;
	uint64_t generation;
	uint8_t public_key[32];
	void *random;
	size_t random_size;
	struct cryptocmp_named_info info;
	struct cryptocmp_named_list_entry *entries;
	uint32_t cursor, max, count, next;
};

static bool
valid_name(const char *name, size_t length, size_t capacity)
{
	size_t i;

	if (name == NULL || length == 0 || length >= capacity)
		return (false);
	for (i = 0; i < length; i++) {
		if (!((name[i] >= 'a' && name[i] <= 'z') ||
		    (name[i] >= 'A' && name[i] <= 'Z') ||
		    (name[i] >= '0' && name[i] <= '9') ||
		    name[i] == '.' || name[i] == '_' ||
		    name[i] == '-'))
			return (false);
	}
	return (true);
}

static bool
valid_cstring_name(const char *name, size_t capacity)
{

	return (name != NULL &&
	    valid_name(name, strnlen(name, capacity), capacity));
}

static int
client_fail(struct cryptocmp_client *client, int error)
{

	if (client->connection != NULL) {
		fidl_bsd_connection_destroy(client->connection);
		client->connection = NULL;
	}
	client->terminal_error = error != 0 ? error : EIO;
	return (errno = client->terminal_error, -1);
}

static void
malformed(struct completion *result)
{

	result->malformed = true;
	result->error = EPROTO;
	if (result->fd >= 0) {
		(void)close(result->fd);
		result->fd = -1;
	}
}

/* Record an application error (a valid errno) or a malformed reply. */
static void
domain_error(struct completion *result, uint32_t error)
{

	if (error == 0 || error > ELAST)
		malformed(result);
	else
		result->error = (int)error;
}

static void
info_reply(void *context, int error, struct bsd_crypto_v1_ProtocolInfo *value)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (!error &&
	    (value == NULL || value->wire_version != CRYPTOCMP_WIRE_VERSION)) {
		result->malformed = true;
		result->error = EPROTONOSUPPORT;
	}
}

#define	RESULT_HEAD(method)                                                   \
	struct completion *result = context;                                  \
	result->done = true;                                                  \
	result->error = error;                                                \
	if (error)                                                            \
		return;                                                       \
	if (v == NULL) {                                                      \
		malformed(result);                                            \
		return;                                                       \
	}                                                                     \
	if (v->tag == bsd_crypto_v1_Crypto_##method##_Result_err_tag) {       \
		domain_error(result, v->value.err);                           \
		return;                                                       \
	}                                                                     \
	if (v->tag != bsd_crypto_v1_Crypto_##method##_Result_response_tag) {  \
		malformed(result);                                            \
		return;                                                       \
	}

static void
generate_reply(void *context, int error,
    struct bsd_crypto_v1_Crypto_Generate_Result *v)
{
	RESULT_HEAD(Generate)
	result->fd = fidl_bsd_take_fd(&v->value.response.descriptor);
	if (result->fd < 0)
		malformed(result);
}

static void
digest_reply(void *context, int error,
    struct bsd_crypto_v1_Crypto_Digest_Result *v)
{
	RESULT_HEAD(Digest)
	result->fd = fidl_bsd_take_fd(&v->value.response.descriptor);
	if (result->fd < 0)
		malformed(result);
}

static void
key_reply(void *context, int error,
    struct bsd_crypto_v1_Crypto_GenerateKey_Result *v)
{
	RESULT_HEAD(GenerateKey)
	result->fd = fidl_bsd_take_fd(&v->value.response.descriptor);
	if (result->fd < 0) {
		malformed(result);
		return;
	}
	memcpy(result->public_key, v->value.response.public_key,
	    sizeof(result->public_key));
}

#define	GENERATION_REPLY(name, method)                                        \
static void                                                                   \
name(void *context, int error,                                                \
    struct bsd_crypto_v1_Crypto_##method##_Result *v)                         \
{                                                                             \
	RESULT_HEAD(method)                                                   \
	if (v->value.response.generation == 0)                                \
		malformed(result);                                            \
	else                                                                  \
		result->generation = v->value.response.generation;            \
}
GENERATION_REPLY(create_reply, NamedCreate)
GENERATION_REPLY(rotate_reply, NamedRotate)
GENERATION_REPLY(delete_reply, NamedDelete)

static void
lease_reply(void *context, int error,
    struct bsd_crypto_v1_Crypto_NamedLease_Result *v)
{
	RESULT_HEAD(NamedLease)
	result->fd = fidl_bsd_take_fd(&v->value.response.descriptor);
	if (result->fd < 0 || v->value.response.generation == 0) {
		malformed(result);
		return;
	}
	result->generation = v->value.response.generation;
}

static void
random_reply(void *context, int error,
    struct bsd_crypto_v1_Crypto_Random_Result *v)
{
	RESULT_HEAD(Random)
	if (v->value.response.data_size != result->random_size) {
		explicit_bzero(v->value.response.data,
		    v->value.response.data_size);
		malformed(result);
		return;
	}
	memcpy(result->random, v->value.response.data,
	    v->value.response.data_size);
	explicit_bzero(v->value.response.data, v->value.response.data_size);
}

static void
stat_reply(void *context, int error,
    struct bsd_crypto_v1_Crypto_NamedStat_Result *v)
{
	const struct bsd_crypto_v1_NamedInfo *info;

	RESULT_HEAD(NamedStat)
	info = &v->value.response;
	if (info->generation == 0 || info->rights == 0 ||
	    (info->rights & ~CRYPTODESC_RIGHT_ALL) != 0) {
		malformed(result);
		return;
	}
	result->info.generation = info->generation;
	result->info.rights = info->rights;
	result->info.cipher = info->cipher;
	result->info.mac = info->mac;
	result->info.keylen = info->keylen;
	result->info.mackeylen = info->mackeylen;
}

static void
list_reply(void *context, int error,
    struct bsd_crypto_v1_Crypto_NamedList_Result *v)
{
	const struct bsd_crypto_v1_NamedPage *page;
	uint32_t count, i;

	RESULT_HEAD(NamedList)
	page = &v->value.response;
	if (page->entries_size > CRYPTOCMP_NAMED_LIST_MAX ||
	    (page->next_cursor != 0 &&
	    (page->entries_size == 0 || page->next_cursor <= result->cursor))) {
		malformed(result);
		return;
	}
	count = (uint32_t)page->entries_size;
	for (i = 0; i < count; i++) {
		const struct bsd_crypto_v1_NamedEntry *e = &page->entries[i];

		if (!valid_name(e->name, e->name_size,
		    sizeof(result->entries[0].name)) || e->generation == 0 ||
		    e->rights == 0 || (e->rights & ~CRYPTODESC_RIGHT_ALL) != 0) {
			malformed(result);
			return;
		}
	}
	result->count = count;
	result->next = page->next_cursor;
	if (count > result->max)
		return;		/* the caller reports ENOMEM */
	for (i = 0; i < count; i++) {
		const struct bsd_crypto_v1_NamedEntry *e = &page->entries[i];

		memset(&result->entries[i], 0, sizeof(result->entries[i]));
		memcpy(result->entries[i].name, e->name, e->name_size);
		result->entries[i].generation = e->generation;
		result->entries[i].rights = e->rights;
	}
}

/*
 * Wait for one completion.  Transport failures, timeouts and malformed
 * replies make the client terminal (closing any received descriptor);
 * application errors keep it.
 */
static int
finish_locked(struct cryptocmp_client *client, int error,
    struct completion *result, const struct timespec *deadline)
{

	if (error == 0) {
		error = fidl_bsd_sync_wait_txid(client->connection,
		    &result->done, deadline, result->txid);
		/* A timeout cancels just this call; the session survives. */
		if (error == ETIMEDOUT &&
		    fidl_bsd_connection_error(client->connection) == 0)
			return (errno = ETIMEDOUT, -1);
	}
	if (error == 0 && result->malformed)
		error = result->error;
	if (error != 0) {
		if (result->fd >= 0) {
			(void)close(result->fd);
			result->fd = -1;
		}
		return (client_fail(client, error));
	}
	if (result->error != 0)
		return (errno = result->error, -1);
	return (0);
}

/* Complete a call begun with begin(), releasing the client. */
static int
finish(struct cryptocmp_client *client, int error, struct completion *result,
    const struct timespec *deadline) __no_lock_analysis
{
	int rc, saved;

	rc = finish_locked(client, error, result, deadline);
	saved = errno;
	pthread_mutex_unlock(&client->lock);
	errno = saved;
	return (rc);
}

static int
begin(struct cryptocmp_client *client, struct timespec *deadline) __no_lock_analysis
{
	struct completion result = { .fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t timeout_ms = CRYPTOCMP_CALL_TIMEOUT_MS;
	int error;

	/* A caller's service_budget_begin(3) bounds the whole operation. */
	if (service_budget_timeout(&timeout_ms) == -1)
		return (-1);
	if ((error = fidl_bsd_sync_deadline(deadline, timeout_ms)) != 0)
		return (errno = error, -1);
	pthread_mutex_lock(&client->lock);
	if (client->terminal_error != 0) {
		error = client->terminal_error;
		pthread_mutex_unlock(&client->lock);
		return (errno = error, -1);
	}
	if (client->negotiated)
		return (0);
	error = bsd_crypto_v1_Crypto_GetProtocolInfo(client->connection,
	    &empty, info_reply, &result, &result.txid);
	if (finish_locked(client, error, &result, deadline) == -1) {
		error = errno;
		pthread_mutex_unlock(&client->lock);
		return (errno = error, -1);
	}
	client->negotiated = true;
	return (0);
}

static bool
usable(const struct cryptocmp_client *client)
{

	return (client != NULL && client->owner == getpid());
}

int
cryptocmp_client_create(int fd, struct cryptocmp_client **out)
{
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct cryptocmp_client *client;
	int error, owned;

	if (out == NULL)
		return (errno = EINVAL, -1);
	*out = NULL;
	if ((client = calloc(1, sizeof(*client))) == NULL)
		return (-1);
	/*
	 * Harden the session fd like the sibling *cmp clients: make it
	 * non-transferable and close-on-exec locked so the crypto channel
	 * cannot be passed to another process or leak across an exec.
	 */
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned < 0 || cap_xfer_limit(owned, CAP_XFER_NONE) == -1 ||
	    cap_cloexec_limit(owned, CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		if (owned >= 0)
			(void)close(owned);
		free(client);
		return (errno = error, -1);
	}
	options.max_pending_requests = 1;
	options.max_queued_messages = 2;
	options.max_queued_bytes = 4096;
	options.max_queued_fds = 0;
	error = fidl_bsd_connection_create_with_options(owned, FIDL_BSD_CLIENT,
	    &options, &client->connection);
	if (error != 0) {
		(void)close(owned);
		free(client);
		return (errno = error, -1);
	}
	(void)close(fd);
	pthread_mutex_init(&client->lock, NULL);
	client->owner = getpid();
	*out = client;
	return (0);
}

int
cryptocmp_open(struct cryptocmp_client **out)
{
	int error, fd;

	if (out == NULL)
		return (errno = EINVAL, -1);
	*out = NULL;
	if (service_open(CRYPTOCMP_INTERFACE, &fd) == -1)
		return (-1);
	if (cryptocmp_client_create(fd, out) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	return (0);
}

void
cryptocmp_close(struct cryptocmp_client *client)
{

	if (client == NULL)
		return;
	if (client->owner == getpid()) {
		if (client->connection != NULL)
			fidl_bsd_connection_destroy(client->connection);
		pthread_mutex_destroy(&client->lock);
	}
	free(client);
}

static void
generate_params(const struct cryptocmp_generate *in,
    struct bsd_crypto_v1_GenerateParams *out)
{

	out->cipher = in->cipher;
	out->mac = in->mac;
	out->keylen = in->keylen;
	out->mackeylen = in->mackeylen;
	out->rights = in->rights;
	out->ttl = in->ttl;
	out->flags = in->flags;
	out->crid = in->crid;
	out->ivlen = in->ivlen;
	out->maclen = in->maclen;
}

int
cryptocmp_generate(struct cryptocmp_client *client,
    const struct cryptocmp_generate *request, int *descriptor)
{
	struct completion result = { .fd = -1 };
	struct bsd_crypto_v1_GenerateParams params;
	struct timespec deadline;

	if (!usable(client) || request == NULL || descriptor == NULL)
		return (errno = EINVAL, -1);
	*descriptor = -1;
	generate_params(request, &params);
	if (begin(client, &deadline) == -1 ||
	    finish(client, bsd_crypto_v1_Crypto_Generate(client->connection,
	    &params, generate_reply, &result, &result.txid), &result, &deadline) == -1)
		return (-1);
	*descriptor = result.fd;
	return (0);
}

int
cryptocmp_generate_key(struct cryptocmp_client *client,
    const struct cryptocmp_key_generate *request, uint8_t public_key[32],
    int *descriptor)
{
	struct completion result = { .fd = -1 };
	struct bsd_crypto_v1_KeyParams params;
	struct timespec deadline;

	if (!usable(client) || request == NULL || public_key == NULL ||
	    descriptor == NULL)
		return (errno = EINVAL, -1);
	*descriptor = -1;
	memset(public_key, 0, 32);
	params.type = request->type;
	params.rights = request->rights;
	params.ttl = request->ttl;
	params.flags = request->flags;
	if (begin(client, &deadline) == -1 ||
	    finish(client, bsd_crypto_v1_Crypto_GenerateKey(client->connection,
	    &params, key_reply, &result, &result.txid), &result, &deadline) == -1)
		return (-1);
	memcpy(public_key, result.public_key, sizeof(result.public_key));
	*descriptor = result.fd;
	return (0);
}

int
cryptocmp_digest(struct cryptocmp_client *client, uint32_t alg, uint32_t ttl,
    uint32_t flags, int *descriptor)
{
	struct completion result = { .fd = -1 };
	struct bsd_crypto_v1_DigestParams params = { alg, ttl, flags };
	struct timespec deadline;

	if (!usable(client) || descriptor == NULL)
		return (errno = EINVAL, -1);
	*descriptor = -1;
	if (alg != CRYPTO_SHA2_256 && alg != CRYPTO_SHA2_384 &&
	    alg != CRYPTO_SHA2_512)
		return (errno = EINVAL, -1);
	if (begin(client, &deadline) == -1 ||
	    finish(client, bsd_crypto_v1_Crypto_Digest(client->connection,
	    &params, digest_reply, &result, &result.txid), &result, &deadline) == -1)
		return (-1);
	*descriptor = result.fd;
	return (0);
}

int
cryptocmp_random(struct cryptocmp_client *client, void *buf, size_t nbytes)
{
	struct completion result = { .fd = -1 };
	struct bsd_crypto_v1_RandomRequest params;
	struct timespec deadline;

	if (!usable(client) || buf == NULL || nbytes == 0 ||
	    nbytes > CRYPTOCMP_MAX_RANDOM_BYTES)
		return (errno = EINVAL, -1);
	memset(buf, 0, nbytes);
	params.nbytes = (uint32_t)nbytes;
	result.random = buf;
	result.random_size = nbytes;
	if (begin(client, &deadline) == -1 ||
	    finish(client, bsd_crypto_v1_Crypto_Random(client->connection,
	    &params, random_reply, &result, &result.txid), &result, &deadline) == -1) {
		explicit_bzero(buf, nbytes);
		return (-1);
	}
	return (0);
}

int
cryptocmp_named_create(struct cryptocmp_client *client, const char *name,
    const struct cryptocmp_generate *request, uint64_t *generation)
{
	struct completion result = { .fd = -1 };
	struct bsd_crypto_v1_NamedCreateRequest params;
	struct timespec deadline;

	if (!usable(client) || generation == NULL)
		return (errno = EINVAL, -1);
	*generation = 0;
	if (request == NULL ||
	    !valid_cstring_name(name, sizeof(((struct cryptocmp_named_create *)0)->name)))
		return (errno = EINVAL, -1);
	params.name = name;
	params.name_size = strlen(name);
	generate_params(request, &params.params);
	if (begin(client, &deadline) == -1 ||
	    finish(client, bsd_crypto_v1_Crypto_NamedCreate(client->connection,
	    &params, create_reply, &result, &result.txid), &result, &deadline) == -1)
		return (-1);
	*generation = result.generation;
	return (0);
}

int
cryptocmp_named_lease(struct cryptocmp_client *client, const char *name,
    uint32_t rights, uint32_t ttl, uint64_t *generation, int *descriptor)
{
	struct completion result = { .fd = -1 };
	struct bsd_crypto_v1_NamedLeaseRequest params;
	struct timespec deadline;

	if (!usable(client) || generation == NULL || descriptor == NULL)
		return (errno = EINVAL, -1);
	*generation = 0;
	*descriptor = -1;
	if (!valid_cstring_name(name,
	    sizeof(((struct cryptocmp_named_lease *)0)->name)))
		return (errno = EINVAL, -1);
	params.name = name;
	params.name_size = strlen(name);
	params.rights = rights;
	params.ttl = ttl;
	params.flags = 0;
	if (begin(client, &deadline) == -1 ||
	    finish(client, bsd_crypto_v1_Crypto_NamedLease(client->connection,
	    &params, lease_reply, &result, &result.txid), &result, &deadline) == -1)
		return (-1);
	*generation = result.generation;
	*descriptor = result.fd;
	return (0);
}

static int
cryptocmp_named_change(struct cryptocmp_client *client, bool rotate,
    const char *name, uint64_t *generation)
{
	struct completion result = { .fd = -1 };
	struct bsd_crypto_v1_NamedControlRequest params;
	struct timespec deadline;
	int error;

	if (!usable(client) || generation == NULL)
		return (errno = EINVAL, -1);
	*generation = 0;
	if (!valid_cstring_name(name,
	    sizeof(((struct cryptocmp_named_control *)0)->name)))
		return (errno = EINVAL, -1);
	params.name = name;
	params.name_size = strlen(name);
	params.flags = 0;
	if (begin(client, &deadline) == -1)
		return (-1);
	error = rotate ?
	    bsd_crypto_v1_Crypto_NamedRotate(client->connection, &params,
	    rotate_reply, &result, &result.txid) :
	    bsd_crypto_v1_Crypto_NamedDelete(client->connection, &params,
	    delete_reply, &result, &result.txid);
	if (finish(client, error, &result, &deadline) == -1)
		return (-1);
	*generation = result.generation;
	return (0);
}

int
cryptocmp_named_rotate(struct cryptocmp_client *client, const char *name,
    uint64_t *generation)
{

	return (cryptocmp_named_change(client, true, name, generation));
}

int
cryptocmp_named_delete(struct cryptocmp_client *client, const char *name,
    uint64_t *generation)
{

	return (cryptocmp_named_change(client, false, name, generation));
}

/*
 * Read-only named-key introspection: returns the key's metadata; no
 * descriptor is minted.  A nonexistent (or foreign-owner) key is ENOENT.
 */
int
cryptocmp_named_stat(struct cryptocmp_client *client, const char *name,
    struct cryptocmp_named_info *out)
{
	struct completion result = { .fd = -1 };
	struct bsd_crypto_v1_NamedControlRequest params;
	struct timespec deadline;

	if (!usable(client) || out == NULL ||
	    !valid_cstring_name(name,
	    sizeof(((struct cryptocmp_named_stat *)0)->name)))
		return (errno = EINVAL, -1);
	memset(out, 0, sizeof(*out));
	params.name = name;
	params.name_size = strlen(name);
	params.flags = 0;
	if (begin(client, &deadline) == -1 ||
	    finish(client, bsd_crypto_v1_Crypto_NamedStat(client->connection,
	    &params, stat_reply, &result, &result.txid), &result, &deadline) == -1)
		return (-1);
	*out = result.info;
	return (0);
}

/*
 * Owner-scoped enumeration of the caller's own named keys.  No owner is ever
 * sent on the wire -- the daemon scopes to the session's own label -- and no
 * descriptor is delivered.  Page by re-issuing with the returned next_cursor
 * until it is zero.
 */
int
cryptocmp_named_list(struct cryptocmp_client *client, uint32_t cursor,
    struct cryptocmp_named_list_entry *entries, uint32_t max, uint32_t *count,
    uint32_t *next_cursor)
{
	struct completion result = { .fd = -1 };
	struct bsd_crypto_v1_NamedListRequest params = { cursor, 0 };
	struct timespec deadline;

	if (!usable(client) || entries == NULL || max == 0 || count == NULL ||
	    next_cursor == NULL)
		return (errno = EINVAL, -1);
	*count = 0;
	*next_cursor = 0;
	memset(entries, 0, (size_t)MIN(max, CRYPTOCMP_NAMED_LIST_MAX) *
	    sizeof(*entries));
	result.entries = entries;
	result.cursor = cursor;
	result.max = max;
	if (begin(client, &deadline) == -1 ||
	    finish(client, bsd_crypto_v1_Crypto_NamedList(client->connection,
	    &params, list_reply, &result, &result.txid), &result, &deadline) == -1)
		return (-1);
	if (result.count > max) {
		*count = result.count;
		return (errno = ENOMEM, -1);
	}
	*count = result.count;
	*next_cursor = result.next;
	return (0);
}
