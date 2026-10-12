/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Client library for the system.Sysctl capability: read and (policy
 * permitting) write kernel sysctl variables by name through the provider,
 * instead of calling sysctl(3) directly or forking a Casper cap_sysctl helper.
 * Speaks FIDL bsd.sysctl.v1 (sysctlcmp.fidl) over a native capability channel.
 */

#include <sys/capsicum.h>
#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.sysctl.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <service_runtime.h>

#include "sysctlcmp.h"

#define	SYSCTLCMP_CALL_TIMEOUT_MS	5000

struct sysctlcmp_client {
	struct fidl_bsd_connection	*connection;
	pid_t				 owner;
	bool				 negotiated;
	int				 terminal_error;
	/*
	 * A client may be shared between threads; the connection has a single
	 * dispatch thread, so calls are serialized (begin() locks, finish()
	 * unlocks).
	 */
	pthread_mutex_t			 lock;
};

/* One call's result; value bytes are copied out in the callback. */
struct completion {
	uint32_t txid;		/* the call, for cancellation */
	bool done, malformed;
	int error;
	void *buf;		/* NULL: size query */
	size_t capacity, length;
	struct sysctlcmp_interface *interfaces;
	size_t count;
};

static int
client_fail(struct sysctlcmp_client *client, int error)
{

	if (client->connection != NULL) {
		fidl_bsd_connection_destroy(client->connection);
		client->connection = NULL;
	}
	client->terminal_error = error != 0 ? error : EIO;
	return (errno = client->terminal_error, -1);
}

/* client_fail() for a reply found malformed after its call completed. */
static int
client_fail_unlocked(struct sysctlcmp_client *client, int error)
{
	int rc;

	pthread_mutex_lock(&client->lock);
	rc = client_fail(client, error);
	pthread_mutex_unlock(&client->lock);
	return (errno = error, rc);
}

static void
malformed(struct completion *result)
{

	result->malformed = true;
	result->error = EPROTO;
}

static void
domain_error(struct completion *result, uint32_t error)
{

	if (error == 0 || error > ELAST)
		malformed(result);
	else
		result->error = (int)error;
}

static void
info_reply(void *context, int error, struct bsd_sysctl_v1_ProtocolInfo *value)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (!error &&
	    (value == NULL || value->wire_version != SYSCTLCMP_WIRE_VERSION)) {
		result->malformed = true;
		result->error = EPROTONOSUPPORT;
	}
}

/* Copy a value reply, or report the size the caller needs (ENOMEM). */
static void
take_value(struct completion *result, const struct bsd_sysctl_v1_Value *v)
{

	result->length = v->value_size;
	if (v->value_size > result->capacity) {
		result->error = ENOMEM;
		return;
	}
	if (v->value_size != 0)
		memcpy(result->buf, v->value, v->value_size);
}

#define VALUE_CALLBACK(method)                                               \
static void                                                                  \
method##_reply(void *context, int error,                                     \
    struct bsd_sysctl_v1_Sysctl_##method##_Result *v)                        \
{                                                                            \
	struct completion *result = context;                                 \
                                                                             \
	result->done = true;                                                 \
	result->error = error;                                               \
	if (error)                                                           \
		return;                                                      \
	if (v == NULL)                                                       \
		malformed(result);                                           \
	else if (v->tag == bsd_sysctl_v1_Sysctl_##method##_Result_err_tag)   \
		domain_error(result, v->value.err);                          \
	else if (v->tag ==                                                   \
	    bsd_sysctl_v1_Sysctl_##method##_Result_response_tag)             \
		take_value(result, &v->value.response);                      \
	else                                                                 \
		malformed(result);                                           \
}
VALUE_CALLBACK(Get)
VALUE_CALLBACK(OidFormat)
VALUE_CALLBACK(Describe)
VALUE_CALLBACK(Next)

static void
set_reply(void *context, int error, struct bsd_sysctl_v1_Sysctl_Set_Result *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL)
		malformed(result);
	else if (v->tag == bsd_sysctl_v1_Sysctl_Set_Result_err_tag)
		domain_error(result, v->value.err);
	else if (v->tag != bsd_sysctl_v1_Sysctl_Set_Result_response_tag)
		malformed(result);
}

/* Interfaces: sorted by index, non-empty unique names, known link states. */
static void
interfaces_reply(void *context, int error,
    struct bsd_sysctl_v1_Sysctl_ListInterfaces_Result *v)
{
	struct completion *result = context;
	const struct bsd_sysctl_v1_Interfaces *list;
	uint32_t last = 0;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL) {
		malformed(result);
		return;
	}
	if (v->tag == bsd_sysctl_v1_Sysctl_ListInterfaces_Result_err_tag) {
		domain_error(result, v->value.err);
		return;
	}
	if (v->tag != bsd_sysctl_v1_Sysctl_ListInterfaces_Result_response_tag) {
		malformed(result);
		return;
	}
	list = &v->value.response;
	for (size_t i = 0; i < list->interfaces_size; i++) {
		const struct bsd_sysctl_v1_Interface *e = &list->interfaces[i];

		if (e->index <= last || e->link_state > SYSCTLCMP_LINK_UP ||
		    e->name_size == 0 ||
		    e->name_size >= SYSCTLCMP_IFNAME_SIZE ||
		    memchr(e->name, '\0', e->name_size) != NULL) {
			malformed(result);
			return;
		}
		for (size_t j = 0; j < i; j++)
			if (list->interfaces[j].name_size == e->name_size &&
			    memcmp(list->interfaces[j].name, e->name,
			    e->name_size) == 0) {
				malformed(result);
				return;
			}
		last = e->index;
	}
	result->count = list->interfaces_size;
	if (result->interfaces == NULL)
		return;
	for (size_t i = 0; i < list->interfaces_size; i++) {
		const struct bsd_sysctl_v1_Interface *e = &list->interfaces[i];
		struct sysctlcmp_interface *out = &result->interfaces[i];

		memset(out, 0, sizeof(*out));
		out->index = e->index;
		out->flags = e->flags;
		out->mtu = e->mtu;
		out->link_state = e->link_state;
		memcpy(out->name, e->name, e->name_size);
	}
}

/*
 * Wait for one completion.  Transport failures, timeouts and malformed
 * replies make the client terminal; application errors (including the ENOMEM
 * size report) keep it.
 */
static int
finish_locked(struct sysctlcmp_client *client, int error,
    struct completion *result, const struct timespec *deadline)
{

	if (error == 0)
		error = fidl_bsd_sync_wait(client->connection, &result->done,
		    deadline);
	if (error != 0)
		return (client_fail(client, error));
	if (result->malformed)
		return (client_fail(client, result->error));
	/* A call failed by the transport (the peer closed) ends the session. */
	if (result->error != 0 &&
	    fidl_bsd_connection_error(client->connection) != 0)
		return (client_fail(client, result->error));
	if (result->error != 0)
		return (errno = result->error, -1);
	return (0);
}

/* Complete a call begun with begin(), releasing the client. */
static int
finish(struct sysctlcmp_client *client, int error, struct completion *result,
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
begin(struct sysctlcmp_client *client, struct timespec *deadline) __no_lock_analysis
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t timeout_ms = SYSCTLCMP_CALL_TIMEOUT_MS;
	int error;

	if (client == NULL)
		return (errno = EINVAL, -1);
	if (client->owner != getpid())
		return (errno = ECHILD, -1);
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
	error = bsd_sysctl_v1_Sysctl_GetProtocolInfo(client->connection,
	    &empty, info_reply, &result, &result.txid);
	if (finish_locked(client, error, &result, deadline) == -1) {
		error = errno;
		pthread_mutex_unlock(&client->lock);
		return (errno = error, -1);
	}
	client->negotiated = true;
	return (0);
}

/* A request name: at most SYSCTLCMP_MAX_NAME - 1 bytes. */
static int
request_name(const char *name, struct bsd_sysctl_v1_NameRequest *request)
{
	size_t length;

	if (name == NULL)
		return (errno = EINVAL, -1);
	length = strnlen(name, SYSCTLCMP_MAX_NAME);
	if (length >= SYSCTLCMP_MAX_NAME)
		return (errno = EINVAL, -1);
	request->name = name;
	request->name_size = length;
	return (0);
}

enum read_op { READ_GET, READ_OIDFMT, READ_DESCR, READ_NEXT };

/* Shared read-side op: send a name-only request and copy the value reply. */
static int
read_value_op(struct sysctlcmp_client *client, enum read_op op,
    const char *name, void *buf, size_t *lenp)
{
	struct bsd_sysctl_v1_NameRequest request;
	struct completion result = { 0 };
	struct timespec deadline;
	int error;

	if (client == NULL || lenp == NULL || (buf == NULL && *lenp != 0))
		return (errno = EINVAL, -1);
	if (request_name(name, &request) == -1)
		return (-1);
	if (op != READ_NEXT && request.name_size == 0)
		return (errno = EINVAL, -1);
	if (begin(client, &deadline) == -1)
		return (-1);
	result.buf = buf;
	result.capacity = *lenp;
	switch (op) {
	case READ_GET:
		error = bsd_sysctl_v1_Sysctl_Get(client->connection, &request,
		    Get_reply, &result, &result.txid);
		break;
	case READ_OIDFMT:
		error = bsd_sysctl_v1_Sysctl_OidFormat(client->connection,
		    &request, OidFormat_reply, &result, &result.txid);
		break;
	case READ_DESCR:
		error = bsd_sysctl_v1_Sysctl_Describe(client->connection,
		    &request, Describe_reply, &result, &result.txid);
		break;
	default:
		error = bsd_sysctl_v1_Sysctl_Next(client->connection, &request,
		    Next_reply, &result, &result.txid);
		break;
	}
	if (finish(client, error, &result, &deadline) == -1) {
		if (errno == ENOMEM && result.length > *lenp)
			*lenp = result.length;
		return (-1);
	}
	*lenp = result.length;
	return (0);
}

int
sysctlcmp_get(struct sysctlcmp_client *client, const char *name, void *buf,
    size_t *lenp)
{

	return (read_value_op(client, READ_GET, name, buf, lenp));
}

int
sysctlcmp_interfaces(struct sysctlcmp_client *client,
    struct sysctlcmp_interface *out, size_t *count)
{
	struct sysctlcmp_interface entries[SYSCTLCMP_MAX_INTERFACES];
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;

	if (count == NULL || (out == NULL && *count != 0))
		return (errno = EINVAL, -1);
	if (begin(client, &deadline) == -1)
		return (-1);
	result.interfaces = entries;
	if (finish(client, bsd_sysctl_v1_Sysctl_ListInterfaces(
	    client->connection, &empty, interfaces_reply, &result, &result.txid),
	    &result, &deadline) == -1)
		return (-1);
	if (out != NULL && *count < result.count) {
		*count = result.count;
		return (errno = ENOMEM, -1);
	}
	if (out != NULL)
		memcpy(out, entries, result.count * sizeof(*entries));
	*count = result.count;
	return (0);
}

int
sysctlcmp_describe(struct sysctlcmp_client *client, const char *name,
    char *buf, size_t *lenp)
{

	if (read_value_op(client, READ_DESCR, name, buf, lenp) == -1)
		return (-1);
	if (*lenp == 0 || buf[*lenp - 1] != '\0')
		return (client_fail_unlocked(client, EPROTO));
	return (0);
}

int
sysctlcmp_next(struct sysctlcmp_client *client, const char *name,
    char *buf, size_t *lenp)
{

	/* An empty name starts enumeration from the root. */
	if (read_value_op(client, READ_NEXT, name != NULL ? name : "", buf,
	    lenp) == -1)
		return (-1);
	if (*lenp == 0 || buf[*lenp - 1] != '\0')
		return (client_fail_unlocked(client, EPROTO));
	return (0);
}

int
sysctlcmp_oidfmt(struct sysctlcmp_client *client, const char *name,
    unsigned int *kindp, char *fmt, size_t *fmtlenp)
{
	uint8_t raw[sizeof(struct sysctlcmp_oidfmt) + SYSCTLCMP_MAX_NAME];
	const struct sysctlcmp_oidfmt *of;
	size_t rawlen, fmtlen;

	if (kindp == NULL || fmtlenp == NULL ||
	    (fmt == NULL && *fmtlenp != 0)) {
		errno = EINVAL;
		return (-1);
	}
	rawlen = sizeof(raw);
	if (read_value_op(client, READ_OIDFMT, name, raw, &rawlen) == -1)
		return (-1);
	if (rawlen < sizeof(*of))
		return (client_fail_unlocked(client, EPROTO));
	of = (const void *)raw;
	fmtlen = rawlen - sizeof(*of);		/* includes trailing NUL */
	if (fmtlen == 0 || of->fmt[fmtlen - 1] != '\0')
		return (client_fail_unlocked(client, EPROTO));
	if (fmtlen > *fmtlenp) {
		*fmtlenp = fmtlen;
		errno = ENOMEM;
		return (-1);
	}
	*kindp = of->kind;
	memcpy(fmt, of->fmt, fmtlen);
	*fmtlenp = fmtlen;
	return (0);
}

int
sysctlcmp_set(struct sysctlcmp_client *client, const char *name,
    const void *value, size_t len)
{
	struct bsd_sysctl_v1_NameRequest named;
	struct bsd_sysctl_v1_SetRequest request;
	struct completion result = { 0 };
	struct timespec deadline;

	if (client == NULL || (value == NULL && len != 0) ||
	    len > SYSCTLCMP_MAX_VALUE)
		return (errno = EINVAL, -1);
	if (request_name(name, &named) == -1)
		return (-1);
	if (named.name_size == 0)
		return (errno = EINVAL, -1);
	if (begin(client, &deadline) == -1)
		return (-1);
	request.name = named.name;
	request.name_size = named.name_size;
	request.value = __DECONST(uint8_t *, value);
	request.value_size = len;
	return (finish(client, bsd_sysctl_v1_Sysctl_Set(client->connection,
	    &request, set_reply, &result, &result.txid), &result, &deadline));
}

int
sysctlcmp_client_create(int fd, struct sysctlcmp_client **clientp)
{
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct sysctlcmp_client *client;
	int error, owned;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (-1);
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned < 0 || cap_xfer_limit(owned, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(owned, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(owned, CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		if (owned >= 0)
			(void)close(owned);
		free(client);
		return (errno = error, -1);
	}
	options.max_pending_requests = 1;
	options.max_queued_messages = 2;
	options.max_queued_bytes = 16 * 1024;
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
	*clientp = client;
	return (0);
}

int
sysctlcmp_client_open(struct sysctlcmp_client **clientp)
{
	int error, fd;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	fd = -1;
	if (service_open(SYSCTLCMP_INTERFACE, &fd) == -1)
		return (-1);
	if (sysctlcmp_client_create(fd, clientp) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	return (0);
}

void
sysctlcmp_client_close(struct sysctlcmp_client *client)
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
