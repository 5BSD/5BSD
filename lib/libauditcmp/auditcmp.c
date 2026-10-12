/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * system.Audit client, using the generated bsd.audit.v1 bindings
 * (auditcmp.fidl) over a native capability channel.
 */

#include <sys/capsicum.h>
#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fidl/bsd.audit.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <libservice.h>
#include <service_runtime.h>

#include "auditcmp.h"
#include "auditcmp_server.h"

#define	AUDITCMP_CALL_TIMEOUT_MS	5000

struct auditcmp_client {
	struct fidl_bsd_connection	*connection;
	pid_t				 owner;
	bool				 negotiated;
	int				 terminal_error;
	/*
	 * Callers may share one client between threads; the connection has a
	 * single dispatch thread, so calls are serialized (begin() locks,
	 * finish() unlocks).
	 */
	pthread_mutex_t			 lock;
};

int
auditcmp_client_prepare(int *fdp)
{
	int error, fd;

	if (fdp == NULL)
		return (errno = EINVAL, -1);
	*fdp = -1;
	fd = -1;
	error = service_open(AUDITCMP_INTERFACE, &fd) == -1 ? errno : 0;
	if (error == 0 &&
	    (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1))
		error = errno;
	if (error != 0) {
		if (fd >= 0)
			close(fd);
		errno = error;
		return (-1);
	}
	*fdp = fd;
	return (0);
}

struct completion {
	uint32_t txid;		/* the call, for cancellation */
	bool done, malformed;
	int error;
	struct auditcmp_stats stats;
};

static int
client_fail(struct auditcmp_client *client, int error)
{

	if (client->connection != NULL) {
		fidl_bsd_connection_destroy(client->connection);
		client->connection = NULL;
	}
	client->terminal_error = error != 0 ? error : EIO;
	return (errno = client->terminal_error, -1);
}

static void
info_reply(void *context, int error, struct bsd_audit_v1_ProtocolInfo *value)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (!error &&
	    (value == NULL || value->wire_version != AUDITCMP_WIRE_VERSION)) {
		result->malformed = true;
		result->error = EPROTONOSUPPORT;
	}
}

static void
submit_reply(void *context, int error,
    struct bsd_audit_v1_Audit_Submit_Result *value)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (value != NULL &&
	    value->tag == bsd_audit_v1_Audit_Submit_Result_response_tag)
		return;
	if (value != NULL &&
	    value->tag == bsd_audit_v1_Audit_Submit_Result_err_tag &&
	    value->value.err != 0 && value->value.err <= ELAST) {
		result->error = (int)value->value.err;
		return;
	}
	result->malformed = true;
	result->error = EPROTO;
}

static void
stats_reply(void *context, int error, struct bsd_audit_v1_AuditStats *value)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (value == NULL) {
		result->malformed = true;
		result->error = EPROTO;
		return;
	}
	memset(&result->stats, 0, sizeof(result->stats));
	result->stats.submitted = value->submitted;
	result->stats.rejected = value->rejected;
}

/*
 * Wait for one completion.  Transport failures, timeouts and malformed
 * replies make the client terminal; application errors keep it.
 */
static int
finish_locked(struct auditcmp_client *client, int error,
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
	/* A call failed by the transport (the peer closed) ends the session. */
	if (error == 0 && result->error != 0 &&
	    fidl_bsd_connection_error(client->connection) != 0)
		error = result->error;
	if (error != 0)
		return (client_fail(client, error));
	if (result->error != 0)
		return (errno = result->error, -1);
	return (0);
}

/* Complete a call begun with begin(), releasing the client. */
static int
finish(struct auditcmp_client *client, int error, struct completion *result,
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
begin(struct auditcmp_client *client, struct timespec *deadline) __no_lock_analysis
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t timeout_ms = AUDITCMP_CALL_TIMEOUT_MS;
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
	error = bsd_audit_v1_Audit_GetProtocolInfo(client->connection, &empty,
	    info_reply, &result, &result.txid);
	if (finish_locked(client, error, &result, deadline) == -1) {
		error = errno;
		pthread_mutex_unlock(&client->lock);
		return (errno = error, -1);
	}
	client->negotiated = true;
	return (0);
}

int
auditcmp_client_adopt(int fd, struct auditcmp_client **clientp)
{
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct auditcmp_client *client;
	int error, owned;

	if (fd < 0 || clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	error = owned == -1 ? errno : 0;
	(void)close(fd);
	if (error != 0)
		return (errno = error, -1);
	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		close(owned);
		return (-1);
	}
	options.max_pending_requests = 1;
	options.max_queued_messages = 2;
	options.max_queued_bytes = 1024;
	options.max_queued_fds = 0;
	error = fidl_bsd_connection_create_with_options(owned, FIDL_BSD_CLIENT,
	    &options, &client->connection);
	if (error != 0) {
		close(owned);
		free(client);
		return (errno = error, -1);
	}
	pthread_mutex_init(&client->lock, NULL);
	client->owner = getpid();
	*clientp = client;
	return (0);
}

int
auditcmp_client_open(struct auditcmp_client **clientp)
{
	int fd;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	if (auditcmp_client_prepare(&fd) == -1)
		return (-1);
	if (auditcmp_client_adopt(fd, clientp) == -1)
		return (-1);
	return (0);
}

void
auditcmp_client_close(struct auditcmp_client *client)
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

int
auditcmp_submit(struct auditcmp_client *client, const char *subject,
    const char *operation, int error)
{
	struct {
		struct auditcmp_msg msg;
		struct auditcmp_submit_request submit;
	} record;
	struct bsd_audit_v1_SubmitRequest request;
	struct completion result = { 0 };
	struct timespec deadline;
	size_t subject_length, operation_length;

	if (client == NULL || subject == NULL || operation == NULL ||
	    error < 0 || error > ELAST)
		return (errno = EINVAL, -1);
	subject_length = strnlen(subject, AUDITCMP_MAX_SUBJECT + 1);
	operation_length = strnlen(operation, AUDITCMP_MAX_OPERATION + 1);
	if (subject_length == 0 || subject_length > AUDITCMP_MAX_SUBJECT ||
	    operation_length == 0 ||
	    operation_length > AUDITCMP_MAX_OPERATION)
		return (errno = EINVAL, -1);
	/* The provider applies the same record rules; check them first. */
	memset(&record, 0, sizeof(record));
	(void)auditcmp_message_init(&record.msg, AUDITCMP_OP_SUBMIT, 0);
	record.submit.error = error;
	record.submit.subject_length = subject_length;
	record.submit.operation_length = operation_length;
	memcpy(record.submit.subject, subject, subject_length);
	memcpy(record.submit.operation, operation, operation_length);
	if (auditcmp_validate_message(&record.msg, sizeof(record),
	    AUDITCMP_MESSAGE_REQUEST) == -1)
		return (errno = EINVAL, -1);
	if (begin(client, &deadline) == -1)
		return (-1);
	request.error = error;
	request.subject = subject;
	request.subject_size = subject_length;
	request.operation = operation;
	request.operation_size = operation_length;
	return (finish(client, bsd_audit_v1_Audit_Submit(client->connection,
	    &request, submit_reply, &result, &result.txid), &result, &deadline));
}

int
auditcmp_stats(struct auditcmp_client *client, struct auditcmp_stats *stats)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;

	if (stats == NULL)
		return (errno = EINVAL, -1);
	if (begin(client, &deadline) == -1)
		return (-1);
	if (finish(client, bsd_audit_v1_Audit_Stats(client->connection, &empty,
	    stats_reply, &result, &result.txid), &result, &deadline) == -1)
		return (-1);
	*stats = result.stats;
	return (0);
}
