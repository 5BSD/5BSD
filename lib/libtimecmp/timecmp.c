/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 *
 * C application API for system.Time, using generated bsd.time.v1 bindings.
 */
#include <sys/capsicum.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.time.v1/c/bsd.h>
#include <libservice.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "timecmp.h"
#include "diagnostics.h"

struct timecmp_client {
	struct fidl_bsd_connection *connection;
	pid_t owner;
	bool negotiated;
};
struct completion {
	bool done, malformed;
	int error;
	struct timespec time;
	struct timeval delta;
};
static int
failure(int error)
{
	errno = error;
	return (-1);
}
static void
bad_reply(struct completion *result)
{
	TIMECMP_TRACE_REPLY_MALFORMED(EPROTO);
	result->malformed = true;
	result->error = EPROTO;
}
static void
domain_error(struct completion *result, uint32_t error)
{
	if (error == 0 || error > ELAST)
		bad_reply(result);
	else
		result->error = (int)error;
}
static void
info_reply(void *context, int error, struct bsd_time_v1_ProtocolInfo *value)
{
	struct completion *result = context;
	result->done = true;
	result->error = error;
	if (!error &&
	    (value == NULL || value->wire_version != TIMECMP_WIRE_VERSION)) {
		result->malformed = true;
		TIMECMP_TRACE_REPLY_MALFORMED(EPROTONOSUPPORT);
		result->error = EPROTONOSUPPORT;
	}
}
static void
get_reply(void *context, int error, struct bsd_time_v1_Time_Get_Result *value)
{
	struct completion *result = context;
	result->done = true;
	result->error = error;
	if (error)
		return;
	if (value == NULL) {
		bad_reply(result);
		return;
	}
	if (value->tag == bsd_time_v1_Time_Get_Result_err_tag) {
		domain_error(result, value->value.err);
		return;
	}
	if (value->tag != bsd_time_v1_Time_Get_Result_response_tag ||
	    value->value.response.nanoseconds < 0 ||
	    value->value.response.nanoseconds > 999999999 ||
	    (int64_t)(time_t)value->value.response.seconds !=
		value->value.response.seconds) {
		bad_reply(result);
		return;
	}
	result->time.tv_sec = (time_t)value->value.response.seconds;
	result->time.tv_nsec = value->value.response.nanoseconds;
}
static void
set_reply(void *context, int error, struct bsd_time_v1_Time_Set_Result *value)
{
	struct completion *result = context;
	result->done = true;
	result->error = error;
	if (error)
		return;
	if (value == NULL)
		bad_reply(result);
	else if (value->tag == bsd_time_v1_Time_Set_Result_err_tag)
		domain_error(result, value->value.err);
	else if (value->tag != bsd_time_v1_Time_Set_Result_response_tag)
		bad_reply(result);
}
static void
adjust_reply(void *context, int error,
    struct bsd_time_v1_Time_Adjust_Result *value)
{
	struct completion *result = context;
	result->done = true;
	result->error = error;
	if (error)
		return;
	if (value == NULL) {
		bad_reply(result);
		return;
	}
	if (value->tag == bsd_time_v1_Time_Adjust_Result_err_tag) {
		domain_error(result, value->value.err);
		return;
	}
	if (value->tag != bsd_time_v1_Time_Adjust_Result_response_tag ||
	    value->value.response.microseconds < -999999 ||
	    value->value.response.microseconds > 999999 ||
	    (int64_t)(time_t)value->value.response.seconds !=
		value->value.response.seconds) {
		bad_reply(result);
		return;
	}
	result->delta.tv_sec = (time_t)value->value.response.seconds;
	result->delta.tv_usec = value->value.response.microseconds;
}
#ifdef WITH_DTRACE
#define await_impl_name await_trace_impl
#else
#define await_impl_name await
#endif
static int
await_impl_name(struct timecmp_client *client, struct completion *result,
    const struct timespec *deadline)
{
	while (!result->done) {
		struct timespec now;
		int error;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			error = errno;
			fidl_bsd_connection_close(client->connection, error);
			return (failure(error));
		}
		int64_t milliseconds = (deadline->tv_sec - now.tv_sec) *
			INT64_C(1000) +
		    (deadline->tv_nsec - now.tv_nsec) / 1000000;
		if (milliseconds <= 0) {
			// Closing completes pending callbacks before their
			// stack context expires.
			fidl_bsd_connection_close(client->connection,
			    ETIMEDOUT);
			return (failure(ETIMEDOUT));
		}
		error = fidl_bsd_connection_poll(client->connection,
		    milliseconds > INT_MAX ? INT_MAX : (int)milliseconds);
		if (error && !result->done) {
			fidl_bsd_connection_close(client->connection, error);
			return (failure(error));
		}
	}
	if (result->malformed)
		fidl_bsd_connection_close(client->connection, result->error);
	return (result->error ? failure(result->error) : 0);
}

#ifdef WITH_DTRACE
static int
await(struct timecmp_client *client, struct completion *completion,
    const struct timespec *deadline)
{
	int result;

	TIMECMP_TRACE_WAIT_START((uintptr_t)client);
	result = await_trace_impl(client, completion, deadline);
	TIMECMP_TRACE_WAIT_DONE((uintptr_t)client,
	    result == -1 ? errno : 0, completion->malformed);
	return (result);
}
#endif
#undef await_impl_name
static int
begin(struct timecmp_client *client, struct timespec *deadline)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t txid;
	int error;
	if (client == NULL)
		return (failure(EINVAL));
	if (client->owner != getpid())
		return (failure(ECHILD));
	if ((error = fidl_bsd_connection_error(client->connection)) != 0)
		return (failure(error));
	if (clock_gettime(CLOCK_MONOTONIC, deadline) == -1)
		return (-1);
	deadline->tv_sec += 5;
	if (!client->negotiated) {
		error = bsd_time_v1_Time_GetProtocolInfo(client->connection,
		    &empty, info_reply, &result, &txid);
		if (error)
			return (failure(error));
		if (await(client, &result, deadline) == -1)
			return (-1);
		client->negotiated = true;
	}
	return (0);
}
int
timecmp_client_create(int fd, struct timecmp_client **clientp)
{
	struct timecmp_client *client;
	int error, owned;
	if (clientp == NULL)
		return (failure(EINVAL));
	*clientp = NULL;
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (-1);
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned < 0 || cap_xfer_limit(owned, CAP_XFER_NONE) == -1) {
		error = errno;
		if (owned >= 0)
			close(owned);
		free(client);
		return (failure(error));
	}
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	options.max_pending_requests = 1;
	options.max_queued_messages = 2;
	options.max_queued_bytes = 1024;
	options.max_queued_fds = 0;
	error = fidl_bsd_connection_create_with_options(owned, FIDL_BSD_CLIENT,
	    &options, &client->connection);
	if (error) {
		close(owned);
		free(client);
		return (failure(error));
	}
	close(fd);
	client->owner = getpid();
	*clientp = client;
	return (0);
}
int
timecmp_client_open(struct timecmp_client **clientp)
{
	int fd, error;
	if (clientp == NULL)
		return (failure(EINVAL));
	*clientp = NULL;
	if (service_open(TIMECMP_INTERFACE, &fd) == -1)
		return (-1);
	if (timecmp_client_create(fd, clientp) == -1) {
		error = errno;
		close(fd);
		return (failure(error));
	}
	return (0);
}
void
timecmp_client_close(struct timecmp_client *client)
{
	if (client == NULL)
		return;
	// Locked close-on-fork descriptors may have been reused in the child.
	if (client->owner == getpid())
		fidl_bsd_connection_destroy(client->connection);
	free(client);
}
int
timecmp_get(struct timecmp_client *client, struct timespec *ts)
{
	struct completion result = { 0 };
	struct timespec deadline;
	struct fidl_bsd_empty empty = { 0 };
	uint32_t txid;
	int error;
	if (ts == NULL)
		return (failure(EINVAL));
	if (begin(client, &deadline) == -1)
		return (-1);
	error = bsd_time_v1_Time_Get(client->connection, &empty, get_reply,
	    &result, &txid);
	if (error)
		return (failure(error));
	if (await(client, &result, &deadline) == -1)
		return (-1);
	*ts = result.time;
	return (0);
}
int
timecmp_set(struct timecmp_client *client, const struct timespec *ts)
{
	struct completion result = { 0 };
	struct timespec deadline;
	uint32_t txid;
	int error;
	if (ts == NULL || ts->tv_nsec < 0 || ts->tv_nsec > 999999999)
		return (failure(EINVAL));
	if (begin(client, &deadline) == -1)
		return (-1);
	struct bsd_time_v1_Timestamp value = { ts->tv_sec,
		(int32_t)ts->tv_nsec };
	error = bsd_time_v1_Time_Set(client->connection, &value, set_reply,
	    &result, &txid);
	return (error ? failure(error) : await(client, &result, &deadline));
}
int
timecmp_adjust(struct timecmp_client *client, const struct timeval *delta,
    struct timeval *old)
{
	struct completion result = { 0 };
	struct timespec deadline;
	uint32_t txid;
	int error;
	if (delta == NULL || delta->tv_usec < -999999 ||
	    delta->tv_usec > 999999)
		return (failure(EINVAL));
	if (begin(client, &deadline) == -1)
		return (-1);
	struct bsd_time_v1_Delta value = { delta->tv_sec,
		(int32_t)delta->tv_usec };
	error = bsd_time_v1_Time_Adjust(client->connection, &value,
	    adjust_reply, &result, &txid);
	if (error)
		return (failure(error));
	if (await(client, &result, &deadline) == -1)
		return (-1);
	if (old != NULL)
		*old = result.delta;
	return (0);
}
