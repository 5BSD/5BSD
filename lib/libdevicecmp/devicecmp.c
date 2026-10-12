/*- SPDX-License-Identifier: BSD-2-Clause */
/*
 * system.Device client: open a named /dev leaf and receive a Capsicum-narrowed
 * descriptor, using the generated bsd.device.v1 bindings (devicecmp.fidl).
 * The provider session is opened by name once and cached for the process,
 * guarded by a mutex (the connection has a single dispatch thread) and
 * re-created after a fork.  A transport failure, timeout or malformed reply
 * drops exactly that session; application errors keep it.
 */
#include <sys/types.h>

#include <errno.h>
#include <fidl/bsd.device.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <service_runtime.h>

#include "devicecmp.h"

#define	DEVICECMP_CALL_TIMEOUT_MS	30000

static pthread_mutex_t devicecmp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct fidl_bsd_connection *devicecmp_connection;
static pid_t devicecmp_owner;
static bool devicecmp_negotiated;

struct completion {
	bool done, malformed;
	int error;
	uint32_t want;				/* Open: requested rights */
	uint32_t cursor;			/* List: request cursor */
	uint32_t granted;
	int fd;
	struct devicecmp_list_entry *entries;
	uint32_t max, count, next;
};

static bool
valid_leaf(const char *name, size_t length)
{

	return (name != NULL && length != 0 && length < DEVICECMP_MAX_NAME &&
	    name[0] != '.' && memchr(name, '/', length) == NULL &&
	    memchr(name, '\0', length) == NULL);
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
info_reply(void *context, int error, struct bsd_device_v1_ProtocolInfo *value)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (!error &&
	    (value == NULL || value->wire_version != DEVICECMP_WIRE_VERSION)) {
		result->malformed = true;
		result->error = EPROTONOSUPPORT;
	}
}

static void
open_reply(void *context, int error, struct bsd_device_v1_Device_Open_Result *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL)
		malformed(result);
	else if (v->tag == bsd_device_v1_Device_Open_Result_err_tag)
		domain_error(result, v->value.err);
	else if (v->tag != bsd_device_v1_Device_Open_Result_response_tag)
		malformed(result);
	else {
		/* Retain the descriptor first so a bad reply cannot leak it. */
		int fd = fidl_bsd_take_fd(&v->value.response.device);
		uint32_t rights = v->value.response.rights;

		if (fd < 0 || rights == 0 ||
		    (rights & ~DEVICECMP_RIGHT_ALL) != 0 ||
		    (rights & ~result->want) != 0) {
			if (fd >= 0)
				(void)close(fd);
			malformed(result);
			return;
		}
		result->fd = fd;
		result->granted = rights;
	}
}

static void
list_reply(void *context, int error, struct bsd_device_v1_Device_List_Result *v)
{
	struct completion *result = context;
	const struct bsd_device_v1_DevicePage *page;
	uint32_t count, i;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL) {
		malformed(result);
		return;
	}
	if (v->tag == bsd_device_v1_Device_List_Result_err_tag) {
		domain_error(result, v->value.err);
		return;
	}
	if (v->tag != bsd_device_v1_Device_List_Result_response_tag) {
		malformed(result);
		return;
	}
	page = &v->value.response;
	if (page->entries_size > DEVICECMP_LIST_MAX ||
	    (page->next_cursor != 0 &&
	    (page->entries_size == 0 || page->next_cursor <= result->cursor))) {
		malformed(result);
		return;
	}
	count = (uint32_t)page->entries_size;
	for (i = 0; i < count; i++) {
		const struct bsd_device_v1_DeviceEntry *entry = &page->entries[i];

		if (!valid_leaf(entry->name, entry->name_size) ||
		    entry->rights == 0 ||
		    (entry->rights & ~DEVICECMP_RIGHT_ALL) != 0 ||
		    (entry->flags & ~DEVICECMP_LIST_FLAG_IOCTL_WHITELIST) != 0 ||
		    ((entry->flags & DEVICECMP_LIST_FLAG_IOCTL_WHITELIST) != 0 &&
		    (entry->rights & DEVICECMP_RIGHT_IOCTL) == 0)) {
			malformed(result);
			return;
		}
	}
	result->count = count;
	result->next = page->next_cursor;
	if (count > result->max)
		return;		/* the caller reports ENOMEM */
	for (i = 0; i < count; i++) {
		const struct bsd_device_v1_DeviceEntry *entry = &page->entries[i];

		memset(&result->entries[i], 0, sizeof(result->entries[i]));
		memcpy(result->entries[i].name, entry->name, entry->name_size);
		result->entries[i].rights = entry->rights;
		result->entries[i].flags = entry->flags;
	}
}

/* Drop the cached session.  Caller holds devicecmp_lock. */
static void
session_drop(void)
{

	if (devicecmp_connection != NULL && devicecmp_owner == getpid())
		fidl_bsd_connection_destroy(devicecmp_connection);
	devicecmp_connection = NULL;
	devicecmp_owner = 0;
	devicecmp_negotiated = false;
}

/*
 * Return the cached provider session, opening one on first use (or after a
 * fork that orphaned the inherited session).  Caller holds devicecmp_lock.
 */
static int
session_get(void)
{
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	int error, fd;

	if (devicecmp_connection != NULL && devicecmp_owner == getpid())
		return (0);
	/* Inherited across fork: the parent's connection is not ours. */
	devicecmp_connection = NULL;
	devicecmp_negotiated = false;
	if (service_open(DEVICECMP_INTERFACE, &fd) == -1)
		return (-1);
	options.max_pending_requests = 1;
	options.max_queued_messages = 2;
	options.max_queued_bytes = 2048;
	options.max_queued_fds = 0;
	error = fidl_bsd_connection_create_with_options(fd, FIDL_BSD_CLIENT,
	    &options, &devicecmp_connection);
	if (error != 0) {
		devicecmp_connection = NULL;
		(void)close(fd);
		return (errno = error, -1);
	}
	devicecmp_owner = getpid();
	return (0);
}

/*
 * Wait for one completion with the lock held.  Transport failures, timeouts
 * and malformed replies drop the session; application errors keep it.
 */
static int
finish_locked(int error, struct completion *result,
    const struct timespec *deadline)
{

	if (error == 0)
		error = fidl_bsd_sync_wait(devicecmp_connection, &result->done,
		    deadline);
	if (error == 0 && result->malformed)
		error = result->error;
	/* A reply failed by the transport (the peer closed) is not an
	 * application error: the session is gone. */
	if (error == 0 && result->error != 0 &&
	    fidl_bsd_connection_error(devicecmp_connection) != 0)
		error = result->error;
	if (error != 0) {
		session_drop();
		return (errno = error, -1);
	}
	if (result->error != 0)
		return (errno = result->error, -1);
	return (0);
}

/* Open or reuse the session and negotiate.  Caller holds devicecmp_lock. */
static int
begin_locked(struct timespec *deadline)
{
	struct completion result = { .fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t timeout_ms = DEVICECMP_CALL_TIMEOUT_MS, txid;
	int error;

	/* A caller's service_budget_begin(3) bounds the whole operation. */
	if (service_budget_timeout(&timeout_ms) == -1)
		return (-1);
	if ((error = fidl_bsd_sync_deadline(deadline, timeout_ms)) != 0)
		return (errno = error, -1);
	if (session_get() == -1)
		return (-1);
	if (devicecmp_negotiated)
		return (0);
	error = bsd_device_v1_Device_GetProtocolInfo(devicecmp_connection,
	    &empty, info_reply, &result, &txid);
	if (finish_locked(error, &result, deadline) == -1)
		return (-1);
	devicecmp_negotiated = true;
	return (0);
}

int
devicecmp_open(struct service_context *ctx, const char *name,
    uint32_t want_rights, uint32_t *granted_rights, int *fdp)
{
	struct completion result = { .fd = -1 };
	struct bsd_device_v1_OpenRequest request;
	struct timespec deadline;
	uint32_t txid;
	int rc;

	(void)ctx;
	if (fdp == NULL)
		return (errno = EINVAL, -1);
	*fdp = -1;
	if (granted_rights != NULL)
		*granted_rights = 0;
	if (name == NULL || !valid_leaf(name, strnlen(name, DEVICECMP_MAX_NAME)) ||
	    want_rights == 0 || (want_rights & ~DEVICECMP_RIGHT_ALL) != 0)
		return (errno = EINVAL, -1);
	request.name = name;
	request.name_size = strlen(name);
	request.rights = want_rights;
	result.want = want_rights;

	pthread_mutex_lock(&devicecmp_lock);
	rc = begin_locked(&deadline);
	if (rc == 0)
		rc = finish_locked(bsd_device_v1_Device_Open(devicecmp_connection,
		    &request, open_reply, &result, &txid), &result, &deadline);
	pthread_mutex_unlock(&devicecmp_lock);
	if (rc == -1) {
		int error = errno;

		if (result.fd >= 0)
			(void)close(result.fd);
		return (errno = error, -1);
	}
	if (granted_rights != NULL)
		*granted_rights = result.granted;
	*fdp = result.fd;
	return (0);
}

int
devicecmp_list(struct service_context *ctx, uint32_t cursor,
    struct devicecmp_list_entry *entries, uint32_t max, uint32_t *countp,
    uint32_t *next_cursorp)
{
	struct completion result = { .fd = -1 };
	struct bsd_device_v1_ListRequest request = { cursor };
	struct timespec deadline;
	uint32_t txid;
	int rc;

	(void)ctx;
	if (countp != NULL)
		*countp = 0;
	if (next_cursorp != NULL)
		*next_cursorp = 0;
	if (entries == NULL || max == 0)
		return (errno = EINVAL, -1);
	result.cursor = cursor;
	result.entries = entries;
	result.max = max;

	pthread_mutex_lock(&devicecmp_lock);
	rc = begin_locked(&deadline);
	if (rc == 0)
		rc = finish_locked(bsd_device_v1_Device_List(devicecmp_connection,
		    &request, list_reply, &result, &txid), &result, &deadline);
	pthread_mutex_unlock(&devicecmp_lock);
	if (rc == -1)
		return (-1);
	if (result.count > max) {
		if (countp != NULL)
			*countp = result.count;
		return (errno = ENOMEM, -1);
	}
	if (countp != NULL)
		*countp = result.count;
	if (next_cursorp != NULL)
		*next_cursorp = result.next;
	return (0);
}
