/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Scripted system.Audit provider for the libauditcmp client tests.  It
 * replaces libservice's service_open() (each call creates a real capability
 * channel served by a bsd.audit.v1 server on its own thread) and
 * service_budget_timeout() (a scripted timeout shortens the call deadline).
 */
#include <sys/types.h>

#include <assert.h>
#include <channel.h>
#include <errno.h>
#include <fidl/bsd.audit.v1/c/bsd.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <auditcmp.h>
#include "fake_service.h"

int service_open(const char *, int *);
int service_budget_timeout(uint32_t *);

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned created, closed, submitted;
static int next_error, next_connect_error;
static enum fake_reply_mode mode;
static bool short_deadline;

void
fake_service_reset(void)
{
	pthread_mutex_lock(&lock);
	while (closed < created)
		pthread_cond_wait(&changed, &lock);
	created = closed = submitted = 0;
	next_error = next_connect_error = 0;
	mode = FAKE_REPLY_NORMAL;
	short_deadline = false;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fail_next(int error)
{
	pthread_mutex_lock(&lock);
	next_error = error;
	short_deadline = error == ETIMEDOUT;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fail_connect_next(int error)
{
	pthread_mutex_lock(&lock);
	next_connect_error = error;
	pthread_mutex_unlock(&lock);
}

void
fake_service_reply_mode(enum fake_reply_mode value)
{
	pthread_mutex_lock(&lock);
	mode = value;
	pthread_mutex_unlock(&lock);
}

unsigned
fake_service_created(void)
{
	unsigned result;
	pthread_mutex_lock(&lock);
	result = created;
	pthread_mutex_unlock(&lock);
	return (result);
}

/* Sessions whose server saw the client leave (waits briefly for them). */
unsigned
fake_service_closed(void)
{
	struct timespec deadline;
	unsigned result;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 2;
	pthread_mutex_lock(&lock);
	while (closed < created &&
	    pthread_cond_timedwait(&changed, &lock, &deadline) == 0)
		;
	result = closed;
	pthread_mutex_unlock(&lock);
	return (result);
}

unsigned
fake_service_submitted(void)
{
	unsigned result;
	pthread_mutex_lock(&lock);
	result = submitted;
	pthread_mutex_unlock(&lock);
	return (result);
}

int
service_budget_timeout(uint32_t *ms)
{
	if (ms == NULL)
		return (errno = EINVAL, -1);
	pthread_mutex_lock(&lock);
	if (short_deadline && *ms > 300)
		*ms = 300;
	pthread_mutex_unlock(&lock);
	return (0);
}

/* The scripted fault for the next operation: 0, a close, or silence. */
static int
take_error(void)
{
	int error;

	pthread_mutex_lock(&lock);
	error = next_error;
	next_error = 0;
	pthread_mutex_unlock(&lock);
	return (error);
}

static void
info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct bsd_audit_v1_ProtocolInfo v = { AUDITCMP_WIRE_VERSION };
	(void)x;
	(void)e;
	pthread_mutex_lock(&lock);
	if (mode == FAKE_REPLY_FUTURE_VERSION)
		v.wire_version++;
	pthread_mutex_unlock(&lock);
	assert(bsd_audit_v1_Audit_GetProtocolInfo_reply(c, r, &v) == 0);
}

static void
submit(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_audit_v1_SubmitRequest *q)
{
	struct bsd_audit_v1_Audit_Submit_Result v = {
		.tag = bsd_audit_v1_Audit_Submit_Result_response_tag
	};
	enum fake_reply_mode selected;
	int error = take_error();
	(void)x;
	(void)q;
	if (error == ETIMEDOUT)
		return;
	if (error != 0) {
		fidl_bsd_connection_close(c, error);
		return;
	}
	/* Let concurrent sessions overlap. */
	usleep(10000);
	pthread_mutex_lock(&lock);
	selected = mode;
	submitted++;
	pthread_mutex_unlock(&lock);
	if (selected == FAKE_REPLY_STATUS) {
		v.tag = bsd_audit_v1_Audit_Submit_Result_err_tag;
		v.value.err = EPERM;
	} else if (selected == FAKE_REPLY_ZERO_ERRNO ||
	    selected == FAKE_REPLY_RANGE_ERRNO) {
		v.tag = bsd_audit_v1_Audit_Submit_Result_err_tag;
		v.value.err = selected == FAKE_REPLY_ZERO_ERRNO ? 0 : ELAST + 1;
	}
	assert(bsd_audit_v1_Audit_Submit_reply(c, r, &v) == 0);
}

static void
stats(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct bsd_audit_v1_AuditStats v = { 0, 0 };
	int error = take_error();
	(void)x;
	(void)e;
	if (error == ETIMEDOUT)
		return;
	if (error != 0) {
		fidl_bsd_connection_close(c, error);
		return;
	}
	pthread_mutex_lock(&lock);
	v.submitted = submitted;
	pthread_mutex_unlock(&lock);
	assert(bsd_audit_v1_Audit_Stats_reply(c, r, &v) == 0);
}

static void *
serve(void *argument)
{
	struct bsd_audit_v1_Audit_server handlers = {
		.GetProtocolInfo = info,
		.Submit = submit,
		.Stats = stats
	};
	struct fidl_bsd_connection *connection;
	int fd = (int)(intptr_t)argument;

	assert(fidl_bsd_connection_create(fd, FIDL_BSD_SERVER,
	    &connection) == 0);
	assert(bsd_audit_v1_Audit_bind(connection, &handlers, NULL) == 0);
	while (fidl_bsd_connection_poll(connection, 10000) == 0)
		;
	fidl_bsd_connection_destroy(connection);
	pthread_mutex_lock(&lock);
	closed++;
	pthread_cond_broadcast(&changed);
	pthread_mutex_unlock(&lock);
	return (NULL);
}

int
service_open(const char *name, int *fdp)
{
	pthread_t thread;
	int ends[2], error;

	if (name == NULL || strcmp(name, AUDITCMP_INTERFACE) != 0 ||
	    fdp == NULL)
		return (errno = EINVAL, -1);
	pthread_mutex_lock(&lock);
	error = next_connect_error;
	next_connect_error = 0;
	pthread_mutex_unlock(&lock);
	if (error != 0)
		return (errno = error, -1);
	if (mac_capability_channel_create(ends) != 0)
		return (-1);
	assert(pthread_create(&thread, NULL, serve,
	    (void *)(intptr_t)ends[1]) == 0);
	assert(pthread_detach(thread) == 0);
	pthread_mutex_lock(&lock);
	created++;
	pthread_mutex_unlock(&lock);
	*fdp = ends[0];
	return (0);
}
