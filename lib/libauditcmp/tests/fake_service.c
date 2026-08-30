/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <auditcmp.h>
#include <libservice.h>

#include "fake_service.h"

struct service_context { int unused; };
struct service_session { int terminal; };
static struct service_context context;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned created, closed, concurrent, maximum;
static int next_error, next_connect_error;
static enum fake_reply_mode next_mode;

void
fake_service_reset(void)
{
	pthread_mutex_lock(&lock);
	created = closed = concurrent = maximum = 0;
	next_error = next_connect_error = 0;
	next_mode = FAKE_REPLY_NORMAL;
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
fake_service_fail_next(int error)
{
	pthread_mutex_lock(&lock);
	next_error = error;
	pthread_mutex_unlock(&lock);
}

void
fake_service_reply_mode(enum fake_reply_mode mode)
{
	pthread_mutex_lock(&lock);
	next_mode = mode;
	pthread_mutex_unlock(&lock);
}

#define COUNTER(name, value) \
	unsigned name(void) { unsigned result; pthread_mutex_lock(&lock); \
	result = value; pthread_mutex_unlock(&lock); return (result); }
COUNTER(fake_service_created, created)
COUNTER(fake_service_closed, closed)
COUNTER(fake_service_max_concurrent, maximum)

int
service_acquire(struct service_context **result)
{
	if (result == NULL)
		return (errno = EINVAL, -1);
	*result = &context;
	return (0);
}

void
service_release(struct service_context *service __unused)
{
}

int
service_connect(struct service_context *service, const char *name, int *fd)
{
	int error;

	if (service != &context || strcmp(name, AUDITCMP_INTERFACE) != 0 ||
	    fd == NULL)
		return (errno = EINVAL, -1);
	pthread_mutex_lock(&lock);
	error = next_connect_error;
	next_connect_error = 0;
	pthread_mutex_unlock(&lock);
	if (error != 0)
		return (errno = error, -1);
	*fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return (*fd < 0 ? -1 : 0);
}

int
service_open(const char *name, int *fd)
{
	struct service_context *ctx;
	int rv;

	if (service_acquire(&ctx) == -1)
		return (-1);
	rv = service_connect(ctx, name, fd);
	service_release(ctx);
	return (rv);
}

int
service_session_create(int fd, struct service_session **result)
{
	struct service_session *session;

	if (fd < 0 || result == NULL)
		return (errno = EINVAL, -1);
	session = calloc(1, sizeof(*session));
	if (session == NULL)
		return (-1);
	close(fd);
	pthread_mutex_lock(&lock);
	created++;
	pthread_mutex_unlock(&lock);
	*result = session;
	return (0);
}

void
service_session_close(struct service_session *session)
{
	if (session == NULL)
		return;
	pthread_mutex_lock(&lock);
	closed++;
	pthread_mutex_unlock(&lock);
	free(session);
}

int
service_session_fail(struct service_session *session, int error)
{
	if (session == NULL || error <= 0 || error > ELAST)
		return (errno = EINVAL, -1);
	session->terminal = error;
	errno = error;
	return (0);
}

int
service_session_call(struct service_session *session,
    const struct service_message *outgoing, struct service_reply *reply,
    const struct service_call_options *options __unused)
{
	union {
		max_align_t align;
		uint8_t bytes[AUDITCMP_MAX_MESSAGE];
	} response;
	const struct auditcmp_msg *request;
	struct auditcmp_msg *message;
	struct auditcmp_hello_reply *hello;
	struct auditcmp_stats *stats;
	enum fake_reply_mode mode;
	size_t length;
	int error;

	if (session == NULL || outgoing == NULL || reply == NULL ||
	    outgoing->length < sizeof(*request))
		return (errno = EINVAL, -1);
	request = outgoing->data;
	pthread_mutex_lock(&lock);
	concurrent++;
	if (concurrent > maximum)
		maximum = concurrent;
	error = session->terminal != 0 ? session->terminal : next_error;
	if (next_error != 0) {
		if (next_error == ECONNRESET || next_error == EPIPE ||
		    next_error == ENOTCONN || next_error == ESHUTDOWN)
			session->terminal = next_error;
		next_error = 0;
	}
	mode = next_mode;
	next_mode = FAKE_REPLY_NORMAL;
	pthread_mutex_unlock(&lock);
	usleep(20000);
	if (error != 0)
		goto fail;
	memset(&response, 0, sizeof(response));
	message = (void *)response.bytes;
	message->magic = AUDITCMP_MAGIC;
	message->version = AUDITCMP_ABI_VERSION;
	message->opcode = mode == FAKE_REPLY_BAD_OPCODE ?
	    (request->opcode == AUDITCMP_OP_STATS ? AUDITCMP_OP_SUBMIT :
	    AUDITCMP_OP_STATS) : request->opcode;
	length = sizeof(*message);
	if (request->opcode == AUDITCMP_OP_HELLO) {
		hello = (void *)(message + 1);
		hello->version = AUDITCMP_ABI_VERSION;
		if (mode == FAKE_REPLY_BAD_HELLO)
			hello->version++;
		length += sizeof(*hello);
	} else if (request->opcode == AUDITCMP_OP_STATS) {
		stats = (void *)(message + 1);
		stats->submitted = 7;
		length += sizeof(*stats);
		if (mode == FAKE_REPLY_BAD_STATS)
			length--;
	}
	if (mode == FAKE_REPLY_STATUS) {
		message->status = -EPERM;
		length = sizeof(*message);
	} else if (mode == FAKE_REPLY_TRUNCATED && length > 0)
		length--;
	if (reply->capacity < length) {
		error = EMSGSIZE;
		goto fail;
	}
	memcpy(reply->data, response.bytes, length);
	reply->length = length;
	reply->nfds = mode == FAKE_REPLY_UNEXPECTED_FD ? 1 : 0;
	pthread_mutex_lock(&lock);
	concurrent--;
	pthread_mutex_unlock(&lock);
	return (0);

fail:
	pthread_mutex_lock(&lock);
	concurrent--;
	pthread_mutex_unlock(&lock);
	errno = error != 0 ? error : EIO;
	return (-1);
}
