/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include <cryptocmp.h>

#include "fake_service.h"

struct service_context {
	int unused;
};

struct service_session {
	unsigned ident;
};

static struct service_context context;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static enum fake_service_fault next_fault;
static unsigned calls, closed, created;
static int next_status, last_fd = -1;

void
fake_service_reset(void)
{

	pthread_mutex_lock(&lock);
	next_fault = FAKE_SERVICE_FAULT_NONE;
	next_status = 0;
	last_fd = -1;
	calls = closed = created = 0;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fault_next(enum fake_service_fault fault)
{

	pthread_mutex_lock(&lock);
	next_fault = fault;
	pthread_mutex_unlock(&lock);
}

void
fake_service_status_next(int status)
{

	pthread_mutex_lock(&lock);
	next_status = status;
	pthread_mutex_unlock(&lock);
}

#define COUNTER(name, field) \
	unsigned name(void) { unsigned value; pthread_mutex_lock(&lock); \
	value = field; pthread_mutex_unlock(&lock); return (value); }
COUNTER(fake_service_calls, calls)
COUNTER(fake_service_closed, closed)
COUNTER(fake_service_created, created)

int
fake_service_last_fd(void)
{
	int fd;

	pthread_mutex_lock(&lock);
	fd = last_fd;
	pthread_mutex_unlock(&lock);
	return (fd);
}

int
service_acquire(struct service_context **result)
{

	if (result == NULL) {
		errno = EINVAL;
		return (-1);
	}
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

	if (service != &context || name == NULL || fd == NULL ||
	    strcmp(name, CRYPTOCMP_INTERFACE) != 0) {
		errno = EINVAL;
		return (-1);
	}
	*fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return (*fd == -1 ? -1 : 0);
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

	if (fd < 0 || result == NULL) {
		errno = EINVAL;
		return (-1);
	}
	session = calloc(1, sizeof(*session));
	if (session == NULL)
		return (-1);
	(void)close(fd);
	pthread_mutex_lock(&lock);
	session->ident = ++created;
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
service_session_call(struct service_session *session,
    const struct service_message *outgoing, struct service_reply *reply,
    const struct service_call_options *options __unused)
{
	union {
		struct cryptocmp_msg msg;
		struct cryptocmp_key_reply key;
		struct cryptocmp_named_reply named;
	} response;
	const struct cryptocmp_msg *request;
	enum fake_service_fault fault;
	size_t length;
	int fd, status;
	bool wants_fd;

	if (session == NULL || outgoing == NULL || outgoing->data == NULL ||
	    outgoing->length < sizeof(*request) || reply == NULL ||
	    reply->data == NULL) {
		errno = EINVAL;
		return (-1);
	}
	request = outgoing->data;
	pthread_mutex_lock(&lock);
	calls++;
	fault = next_fault;
	status = next_status;
	next_fault = FAKE_SERVICE_FAULT_NONE;
	next_status = 0;
	pthread_mutex_unlock(&lock);
	if (fault == FAKE_SERVICE_FAULT_CALL) {
		errno = ECONNRESET;
		return (-1);
	}
	memset(&response, 0, sizeof(response));
	response.msg.magic = CRYPTOCMP_MAGIC;
	response.msg.version = CRYPTOCMP_VERSION;
	response.msg.opcode = request->opcode;
	response.msg.status = -status;
	length = sizeof(response.msg);
	if (request->opcode == CRYPTOCMP_OP_GENERATE_KEY) {
		length = sizeof(response.key);
		memset(response.key.public_key, 0xa5,
		    sizeof(response.key.public_key));
	} else if (request->opcode >= CRYPTOCMP_OP_NAMED_CREATE &&
	    request->opcode <= CRYPTOCMP_OP_NAMED_DELETE) {
		length = sizeof(response.named);
		response.named.generation = 42;
	}
	switch (fault) {
	case FAKE_SERVICE_FAULT_TRUNCATE:
		length--;
		break;
	case FAKE_SERVICE_FAULT_WRONG_MAGIC:
		response.msg.magic ^= 1;
		break;
	case FAKE_SERVICE_FAULT_WRONG_VERSION:
		response.msg.version++;
		break;
	case FAKE_SERVICE_FAULT_WRONG_OPCODE:
		response.msg.opcode++;
		break;
	case FAKE_SERVICE_FAULT_POSITIVE_STATUS:
		response.msg.status = 1;
		break;
	case FAKE_SERVICE_FAULT_INVALID_STATUS:
		response.msg.status = -(ELAST + 1);
		break;
	default:
		break;
	}
	if (reply->capacity < length) {
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(reply->data, &response, length);
	reply->length = length;
	reply->nfds = 0;
	wants_fd = status == 0 && (request->opcode == CRYPTOCMP_OP_GENERATE ||
	    request->opcode == CRYPTOCMP_OP_GENERATE_KEY ||
	    request->opcode == CRYPTOCMP_OP_NAMED_LEASE);
	if (fault == FAKE_SERVICE_FAULT_MISSING_FD)
		wants_fd = false;
	if (fault == FAKE_SERVICE_FAULT_UNEXPECTED_FD)
		wants_fd = true;
	if (wants_fd) {
		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (fd == -1)
			return (-1);
		if (reply->fds == NULL || reply->fd_capacity == 0) {
			(void)close(fd);
			errno = EMSGSIZE;
			return (-1);
		}
		reply->fds[0] = fd;
		reply->nfds = 1;
		pthread_mutex_lock(&lock);
		last_fd = fd;
		pthread_mutex_unlock(&lock);
	}
	return (0);
}
