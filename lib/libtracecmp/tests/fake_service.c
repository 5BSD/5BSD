/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include <tracecmp.h>
#include "fake_service.h"

struct service_context { int unused; };
struct service_session { int unused; };
static struct service_context context;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned created, closed, concurrent, maximum;
static int connect_error, call_error;
static enum fake_reply_mode mode;

void
fake_service_reset(void)
{
	pthread_mutex_lock(&lock);
	created = closed = concurrent = maximum = 0;
	connect_error = call_error = 0;
	mode = FAKE_REPLY_NORMAL;
	pthread_mutex_unlock(&lock);
}

void fake_service_fail_connect(int error) { connect_error = error; }
void fake_service_fail_call(int error) { call_error = error; }
void fake_service_reply_mode(enum fake_reply_mode value) { mode = value; }
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
void service_release(struct service_context *service __unused) { }

int
service_connect(struct service_context *service, const char *name, int *fd)
{
	int error;
	if (service != &context || strcmp(name, TRACECMP_INTERFACE) != 0 ||
	    fd == NULL)
		return (errno = EINVAL, -1);
	pthread_mutex_lock(&lock);
	error = connect_error;
	connect_error = 0;
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
service_session_call(struct service_session *session,
    const struct service_message *outgoing, struct service_reply *reply,
    const struct service_call_options *options __unused)
{
	struct {
		struct tracecmp_msg msg;
		union {
			struct tracecmp_hello_reply hello;
			struct tracecmp_stats stats;
		} body;
	} response;
	const struct tracecmp_msg *request;
	enum fake_reply_mode selected;
	size_t length;
	int error, fd[2];

	if (session == NULL || outgoing == NULL || reply == NULL ||
	    outgoing->length != sizeof(*request))
		return (errno = EINVAL, -1);
	request = outgoing->data;
	pthread_mutex_lock(&lock);
	concurrent++;
	if (concurrent > maximum)
		maximum = concurrent;
	error = call_error;
	call_error = 0;
	selected = mode;
	pthread_mutex_unlock(&lock);
	usleep(20000);
	if (error != 0)
		goto fail;
	memset(&response, 0, sizeof(response));
	response.msg.magic = TRACECMP_MAGIC;
	response.msg.version = TRACECMP_ABI_VERSION;
	response.msg.opcode = selected == FAKE_REPLY_BAD_OPCODE ?
	    TRACECMP_OP_STATS : request->opcode;
	if (selected == FAKE_REPLY_BAD_MAGIC)
		response.msg.magic ^= 1;
	else if (selected == FAKE_REPLY_BAD_VERSION)
		response.msg.version++;
	else if (selected == FAKE_REPLY_BAD_FLAGS)
		response.msg.flags = 1;
	length = sizeof(response.msg);
	if (request->opcode == TRACECMP_OP_HELLO) {
		response.body.hello.version = TRACECMP_ABI_VERSION;
		response.body.hello.features = selected == FAKE_REPLY_NO_FEATURE ?
		    0 : TRACECMP_FEATURE_RAW_DTRACE_FD;
		if (selected == FAKE_REPLY_BAD_HELLO_RESERVED)
			response.body.hello.reserved[0] = 1;
		length += sizeof(response.body.hello);
	} else if (request->opcode == TRACECMP_OP_STATS) {
		response.body.stats.opened = FAKE_STATS_OPENED;
		response.body.stats.rejected = FAKE_STATS_REJECTED;
		length += sizeof(response.body.stats);
	}
	if (reply->capacity < length) {
		error = EMSGSIZE;
		goto fail;
	}
	memcpy(reply->data, &response, length);
	reply->length = length;
	reply->nfds = 0;
	if (request->opcode == TRACECMP_OP_HELLO &&
	    selected == FAKE_REPLY_UNEXPECTED_HELLO_FD)
		reply->nfds = 1;
	if (request->opcode == TRACECMP_OP_OPEN &&
	    selected != FAKE_REPLY_MISSING_FD) {
		if (pipe(fd) == -1) {
			error = errno;
			goto fail;
		}
		close(fd[1]);
		if (reply->fd_capacity == 0) {
			close(fd[0]);
			error = EMSGSIZE;
			goto fail;
		}
		reply->fds[0] = fd[0];
		reply->nfds = 1;
	}
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
