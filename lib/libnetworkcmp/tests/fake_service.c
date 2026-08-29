/* SPDX-License-Identifier: BSD-2-Clause */
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
#include <networkcmp.h>
#include <networkcmp_server.h>
#include "fake_service.h"

struct service_context { int unused; };
struct service_session { int terminal; };
static struct service_context context;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned created, closed, calls, concurrent, maximum;
static int next_error;
static bool next_malformed;

void
fake_service_reset(void)
{
	pthread_mutex_lock(&lock);
	created = closed = calls = concurrent = maximum = 0;
	next_error = 0;
	next_malformed = false;
	pthread_mutex_unlock(&lock);
}

void
fake_service_malformed_reply(void)
{
	pthread_mutex_lock(&lock);
	next_malformed = true;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fail(int error)
{
	pthread_mutex_lock(&lock);
	next_error = error;
	pthread_mutex_unlock(&lock);
}

#define COUNTER(name, value) \
	unsigned name(void) { unsigned result; pthread_mutex_lock(&lock); \
	result = value; pthread_mutex_unlock(&lock); return (result); }
COUNTER(fake_service_created, created)
COUNTER(fake_service_closed, closed)
COUNTER(fake_service_calls, calls)
COUNTER(fake_service_max_concurrent, maximum)

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
	if (service != &context || strcmp(name, NETWORKCMP_INTERFACE) != 0 ||
	    fd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return (*fd < 0 ? -1 : 0);
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
	uint8_t storage[NETWORKCMP_MAX_MESSAGE];
	const struct networkcmp_msg *request;
	struct networkcmp_msg *response;
	struct networkcmp_hello_reply *hello;
	int error;
	bool malformed;
	size_t length;

	if (session == NULL || outgoing == NULL || reply == NULL ||
	    outgoing->length < sizeof(*request)) {
		errno = EINVAL;
		return (-1);
	}
	request = outgoing->data;
	pthread_mutex_lock(&lock);
	concurrent++;
	if (concurrent > maximum)
		maximum = concurrent;
	calls++;
	error = session->terminal != 0 ? session->terminal : next_error;
	malformed = next_malformed;
	next_malformed = false;
	if (next_error != 0) {
		session->terminal = next_error;
		next_error = 0;
	}
	pthread_mutex_unlock(&lock);
	usleep(20000);
	if (error != 0)
		goto fail;
	memset(storage, 0, sizeof(storage));
	response = (void *)storage;
	if (networkcmp_message_init_reply(response, request, 0) == -1)
		goto fail;
	if (malformed)
		response->magic ^= 1;
	length = sizeof(*response);
	if (request->opcode == NETWORKCMP_OP_HELLO) {
		hello = (void *)(response + 1);
		hello->version = NETWORKCMP_ABI_VERSION;
		hello->features = NETWORKCMP_FEATURE_TCP | NETWORKCMP_FEATURE_UDP |
		    NETWORKCMP_FEATURE_IPV6 | NETWORKCMP_FEATURE_DNS;
		hello->max_resolve_results = NETWORKCMP_RESOLVE_MAX_RESULTS;
		length += sizeof(*hello);
	}
	if (reply->capacity < length) {
		error = EMSGSIZE;
		goto fail;
	}
	memcpy(reply->data, storage, length);
	reply->length = length;
	reply->nfds = 0;
	pthread_mutex_lock(&lock);
	concurrent--;
	pthread_mutex_unlock(&lock);
	return (0);
fail:
	if (error == 0)
		error = errno != 0 ? errno : EIO;
	pthread_mutex_lock(&lock);
	concurrent--;
	pthread_mutex_unlock(&lock);
	errno = error;
	return (-1);
}

int
service_session_receive_event(struct service_session *session __unused,
    struct service_reply *reply __unused,
    const struct service_call_options *options __unused)
{
	errno = ENOTSUP;
	return (-1);
}
