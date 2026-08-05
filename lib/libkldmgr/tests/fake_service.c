/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include <kldmgr.h>
#include "fake_service.h"

struct service_context { int unused; };
struct service_session { int terminal; };
static struct service_context context;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned created, closed, concurrent, maximum, nonzero_name_tail;
static int next_error, next_connect_error;
static enum fake_reply_mode next_mode;

void
fake_service_reset(void)
{
	pthread_mutex_lock(&lock);
	created = closed = concurrent = maximum = nonzero_name_tail = 0;
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
COUNTER(fake_service_nonzero_name_tail, nonzero_name_tail)

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

	if (service != &context || strcmp(name, KLDMGR_INTERFACE) != 0 ||
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
	uint8_t storage[sizeof(struct kldmgr_msg) +
	    sizeof(struct kldmgr_list_reply) + sizeof(struct kldmgr_list_entry)];
	const struct kldmgr_msg *request;
	const struct kldmgr_module_request *module_request;
	struct kldmgr_msg *response;
	struct kldmgr_id_reply *id;
	struct kldmgr_list_reply *list;
	enum fake_reply_mode mode;
	size_t length;
	int error;

	if (session == NULL || outgoing == NULL || reply == NULL ||
	    outgoing->length < sizeof(*request))
		return (errno = EINVAL, -1);
	request = outgoing->data;
	if ((request->opcode == KLDMGR_OP_LOAD ||
	    request->opcode == KLDMGR_OP_UNLOAD) &&
	    outgoing->length == sizeof(*request) + sizeof(*module_request)) {
		module_request = (const void *)(request + 1);
		length = strnlen(module_request->name,
		    sizeof(module_request->name));
		for (size_t i = length + 1; i < sizeof(module_request->name);
		    i++) {
			if (module_request->name[i] == '\0')
				continue;
			pthread_mutex_lock(&lock);
			nonzero_name_tail++;
			pthread_mutex_unlock(&lock);
			break;
		}
	}
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
	memset(storage, 0, sizeof(storage));
	response = (void *)storage;
	response->magic = KLDMGR_MAGIC;
	response->version = KLDMGR_ABI_VERSION;
	response->opcode = mode == FAKE_REPLY_BAD_OPCODE ? KLDMGR_OP_LIST :
	    request->opcode;
	if (mode == FAKE_REPLY_BAD_MAGIC)
		response->magic ^= 1;
	else if (mode == FAKE_REPLY_BAD_VERSION)
		response->version++;
	else if (mode == FAKE_REPLY_BAD_FLAGS)
		response->flags = 1;
	else if (mode == FAKE_REPLY_BAD_STATUS)
		response->status = 1;
	length = sizeof(*response);
	if (request->opcode == KLDMGR_OP_LOAD ||
	    request->opcode == KLDMGR_OP_UNLOAD) {
		id = (void *)(response + 1);
		id->id = 7;
		if (mode == FAKE_REPLY_BAD_ID)
			id->id = -1;
		else if (mode == FAKE_REPLY_BAD_ID_RESERVED)
			id->reserved = 1;
		length += sizeof(*id);
	} else {
		list = (void *)(response + 1);
		list->count = 1;
		list->entries[0].id = 7;
		strlcpy(list->entries[0].name, "if_bridge",
		    sizeof(list->entries[0].name));
		if (mode == FAKE_REPLY_BAD_LIST_COUNT)
			list->count = KLDMGR_LIST_MAX + 1;
		else if (mode == FAKE_REPLY_BAD_LIST_RESERVED)
			list->reserved = 1;
		else if (mode == FAKE_REPLY_BAD_LIST_ID)
			list->entries[0].id = -1;
		else if (mode == FAKE_REPLY_BAD_LIST_NAME)
			memset(list->entries[0].name, 'x',
			    sizeof(list->entries[0].name));
		length += sizeof(*list) + sizeof(list->entries[0]);
	}
	if (mode == FAKE_REPLY_STATUS) {
		response->status = -EPERM;
		length = sizeof(*response);
	} else if (mode == FAKE_REPLY_ERROR_PAYLOAD) {
		response->status = -EPERM;
	} else if (mode == FAKE_REPLY_TRUNCATED && length > 0)
		length--;
	if (reply->capacity < length) {
		error = EMSGSIZE;
		goto fail;
	}
	memcpy(reply->data, storage, length);
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
