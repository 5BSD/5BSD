/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <logcmp.h>
#include <logcmp_server.h>
#include <shmring.h>

#include "fake_service.h"
#include "logcmp_wakeup.h"

struct service_context { int unused; };
struct service_session {
	unsigned ident;
	struct shmring *ring;
	int wake_fd;
};

static struct service_context context;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned created, closed, writes, concurrent, max_concurrent;
static unsigned attaches, detaches;
static size_t ring_capacity;
static uint32_t ring_shape;
static unsigned loss_records;
static uint64_t last_loss_count;
static int fail_write_error;
static int fail_attach_error;
static uint16_t fail_opcode;
static int fail_operation_error;
static bool ring_enabled;
static bool corrupt_next_ring;
static bool break_next_wakeup;
static enum fake_service_fault next_fault;

void
fake_service_reset(void)
{
	pthread_mutex_lock(&lock);
	created = closed = writes = concurrent = max_concurrent = 0;
	attaches = detaches = 0;
	ring_capacity = 0;
	ring_shape = 0;
	loss_records = 0;
	last_loss_count = 0;
	fail_write_error = 0;
	fail_attach_error = 0;
	fail_opcode = 0;
	fail_operation_error = 0;
	ring_enabled = false;
	corrupt_next_ring = false;
	break_next_wakeup = false;
	next_fault = FAKE_SERVICE_FAULT_NONE;
	pthread_mutex_unlock(&lock);
}

void
fake_service_break_next_wakeup(void)
{

	pthread_mutex_lock(&lock);
	break_next_wakeup = true;
	pthread_mutex_unlock(&lock);
}

void
fake_service_corrupt_next_ring(void)
{

	pthread_mutex_lock(&lock);
	corrupt_next_ring = true;
	pthread_mutex_unlock(&lock);
}

void
fake_service_enable_ring(void)
{

	pthread_mutex_lock(&lock);
	ring_enabled = true;
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
fake_service_fail_write(void)
{
	fake_service_fail_write_with(ECONNRESET);
}

void
fake_service_fail_write_with(int error)
{
	pthread_mutex_lock(&lock);
	fail_write_error = error;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fail_attach_with(int error)
{

	pthread_mutex_lock(&lock);
	fail_attach_error = error;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fail_operation(uint16_t opcode, int error)
{

	pthread_mutex_lock(&lock);
	fail_opcode = opcode;
	fail_operation_error = error;
	pthread_mutex_unlock(&lock);
}

#define COUNTER(name, field) \
	unsigned name(void) { unsigned value; pthread_mutex_lock(&lock); \
	value = field; pthread_mutex_unlock(&lock); return (value); }
COUNTER(fake_service_created, created)
COUNTER(fake_service_closed, closed)
COUNTER(fake_service_writes, writes)
COUNTER(fake_service_max_concurrent, max_concurrent)
COUNTER(fake_service_loss_records, loss_records)
COUNTER(fake_service_attaches, attaches)
COUNTER(fake_service_detaches, detaches)

size_t
fake_service_ring_capacity(void)
{
	size_t value;

	pthread_mutex_lock(&lock);
	value = ring_capacity;
	pthread_mutex_unlock(&lock);
	return (value);
}

uint32_t
fake_service_ring_shape(void)
{
	uint32_t value;

	pthread_mutex_lock(&lock);
	value = ring_shape;
	pthread_mutex_unlock(&lock);
	return (value);
}

uint64_t
fake_service_last_loss_count(void)
{
	uint64_t value;

	pthread_mutex_lock(&lock);
	value = last_loss_count;
	pthread_mutex_unlock(&lock);
	return (value);
}

static void
inspect_record_locked(const struct logcmp_record *record)
{
	static const char subsystem[] = "system.Log";
	static const char event_name[] = "records-dropped";
	const uint8_t *cursor;
	struct logcmp_attribute_wire attribute;

	if (record->subsystem_length != sizeof(subsystem) - 1 ||
	    record->event_name_length != sizeof(event_name) - 1)
		return;
	cursor = (const void *)(record + 1);
	if (memcmp(cursor, subsystem, sizeof(subsystem) - 1) != 0)
		return;
	cursor += record->subsystem_length + record->category_length;
	if (memcmp(cursor, event_name, sizeof(event_name) - 1) != 0)
		return;
	cursor += record->event_name_length + record->message_length;
	memcpy(&attribute, cursor, sizeof(attribute));
	cursor += sizeof(attribute) + attribute.key_length;
	if (record->attribute_count != 1 ||
	    attribute.type != LOGCMP_ATTR_UINT64 ||
	    attribute.value_length != sizeof(last_loss_count))
		return;
	memcpy(&last_loss_count, cursor, sizeof(last_loss_count));
	loss_records++;
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

	if (service != &context || name == NULL ||
	    strcmp(name, LOGCMP_INTERFACE) != 0 || fd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return (*fd == -1 ? -1 : 0);
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
	session->wake_fd = -1;
	close(fd);
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
	shmring_close(session->ring);
	if (session->wake_fd >= 0)
		close(session->wake_fd);
	pthread_mutex_lock(&lock);
	closed++;
	pthread_mutex_unlock(&lock);
	free(session);
}

static int
attach_ring(struct service_session *session,
    const struct service_message *outgoing)
{
	const struct logcmp_attach_request *attach;
	struct shmring_fds consumer;
	int *slots[] = { &consumer.config_fd, &consumer.data_fd,
	    &consumer.head_fd, &consumer.tail_fd };
	unsigned i;
	bool break_wakeup, corrupt;
	int error;
	uint64_t *tail;

	if (session->ring != NULL || outgoing->nfds != LOGCMP_ATTACH_FD_COUNT)
		return (errno = EPROTO, -1);
	attach = (const void *)((const struct logcmp_msg *)outgoing->data + 1);
	if ((attach->ring_size != 16U * 1024 &&
	    attach->ring_size != 64U * 1024) ||
	    attach->max_record != LOGCMP_MAX_RECORD || attach->generation == 0)
		return (errno = EPROTO, -1);
	memset(&consumer, -1, sizeof(consumer));
	for (i = 0; i < nitems(slots); i++) {
		*slots[i] = fcntl(outgoing->fds[i], F_DUPFD_CLOEXEC, 0);
		if (*slots[i] == -1)
			goto fail;
	}
	session->wake_fd = fcntl(outgoing->fds[LOGCMP_ATTACH_FD_WAKE_READ],
	    F_DUPFD_CLOEXEC, 0);
	if (session->wake_fd == -1 || logcmp_wakeup_validate_consumer(
	    session->wake_fd) == -1 || shmring_open(&session->ring, &consumer,
	    SHMRING_ROLE_CONSUMER) == -1)
		goto fail;
	if ((attach->ring_size == 16U * 1024 &&
	    shmring_shape(session->ring) != SHMRING_SHAPE_COMPACT_SPSC) ||
	    (attach->ring_size == 64U * 1024 &&
	    shmring_shape(session->ring) != SHMRING_SHAPE_BULK_SPSC)) {
		errno = EPROTO;
		goto fail;
	}
	pthread_mutex_lock(&lock);
	corrupt = corrupt_next_ring;
	corrupt_next_ring = false;
	break_wakeup = break_next_wakeup;
	break_next_wakeup = false;
	attaches++;
	ring_capacity = shmring_capacity(session->ring);
	ring_shape = shmring_shape(session->ring);
	pthread_mutex_unlock(&lock);
	if (corrupt) {
		tail = mmap(NULL, sizeof(*tail), PROT_READ | PROT_WRITE, MAP_SHARED,
		    consumer.tail_fd, 0);
		if (tail == MAP_FAILED)
			goto fail;
		*tail = 1;
		munmap(tail, sizeof(*tail));
	}
	if (break_wakeup) {
		close(session->wake_fd);
		session->wake_fd = -1;
	}
	shmring_fds_close(&consumer);
	return (0);
fail:
	error = errno != 0 ? errno : EPROTO;
	shmring_close(session->ring);
	session->ring = NULL;
	shmring_fds_close(&consumer);
	if (session->wake_fd >= 0) {
		close(session->wake_fd);
		session->wake_fd = -1;
	}
	return (errno = error, -1);
}

static int
drain_ring(struct service_session *session)
{
	uint8_t record[LOGCMP_MAX_RECORD];
	ssize_t length;

	if (session->ring == NULL)
		return (errno = ENOTCONN, -1);
	if (logcmp_wakeup_drain(session->wake_fd) == -1)
		return (-1);
	for (;;) {
		length = shmring_read_record(session->ring, record, sizeof(record));
		if (length == -1)
			return (errno == EAGAIN ? 0 : -1);
		if (logcmp_validate_record((const void *)record, (size_t)length) == -1)
			return (-1);
		pthread_mutex_lock(&lock);
		inspect_record_locked((const void *)record);
		writes++;
		pthread_mutex_unlock(&lock);
	}
}

int
service_session_fail(struct service_session *session __unused, int error)
{

	errno = error;
	return (error > 0 && error <= ELAST ? 0 : -1);
}

int
service_session_call(struct service_session *session,
    const struct service_message *outgoing, struct service_reply *reply,
    const struct service_call_options *options __unused)
{
	union {
		max_align_t align;
		uint8_t bytes[LOGCMP_MAX_MESSAGE];
	} storage;
	struct logcmp_hello_reply *hello;
	struct logcmp_query_reply *query_reply;
	struct logcmp_record *record;
	const struct logcmp_query_request *query_request;
	struct logcmp_stats *stats;
	const struct logcmp_msg *request;
	struct logcmp_msg *response;
	enum fake_service_fault fault;
	int failure, operation_error;
	bool use_ring;
	size_t length;

	if (session == NULL || outgoing == NULL || reply == NULL ||
	    outgoing->data == NULL || outgoing->length < sizeof(*request)) {
		errno = EINVAL;
		return (-1);
	}
	request = outgoing->data;
	pthread_mutex_lock(&lock);
	concurrent++;
	if (concurrent > max_concurrent)
		max_concurrent = concurrent;
	failure = request->opcode == LOGCMP_OP_WRITE ? fail_write_error : 0;
	if (request->opcode == LOGCMP_OP_ATTACH && fail_attach_error != 0) {
		failure = fail_attach_error;
		fail_attach_error = 0;
	}
	if (request->opcode == fail_opcode && fail_operation_error != 0) {
		failure = fail_operation_error;
		fail_opcode = 0;
		fail_operation_error = 0;
	}
	fault = next_fault;
	use_ring = ring_enabled;
	next_fault = FAKE_SERVICE_FAULT_NONE;
	if (failure != 0)
		fail_write_error = 0;
	else if (request->opcode == LOGCMP_OP_WRITE) {
		inspect_record_locked((const void *)(request + 1));
		writes++;
	}
	pthread_mutex_unlock(&lock);
	if (fault == FAKE_SERVICE_FAULT_DELAY)
		usleep(50000);
	else if (request->opcode != LOGCMP_OP_HELLO)
		usleep(30000);
	if (failure != 0 || fault == FAKE_SERVICE_FAULT_TIMEOUT) {
		pthread_mutex_lock(&lock);
		concurrent--;
		pthread_mutex_unlock(&lock);
		errno = failure != 0 ? failure : ETIMEDOUT;
		return (-1);
	}
	memset(&storage, 0, sizeof(storage));
	response = (void *)storage.bytes;
	if (logcmp_message_init_reply(response, request, 0) == -1)
		return (-1);
	length = sizeof(*response);
	if (request->opcode == LOGCMP_OP_HELLO) {
		hello = (void *)(response + 1);
		hello->version = LOGCMP_ABI_VERSION;
		hello->features = LOGCMP_FEATURE_INLINE |
		    LOGCMP_FEATURE_TYPED_RECORDS | LOGCMP_FEATURE_PRIVACY |
		    LOGCMP_FEATURE_TRACE_CONTEXT | LOGCMP_FEATURE_EDGE_WAKEUP |
		    LOGCMP_FEATURE_SCOPED_QUERY;
		if (use_ring) {
			hello->features |= LOGCMP_FEATURE_SHM_RING;
			hello->ring_size = 64U * 1024;
		}
		hello->max_record = LOGCMP_MAX_RECORD;
		hello->max_text = LOGCMP_MAX_TEXT;
		hello->max_fields = LOGCMP_MAX_FIELDS;
		length += sizeof(*hello);
		if (fault == FAKE_SERVICE_FAULT_INVALID_HELLO)
			hello->features = 0;
	} else if (request->opcode == LOGCMP_OP_ATTACH) {
		operation_error = attach_ring(session, outgoing) == -1 ? errno : 0;
		if (operation_error != 0)
			response->status = -operation_error;
	} else if (request->opcode == LOGCMP_OP_DETACH) {
		operation_error = drain_ring(session) == -1 ? errno : 0;
		if (operation_error != 0)
			response->status = -operation_error;
		else {
			shmring_close(session->ring);
			session->ring = NULL;
			if (session->wake_fd >= 0)
				close(session->wake_fd);
			session->wake_fd = -1;
			pthread_mutex_lock(&lock);
			detaches++;
			ring_capacity = 0;
			ring_shape = 0;
			pthread_mutex_unlock(&lock);
		}
	} else if (request->opcode == LOGCMP_OP_FLUSH && session->ring != NULL) {
		operation_error = drain_ring(session) == -1 ? errno : 0;
		if (operation_error != 0)
			response->status = -operation_error;
	} else if (request->opcode == LOGCMP_OP_STATS) {
		stats = (void *)(response + 1);
		stats->accepted = writes;
		length += sizeof(*stats);
	} else if (request->opcode == LOGCMP_OP_QUERY) {
		static const char subsystem[] = "tests.fake";
		static const char category[] = "query";
		static const char message[] = "stored record";
		uint8_t *cursor;

		query_request = (const void *)(request + 1);
		query_reply = (void *)(response + 1);
		query_reply->cursor.generation = 1;
		query_reply->cursor.offset = query_request->cursor.offset == 0 ?
		    128 : 256;
		length += sizeof(*query_reply);
		if (query_request->cursor.offset == 0) {
			query_reply->result = 1;
			record = (void *)(query_reply + 1);
			record->sequence = 77;
			record->timestamp_ns = 1;
			record->severity = LOGCMP_SEVERITY_INFO;
			record->kind = LOGCMP_KIND_LOG;
			record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
			record->subsystem_length = sizeof(subsystem) - 1;
			record->category_length = sizeof(category) - 1;
			record->message_length = sizeof(message) - 1;
			cursor = (void *)(record + 1);
			memcpy(cursor, subsystem, sizeof(subsystem) - 1);
			cursor += sizeof(subsystem) - 1;
			memcpy(cursor, category, sizeof(category) - 1);
			cursor += sizeof(category) - 1;
			memcpy(cursor, message, sizeof(message) - 1);
			cursor += sizeof(message) - 1;
			query_reply->record_length = cursor - (uint8_t *)record;
			length += query_reply->record_length;
		}
	}
	if (fault == FAKE_SERVICE_FAULT_TRUNCATE)
		length = sizeof(*response) - 1;
	else if (fault == FAKE_SERVICE_FAULT_WRONG_OPCODE)
		response->opcode = request->opcode == LOGCMP_OP_STATS ?
		    LOGCMP_OP_FLUSH : LOGCMP_OP_STATS;
	else if (fault == FAKE_SERVICE_FAULT_STATUS) {
		response->status = -EPERM;
		length = sizeof(*response);
	}
	pthread_mutex_lock(&lock);
	concurrent--;
	pthread_mutex_unlock(&lock);
	if (reply->capacity < length) {
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(reply->data, storage.bytes, length);
	reply->length = length;
	reply->nfds = fault == FAKE_SERVICE_FAULT_ATTACHED_FD ? 1 : 0;
	return (0);
}

int
service_session_receive_event(struct service_session *session __unused,
    struct service_reply *reply __unused,
    const struct service_call_options *options __unused)
{

	errno = ENOTSUP;
	return (-1);
}
