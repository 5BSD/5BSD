/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Scripted system.Log provider for the liblogcmp client tests.  It replaces
 * libservice's service_open(): each call creates a real capability channel
 * served by a bsd.log.v1 server on its own thread, which maps an attached
 * ring and drains it as BSDLog would.  Faults are armed for the next call;
 * malformed replies are written as raw frames on the request's own reply
 * token, and transport failures close the session.  service_budget_timeout()
 * is replaced so an armed timeout costs 300 ms, not the 30 s call deadline.
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

#include <assert.h>
#include <channel.h>
#include <fidl/bsd.log.v1/c/bsd.h>
#include <libservice.h>
#include <logcmp.h>
#include <logcmp_server.h>
#include <shmring.h>

#include "fake_service.h"
#include "logcmp_wakeup.h"

struct service_session {
	struct fidl_bsd_connection *connection;
	unsigned ident;
	struct shmring *ring;
	int wake_fd;
};

int service_open(const char *, int *);
int service_budget_timeout(uint32_t *);

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
static bool legacy_hello;
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
	legacy_hello = false;
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
fake_service_use_legacy_hello(void)
{

	pthread_mutex_lock(&lock);
	legacy_hello = true;
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

static int
attach_ring(struct service_session *session,
    const struct bsd_log_v1_AttachRequest *attach)
{
	int fds[LOGCMP_ATTACH_FD_COUNT] = { attach->config, attach->data,
	    attach->head, attach->tail, attach->wake };
	struct shmring_fds consumer;
	int *slots[] = { &consumer.config_fd, &consumer.data_fd,
	    &consumer.head_fd, &consumer.tail_fd };
	unsigned i;
	bool break_wakeup, corrupt;
	int error;
	uint64_t *tail;

	if (session->ring != NULL)
		return (errno = EPROTO, -1);
	if ((attach->ring_size != 16U * 1024 &&
	    attach->ring_size != 64U * 1024) ||
	    attach->max_record != LOGCMP_MAX_RECORD || attach->generation == 0)
		return (errno = EPROTO, -1);
	memset(&consumer, -1, sizeof(consumer));
	for (i = 0; i < nitems(slots); i++) {
		*slots[i] = fcntl(fds[i], F_DUPFD_CLOEXEC, 0);
		if (*slots[i] == -1)
			goto fail;
	}
	session->wake_fd = fcntl(fds[LOGCMP_ATTACH_FD_WAKE_READ],
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
	if (shmring_consumer_arm(session->ring) == -1)
		goto fail;
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
	int armed;

	if (session->ring == NULL)
		return (errno = ENOTCONN, -1);
	if (logcmp_wakeup_drain(session->wake_fd) == -1)
		return (-1);
	for (;;) {
		length = shmring_read_record(session->ring, record, sizeof(record));
		if (length == -1) {
			if (errno != EAGAIN)
				return (-1);
			armed = shmring_consumer_arm(session->ring);
			if (armed == -1)
				return (-1);
			if (armed == 0)
				return (0);
			continue;
		}
		if (logcmp_validate_record((const void *)record, (size_t)length) == -1)
			return (-1);
		pthread_mutex_lock(&lock);
		inspect_record_locked((const void *)record);
		writes++;
		pthread_mutex_unlock(&lock);
	}
}


/* Sessions whose server has ended (waits briefly for teardown). */
unsigned
fake_service_closed(void)
{
	unsigned value;

	usleep(50000);
	pthread_mutex_lock(&lock);
	value = closed;
	pthread_mutex_unlock(&lock);
	return (value);
}

int
service_budget_timeout(uint32_t *ms)
{
	if (ms == NULL)
		return (errno = EINVAL, -1);
	pthread_mutex_lock(&lock);
	if (next_fault == FAKE_SERVICE_FAULT_TIMEOUT && *ms > 300)
		*ms = 300;
	pthread_mutex_unlock(&lock);
	return (0);
}

/* A raw reply frame on the request's own reply token. */
static void
raw_reply(struct fidl_bsd_request *request, enum fake_service_fault fault)
{
	struct channel_message *native = __DECONST(struct channel_message *,
	    fidl_bsd_request_native(request));
	struct {
		uint32_t txid;
		uint8_t flags[3], magic;
		uint64_t ordinal;
	} header;
	struct channel_outgoing outgoing;
	int fd = -1;

	memcpy(&header, channel_message_data(native), sizeof(header));
	if (fault == FAKE_SERVICE_FAULT_WRONG_OPCODE)
		header.ordinal ^= 1;
	outgoing = (struct channel_outgoing)CHANNEL_OUTGOING_INITIALIZER(
	    &header, fault == FAKE_SERVICE_FAULT_TRUNCATE ? sizeof(header) - 1 :
	    sizeof(header));
	if (fault == FAKE_SERVICE_FAULT_ATTACHED_FD) {
		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		outgoing.fds = &fd;
		outgoing.nfds = 1;
	}
	(void)channel_send_reply(native, &outgoing);
	if (fd >= 0)
		close(fd);
}

/*
 * The scripted outcome of one request: 0 to reply with *errorp (0 or an
 * application errno), 1 when it was answered or left unanswered already,
 * -1 when the session was closed instead.
 */
static int
begin_request(struct service_session *s, struct fidl_bsd_request *request,
    uint16_t opcode, const struct logcmp_record *record, bool interest,
    int *errorp, enum fake_service_fault *faultp, bool *legacyp, bool *ringp)
{
	enum fake_service_fault fault;
	int failure;

	pthread_mutex_lock(&lock);
	concurrent++;
	if (concurrent > max_concurrent)
		max_concurrent = concurrent;
	failure = opcode == LOGCMP_OP_WRITE ? fail_write_error : 0;
	if (opcode == LOGCMP_OP_ATTACH && fail_attach_error != 0) {
		failure = fail_attach_error;
		fail_attach_error = 0;
	}
	if (opcode == fail_opcode && fail_operation_error != 0) {
		failure = fail_operation_error;
		fail_opcode = 0;
		fail_operation_error = 0;
	}
	fault = next_fault;
	*legacyp = legacy_hello;
	*ringp = ring_enabled;
	/* A pre-interest provider refuses the request outright. */
	if (legacy_hello && opcode == LOGCMP_OP_HELLO && interest)
		failure = EPROTO;
	next_fault = FAKE_SERVICE_FAULT_NONE;
	if (failure != 0)
		fail_write_error = 0;
	else if (opcode == LOGCMP_OP_WRITE) {
		inspect_record_locked(record);
		writes++;
	}
	/* Model a committed write whose reply is lost with the connection. */
	if (opcode == LOGCMP_OP_WRITE &&
	    fault == FAKE_SERVICE_FAULT_COMMITTED_RESET)
		failure = ECONNRESET;
	pthread_mutex_unlock(&lock);
	if (fault == FAKE_SERVICE_FAULT_DELAY)
		usleep(50000);
	else if (opcode != LOGCMP_OP_HELLO)
		usleep(30000);
	*faultp = fault;
	*errorp = 0;
	/* Transport failures close the session; the rest are replies. */
	if (failure == ECONNRESET || failure == EPIPE || failure == EPROTO ||
	    failure == ENOTCONN) {
		fidl_bsd_connection_close(s->connection, failure);
		return (-1);
	}
	if (fault == FAKE_SERVICE_FAULT_TIMEOUT)
		return (1);
	if (fault == FAKE_SERVICE_FAULT_TRUNCATE ||
	    fault == FAKE_SERVICE_FAULT_WRONG_OPCODE ||
	    fault == FAKE_SERVICE_FAULT_ATTACHED_FD) {
		raw_reply(request, fault);
		return (1);
	}
	*errorp = fault == FAKE_SERVICE_FAULT_STATUS ? EPERM : failure;
	return (0);
}

static void
end_request(void)
{
	pthread_mutex_lock(&lock);
	concurrent--;
	pthread_mutex_unlock(&lock);
}

static void
on_info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct bsd_log_v1_ProtocolInfo v = { LOGCMP_WIRE_VERSION };
	(void)x;
	(void)e;
	assert(bsd_log_v1_Log_GetProtocolInfo_reply(c, r, &v) == 0);
}

static void
on_hello(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_log_v1_HelloRequest *q)
{
	struct bsd_log_v1_Limits v = { 0 };
	enum fake_service_fault fault;
	bool legacy, ring;
	int error;

	if (begin_request(x, r, LOGCMP_OP_HELLO, NULL,
	    (q->features & LOGCMP_FEATURE_INTEREST) != 0, &error, &fault,
	    &legacy, &ring) == 0) {
		v.features = LOGCMP_FEATURE_INLINE |
		    LOGCMP_FEATURE_TYPED_RECORDS | LOGCMP_FEATURE_PRIVACY |
		    LOGCMP_FEATURE_TRACE_CONTEXT | LOGCMP_FEATURE_EDGE_WAKEUP |
		    LOGCMP_FEATURE_SCOPED_QUERY;
		if (!legacy)
			v.features |= LOGCMP_FEATURE_INTEREST;
		if (ring) {
			v.features |= LOGCMP_FEATURE_SHM_RING;
			v.ring_size = 64U * 1024;
		}
		v.max_record = LOGCMP_MAX_RECORD;
		v.max_text = LOGCMP_MAX_TEXT;
		v.max_fields = LOGCMP_MAX_FIELDS;
		v.minimum_severity = legacy ? 0 : LOGCMP_SEVERITY_INFO;
		if (fault == FAKE_SERVICE_FAULT_INVALID_HELLO)
			v.features = 0;
		(void)bsd_log_v1_Log_Hello_reply(c, r, &v);
	}
	end_request();
}

#define	EMPTY_RESULT(method, error) {					\
	.tag = (error) != 0 ? bsd_log_v1_Log_##method##_Result_err_tag :	\
	    bsd_log_v1_Log_##method##_Result_response_tag,		\
	.value.err = (uint32_t)(error) }

static void
on_attach(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_log_v1_AttachRequest *q)
{
	enum fake_service_fault fault;
	bool legacy, ring;
	int error;

	if (begin_request(x, r, LOGCMP_OP_ATTACH, NULL, false, &error, &fault,
	    &legacy, &ring) == 0) {
		if (error == 0)
			error = attach_ring(x, q) == -1 ? errno : 0;
		/*
		 * Close the received descriptors before replying, as the
		 * provider does: attach_ring() keeps duplicates, and a broken
		 * wakeup must be broken when the client sees the reply.
		 */
		int *received[] = { &q->config, &q->data, &q->head, &q->tail,
		    &q->wake };
		for (size_t i = 0; i < nitems(received); i++) {
			int fd = fidl_bsd_take_fd(received[i]);

			if (fd >= 0)
				close(fd);
		}
		struct bsd_log_v1_Log_Attach_Result v =
		    EMPTY_RESULT(Attach, error);
		(void)bsd_log_v1_Log_Attach_reply(c, r, &v);
	}
	end_request();
}

static void
on_write(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_log_v1_Record *q)
{
	enum fake_service_fault fault;
	bool legacy, ring;
	int error;

	if (q->record_size < sizeof(struct logcmp_record) ||
	    logcmp_validate_record((const void *)q->record,
	    q->record_size) == -1) {
		fidl_bsd_connection_close(c, EPROTO);
		return;
	}
	if (begin_request(x, r, LOGCMP_OP_WRITE, (const void *)q->record,
	    false, &error, &fault, &legacy, &ring) == 0) {
		struct bsd_log_v1_Log_Write_Result v = EMPTY_RESULT(Write, error);
		(void)bsd_log_v1_Log_Write_reply(c, r, &v);
	}
	end_request();
}

static void
on_flush(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct service_session *s = x;
	enum fake_service_fault fault;
	bool legacy, ring;
	int error;
	(void)e;

	if (begin_request(s, r, LOGCMP_OP_FLUSH, NULL, false, &error, &fault,
	    &legacy, &ring) == 0) {
		if (error == 0 && s->ring != NULL)
			error = drain_ring(s) == -1 ? errno : 0;
		struct bsd_log_v1_Log_Flush_Result v = EMPTY_RESULT(Flush, error);
		(void)bsd_log_v1_Log_Flush_reply(c, r, &v);
	}
	end_request();
}

static void
on_detach(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct service_session *s = x;
	enum fake_service_fault fault;
	bool legacy, ring;
	int error;
	(void)e;

	if (begin_request(s, r, LOGCMP_OP_DETACH, NULL, false, &error, &fault,
	    &legacy, &ring) == 0) {
		if (error == 0)
			error = drain_ring(s) == -1 ? errno : 0;
		if (error == 0) {
			shmring_close(s->ring);
			s->ring = NULL;
			if (s->wake_fd >= 0)
				close(s->wake_fd);
			s->wake_fd = -1;
			pthread_mutex_lock(&lock);
			detaches++;
			ring_capacity = 0;
			ring_shape = 0;
			pthread_mutex_unlock(&lock);
		}
		struct bsd_log_v1_Log_Detach_Result v = EMPTY_RESULT(Detach, error);
		(void)bsd_log_v1_Log_Detach_reply(c, r, &v);
	}
	end_request();
}

static void
on_stats(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct bsd_log_v1_Stats v;
	enum fake_service_fault fault;
	bool legacy, ring;
	int error;
	(void)e;

	if (begin_request(x, r, LOGCMP_OP_STATS, NULL, false, &error, &fault,
	    &legacy, &ring) == 0) {
		/* GetStats has no error result: a refusal ends the session. */
		if (error != 0)
			fidl_bsd_connection_close(c, EPROTO);
		else {
			memset(&v, 0, sizeof(v));
			pthread_mutex_lock(&lock);
			v.accepted = writes;
			pthread_mutex_unlock(&lock);
			(void)bsd_log_v1_Log_GetStats_reply(c, r, &v);
		}
	}
	end_request();
}

static void
on_query(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_log_v1_QueryRequest *q)
{
	static const char subsystem[] = "tests.fake";
	static const char category[] = "query";
	static const char message[] = "stored record";
	uint8_t storage[LOGCMP_MAX_RECORD];
	struct logcmp_record *record = (void *)storage;
	struct bsd_log_v1_Log_Query_Result v = {
		.tag = bsd_log_v1_Log_Query_Result_response_tag
	};
	enum fake_service_fault fault;
	bool legacy, ring;
	uint8_t *cursor;
	int error;

	if (begin_request(x, r, LOGCMP_OP_QUERY, NULL, false, &error, &fault,
	    &legacy, &ring) == 0) {
		v.value.response.generation = 1;
		v.value.response.offset = q->offset == 0 ? 128 : 256;
		if (q->offset == 0) {
			memset(storage, 0, sizeof(storage));
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
			v.value.response.found = true;
			v.value.response.record = storage;
			v.value.response.record_size = cursor - storage;
		}
		if (error != 0) {
			v.tag = bsd_log_v1_Log_Query_Result_err_tag;
			v.value.err = (uint32_t)error;
		}
		(void)bsd_log_v1_Log_Query_reply(c, r, &v);
	}
	end_request();
}

static void
on_notify(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	(void)x;
	(void)c;
	(void)r;
	(void)e;
}

static void *
serve(void *argument)
{
	static const struct bsd_log_v1_Log_server handlers = {
		.GetProtocolInfo = on_info,
		.Hello = on_hello,
		.Attach = on_attach,
		.Write = on_write,
		.Flush = on_flush,
		.GetStats = on_stats,
		.Detach = on_detach,
		.Query = on_query,
		.Notify = on_notify
	};
	struct service_session *s = argument;

	assert(bsd_log_v1_Log_bind(s->connection, &handlers, s) == 0);
	while (fidl_bsd_connection_poll(s->connection, 10000) == 0)
		;
	fidl_bsd_connection_destroy(s->connection);
	shmring_close(s->ring);
	if (s->wake_fd >= 0)
		close(s->wake_fd);
	free(s);
	pthread_mutex_lock(&lock);
	closed++;
	pthread_mutex_unlock(&lock);
	return (NULL);
}

int
service_open(const char *name, int *fdp)
{
	struct service_session *s;
	pthread_t thread;
	int ends[2];

	if (name == NULL || strcmp(name, LOGCMP_INTERFACE) != 0 || fdp == NULL)
		return (errno = EINVAL, -1);
	if (mac_capability_channel_create(ends) != 0)
		return (-1);
	s = calloc(1, sizeof(*s));
	assert(s != NULL);
	s->wake_fd = -1;
	assert(fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER,
	    &s->connection) == 0);
	pthread_mutex_lock(&lock);
	s->ident = ++created;
	pthread_mutex_unlock(&lock);
	assert(pthread_create(&thread, NULL, serve, s) == 0);
	assert(pthread_detach(thread) == 0);
	*fdp = ends[0];
	return (0);
}
