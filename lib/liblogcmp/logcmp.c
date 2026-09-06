/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <libservice.h>
#include <shmring.h>

#include "logcmp.h"
#include "logcmp_server.h"
#include "logcmp_probes.h"
#include "logcmp_wakeup.h"

union logcmp_buffer {
	max_align_t align;
	struct {
		struct logcmp_msg msg;
		uint8_t payload[LOGCMP_MAX_MESSAGE - sizeof(struct logcmp_msg)];
	} wire;
};

struct logcmp_client {
	struct service_session	*channel;
	pid_t			owner;
	struct shmring		*ring;
	pthread_mutex_t		lock;
	uint32_t		references;
	uint64_t		sequence;
	uint64_t		dropped;
	uint64_t		dropped_by_severity[24];
	uint64_t		unreported_dropped;
	uint64_t		ring_generation;
	size_t			inline_bytes;
	uint32_t		inline_records;
	uint32_t		ring_shape;
	int			 wake_fd;
	struct logcmp_hello_reply limits;
};

#define	LOGCMP_COMPACT_RING_SIZE	(16U * 1024U)
#define	LOGCMP_INLINE_RECORD_THRESHOLD	8U
#define	LOGCMP_INLINE_BYTE_THRESHOLD	(8U * 1024U)

struct logcmp_logger {
	struct logcmp_client *client;
	pid_t		 owner;
	size_t		 subsystem_length;
	size_t		 category_length;
	char		 subsystem[LOGCMP_MAX_SUBSYSTEM + 1];
	char		 category[LOGCMP_MAX_CATEGORY + 1];
};

static pthread_mutex_t logcmp_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t logcmp_registry_ready = PTHREAD_COND_INITIALIZER;
static pthread_once_t logcmp_atfork_once = PTHREAD_ONCE_INIT;
static struct logcmp_client *logcmp_process_client;
static int logcmp_atfork_error;
static bool logcmp_initializing;

static void logcmp_atfork_prepare(void) __no_lock_analysis;
static void logcmp_atfork_parent(void) __no_lock_analysis;
static void logcmp_atfork_child(void) __no_lock_analysis;
static int logcmp_registry_acquire(void) __no_lock_analysis;
static void logcmp_registry_release(void) __no_lock_analysis;
static void client_disconnect(struct logcmp_client *);
static int client_attach_ring(struct logcmp_client *, size_t, uint32_t);
static int client_promote_ring(struct logcmp_client *);

static void
logcmp_atfork_prepare(void)
{

	(void)pthread_mutex_lock(&logcmp_registry_lock);
}

static void
logcmp_atfork_parent(void)
{

	(void)pthread_mutex_unlock(&logcmp_registry_lock);
}

static void
logcmp_atfork_child(void)
{

	/*
	 * Component channels are close-on-fork authorities.  Do not let the
	 * child reuse parent bookkeeping even on kernels that report closure
	 * lazily; a later open must resolve its own serviced authority.
	 */
	logcmp_process_client = NULL;
	logcmp_initializing = false;
	(void)pthread_mutex_unlock(&logcmp_registry_lock);
}

static void
logcmp_atfork_init(void)
{

	logcmp_atfork_error = pthread_atfork(logcmp_atfork_prepare,
	    logcmp_atfork_parent, logcmp_atfork_child);
}

static int
logcmp_registry_acquire(void)
{
	int error;

	error = pthread_once(&logcmp_atfork_once, logcmp_atfork_init);
	if (error == 0)
		error = logcmp_atfork_error;
	if (error == 0)
		error = pthread_mutex_lock(&logcmp_registry_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

static void
logcmp_registry_release(void)
{

	(void)pthread_mutex_unlock(&logcmp_registry_lock);
}

static bool
valid_text(const void *data, size_t length, bool allow_empty)
{
	const uint8_t *bytes;
	size_t i;

	if ((!allow_empty && length == 0) || (length != 0 && data == NULL))
		return (false);
	bytes = data;
	for (i = 0; i < length; i++)
		if (bytes[i] == '\0' || bytes[i] == 0x7f || bytes[i] < 0x20)
			return (false);
	return (true);
}

static bool
valid_identifier(const void *data, size_t length, size_t maximum)
{
	const unsigned char *name;
	size_t i;

	if (length == 0 || length > maximum || !valid_text(data, length, false))
		return (false);
	name = data;
	if (!((name[0] >= 'a' && name[0] <= 'z') ||
	    (name[0] >= 'A' && name[0] <= 'Z')) ||
	    !((name[length - 1] >= 'a' && name[length - 1] <= 'z') ||
	    (name[length - 1] >= 'A' && name[length - 1] <= 'Z') ||
	    (name[length - 1] >= '0' && name[length - 1] <= '9')))
		return (false);
	for (i = 0; i < length; i++)
		if (!((name[i] >= 'a' && name[i] <= 'z') ||
		    (name[i] >= 'A' && name[i] <= 'Z') ||
		    (i != 0 && name[i] >= '0' && name[i] <= '9') ||
		    name[i] == '.' || name[i] == '_' || name[i] == '-'))
			return (false);
	return (true);
}

static bool
all_zero(const uint8_t *bytes, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++)
		if (bytes[i] != 0)
			return (false);
	return (true);
}

int
logcmp_validate_record(const struct logcmp_record *record, size_t length)
{
	struct logcmp_attribute_wire attribute_storage;
	const struct logcmp_attribute_wire *attribute;
	const uint8_t *attribute_keys[LOGCMP_MAX_ATTRIBUTES];
	uint16_t attribute_key_lengths[LOGCMP_MAX_ATTRIBUTES];
	const uint8_t *cursor, *end;
	size_t payload, redacted_length, i, j;

	if (record == NULL || length < sizeof(*record) ||
	    length > LOGCMP_MAX_RECORD ||
	    record->sequence == 0 || record->timestamp_ns == 0 ||
	    record->severity < 1 || record->severity > 24 ||
	    record->kind < LOGCMP_KIND_LOG ||
	    record->kind > LOGCMP_KIND_SIGNPOST_POINT ||
	    (record->flags & ~LOGCMP_RECORD_F_MASK) != 0 ||
	    record->message_privacy < LOGCMP_PRIVACY_PUBLIC ||
	    record->message_privacy > LOGCMP_PRIVACY_PRIVATE_HASH ||
	    record->subsystem_length == 0 ||
	    record->subsystem_length > LOGCMP_MAX_SUBSYSTEM ||
	    record->category_length == 0 ||
	    record->category_length > LOGCMP_MAX_CATEGORY ||
	    record->event_name_length > LOGCMP_MAX_EVENT_NAME ||
	    record->attribute_count > LOGCMP_MAX_ATTRIBUTES ||
	    record->message_length == 0 ||
	    record->message_length > LOGCMP_MAX_TEXT ||
	    record->attributes_length > LOGCMP_MAX_FIELDS ||
	    (record->kind != LOGCMP_KIND_LOG &&
	    record->event_name_length == 0) ||
	    (record->kind >= LOGCMP_KIND_SIGNPOST_BEGIN &&
	    record->signpost_id == 0) ||
	    (!all_zero(record->span_id, sizeof(record->span_id)) &&
	    all_zero(record->trace_id, sizeof(record->trace_id)))) {
		errno = EPROTO;
		return (-1);
	}
	payload = (size_t)record->subsystem_length + record->category_length +
	    record->event_name_length + record->message_length +
	    record->attributes_length;
	if (payload != length - sizeof(*record)) {
		errno = EPROTO;
		return (-1);
	}
	redacted_length = sizeof(*record) + record->subsystem_length +
	    record->category_length + record->event_name_length +
	    (record->message_privacy == LOGCMP_PRIVACY_PUBLIC ?
	    record->message_length : record->message_privacy ==
	    LOGCMP_PRIVACY_PRIVATE_HASH ? LOGCMP_PRIVATE_HASH_LENGTH :
	    LOGCMP_PRIVATE_REDACTED_LENGTH);
	cursor = (const void *)(record + 1);
	if (!valid_identifier(cursor, record->subsystem_length,
	    LOGCMP_MAX_SUBSYSTEM))
		goto invalid;
	cursor += record->subsystem_length;
	if (!valid_identifier(cursor, record->category_length,
	    LOGCMP_MAX_CATEGORY))
		goto invalid;
	cursor += record->category_length;
	if (record->event_name_length != 0 && !valid_identifier(cursor,
	    record->event_name_length, LOGCMP_MAX_EVENT_NAME))
		goto invalid;
	cursor += record->event_name_length;
	if (!valid_text(cursor, record->message_length, false))
		goto invalid;
	cursor += record->message_length;
	end = cursor + record->attributes_length;
	for (i = 0; i < record->attribute_count; i++) {
		if ((size_t)(end - cursor) < sizeof(*attribute))
			goto invalid;
		memcpy(&attribute_storage, cursor, sizeof(attribute_storage));
		attribute = &attribute_storage;
		cursor += sizeof(*attribute);
		if (attribute->key_length == 0 ||
		    attribute->key_length > LOGCMP_MAX_ATTRIBUTE_KEY ||
		    attribute->value_length > LOGCMP_MAX_ATTRIBUTE_VALUE ||
		    attribute->type < LOGCMP_ATTR_STRING ||
		    attribute->type > LOGCMP_ATTR_BOOL ||
		    attribute->privacy < LOGCMP_PRIVACY_PUBLIC ||
		    attribute->privacy > LOGCMP_PRIVACY_PRIVATE_HASH ||
		    (size_t)(end - cursor) < (size_t)attribute->key_length +
		    attribute->value_length || cursor[0] == '_' ||
		    !valid_identifier(cursor, attribute->key_length,
		    LOGCMP_MAX_ATTRIBUTE_KEY))
			goto invalid;
		for (j = 0; j < i; j++)
			if (attribute_key_lengths[j] == attribute->key_length &&
			    memcmp(attribute_keys[j], cursor,
			    attribute->key_length) == 0)
				goto invalid;
		attribute_keys[i] = cursor;
		attribute_key_lengths[i] = attribute->key_length;
		redacted_length += sizeof(*attribute) + attribute->key_length +
		    (attribute->privacy == LOGCMP_PRIVACY_PUBLIC ?
		    attribute->value_length : attribute->privacy ==
		    LOGCMP_PRIVACY_PRIVATE_HASH ? LOGCMP_PRIVATE_HASH_LENGTH :
		    LOGCMP_PRIVATE_REDACTED_LENGTH);
		cursor += attribute->key_length;
		if (((attribute->type == LOGCMP_ATTR_INT64 ||
		    attribute->type == LOGCMP_ATTR_UINT64 ||
		    attribute->type == LOGCMP_ATTR_DOUBLE) &&
		    attribute->value_length != 8) ||
		    (attribute->type == LOGCMP_ATTR_BOOL &&
		    (attribute->value_length != 1 || cursor[0] > 1)) ||
		    ((attribute->type == LOGCMP_ATTR_STRING) &&
		    !valid_text(cursor, attribute->value_length, true)))
			goto invalid;
		cursor += attribute->value_length;
	}
	if (cursor != end || redacted_length > LOGCMP_MAX_RECORD)
		goto invalid;
	return (0);

invalid:
	errno = EPROTO;
	return (-1);
}

static int
logcmp_header_validate(const struct logcmp_msg *msg, size_t length,
    enum logcmp_message_role role)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > LOGCMP_MAX_MESSAGE ||
	    (role != LOGCMP_MESSAGE_REQUEST &&
	    role != LOGCMP_MESSAGE_REPLY && role != LOGCMP_MESSAGE_EVENT) ||
	    msg->magic != LOGCMP_MAGIC ||
	    msg->version != LOGCMP_ABI_VERSION ||
	    msg->opcode < LOGCMP_OP_HELLO || msg->opcode > LOGCMP_OP_QUERY ||
	    (msg->flags & ~LOGCMP_MSG_F_MASK) != 0 ||
	    (role != LOGCMP_MESSAGE_REPLY && msg->status != 0) ||
	    (role == LOGCMP_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
logcmp_message_init(struct logcmp_msg *msg, uint16_t opcode, uint32_t flags)
{

	if (msg == NULL || opcode < LOGCMP_OP_HELLO ||
	    opcode > LOGCMP_OP_QUERY || (flags & ~LOGCMP_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = LOGCMP_MAGIC;
	msg->version = LOGCMP_ABI_VERSION;
	msg->opcode = opcode;
	msg->flags = flags;
	return (0);
}

int
logcmp_message_init_reply(struct logcmp_msg *reply,
    const struct logcmp_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    logcmp_header_validate(request, sizeof(*request),
	    LOGCMP_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = LOGCMP_MAGIC;
	reply->version = LOGCMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
logcmp_validate_message(const struct logcmp_msg *msg, size_t length,
    enum logcmp_message_role role)
{
	size_t payload;

	if (logcmp_header_validate(msg, length, role) == -1)
		return (-1);
	payload = length - sizeof(*msg);
	if (role == LOGCMP_MESSAGE_REPLY) {
		if (msg->status != 0 && payload != 0) {
			errno = EPROTO;
			return (-1);
		}
		if (msg->status != 0)
			return (0);
		switch (msg->opcode) {
		case LOGCMP_OP_HELLO: {
			const struct logcmp_hello_reply *hello;

			if (payload != sizeof(struct logcmp_hello_reply))
				goto invalid;
			hello = (const void *)(msg + 1);
			if (hello->version != LOGCMP_ABI_VERSION ||
		    (hello->features & ~(LOGCMP_FEATURE_INLINE |
		    LOGCMP_FEATURE_SHM_RING | LOGCMP_FEATURE_SYSLOG |
			    LOGCMP_FEATURE_TYPED_RECORDS | LOGCMP_FEATURE_PRIVACY |
		    LOGCMP_FEATURE_TRACE_CONTEXT |
		    LOGCMP_FEATURE_EDGE_WAKEUP |
		    LOGCMP_FEATURE_SCOPED_QUERY)) != 0 ||
			    hello->max_record == 0 ||
			    hello->max_record > LOGCMP_MAX_RECORD ||
			    hello->max_text == 0 ||
			    hello->max_text > LOGCMP_MAX_TEXT ||
			    hello->max_fields > LOGCMP_MAX_FIELDS)
				goto invalid;
			break;
		}
		case LOGCMP_OP_STATS:
			if (payload != sizeof(struct logcmp_stats))
				goto invalid;
			break;
		case LOGCMP_OP_QUERY: {
			const struct logcmp_query_reply *query;
			const struct logcmp_record *record;

			if (payload < sizeof(*query))
				goto invalid;
			query = (const void *)(msg + 1);
			if (query->result > 1 || query->record_length > LOGCMP_MAX_RECORD ||
			    payload != sizeof(*query) + query->record_length ||
			    (query->result == 0 && query->record_length != 0) ||
			    (query->result == 1 &&
			    query->record_length < sizeof(*record)))
				goto invalid;
			if (query->result == 1) {
				record = (const void *)(query + 1);
				if (logcmp_validate_record(record,
				    query->record_length) == -1)
					return (-1);
			}
			break;
		}
		default:
			if (payload != 0)
				goto invalid;
		}
		return (0);
	}
	if (role == LOGCMP_MESSAGE_EVENT) {
		if (msg->opcode != LOGCMP_OP_NOTIFY || msg->status != 0 ||
		    payload != 0)
			goto invalid;
		return (0);
	}
	if (msg->status != 0)
		goto invalid;
	if (msg->opcode == LOGCMP_OP_NOTIFY)
		goto invalid;
	switch (msg->opcode) {
	case LOGCMP_OP_HELLO: {
		const struct logcmp_hello *hello;

		if (payload != sizeof(struct logcmp_hello))
			goto invalid;
		hello = (const void *)(msg + 1);
		if (hello->reserved != 0 ||
		    hello->min_version > hello->max_version ||
		    hello->min_version > LOGCMP_ABI_VERSION ||
		    hello->max_version < LOGCMP_ABI_VERSION ||
		    (hello->features & ~(LOGCMP_FEATURE_INLINE |
		    LOGCMP_FEATURE_SHM_RING | LOGCMP_FEATURE_SYSLOG |
		    LOGCMP_FEATURE_TYPED_RECORDS | LOGCMP_FEATURE_PRIVACY |
		    LOGCMP_FEATURE_TRACE_CONTEXT |
		    LOGCMP_FEATURE_EDGE_WAKEUP |
		    LOGCMP_FEATURE_SCOPED_QUERY)) != 0)
			goto invalid;
		break;
	}
	case LOGCMP_OP_ATTACH:
		if (payload != sizeof(struct logcmp_attach_request))
			goto invalid;
		break;
	case LOGCMP_OP_WRITE:
		if (payload < sizeof(struct logcmp_record) ||
		    logcmp_validate_record((const void *)(msg + 1), payload) == -1)
			return (-1);
		break;
	case LOGCMP_OP_FLUSH:
	case LOGCMP_OP_STATS:
	case LOGCMP_OP_DETACH:
		if (payload != 0)
			goto invalid;
		break;
	case LOGCMP_OP_QUERY: {
		const struct logcmp_query_request *query;

		if (payload != sizeof(*query))
			goto invalid;
		query = (const void *)(msg + 1);
		if (query->reserved != 0 ||
		    query->minimum_severity > LOGCMP_SEVERITY_FATAL + 3 ||
		    (query->cursor.generation == 0 && query->cursor.offset != 0))
			goto invalid;
		break;
	}
	}
	return (0);

invalid:
	errno = EPROTO;
	return (-1);
}

int
logcmp_validate_fds(const struct logcmp_msg *msg, size_t nfds,
    enum logcmp_message_role role)
{
	size_t expected;

	if (msg == NULL) {
		errno = EINVAL;
		return (-1);
	}
	expected = role == LOGCMP_MESSAGE_REQUEST &&
	    msg->opcode == LOGCMP_OP_ATTACH ? LOGCMP_ATTACH_FD_COUNT : 0;
	if (nfds != expected) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int
logcmp_open_channel(void)
{
	int fd, error;

	fd = -1;
	error = service_open(LOGCMP_INTERFACE, &fd) == -1 ? errno : 0;
	if (error != 0)
		fd = -1;
	LOGCMP_PROBE_OPEN(__DECONST(char *, LOGCMP_INTERFACE), error);
	errno = error;
	return (fd);
}

static int
rpc(struct logcmp_client *client, uint16_t opcode, const void *payload,
    size_t payload_length, const int *fds, size_t nfds, union logcmp_buffer *out)
{
	union logcmp_buffer request;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct logcmp_msg *msg;
	size_t received;
	size_t request_length;
	uint16_t received_opcode;

	if (payload_length > sizeof(request.wire.payload)) {
		errno = EMSGSIZE;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	msg = &request.wire.msg;
	if (logcmp_message_init(msg, opcode, 0) == -1)
		return (-1);
	if (payload_length != 0)
		memcpy(msg + 1, payload, payload_length);
	request_length = sizeof(*msg) + payload_length;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = msg;
	outgoing.length = request_length;
	outgoing.fds = fds;
	outgoing.nfds = nfds;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = out;
	incoming.capacity = sizeof(*out);
	options.timeout_ms = 30000;
	if (service_session_call(client->channel, &outgoing, &incoming,
	    &options) == -1) {
		LOGCMP_PROBE_SEND(opcode, request_length, nfds, errno);
		return (-1);
	}
	LOGCMP_PROBE_SEND(opcode, request_length, nfds, 0);
	received = incoming.length;
	msg = &out->wire.msg;
	received_opcode = received >= sizeof(*msg) ? msg->opcode : 0;
	LOGCMP_PROBE_RECEIVE(received_opcode, received, incoming.nfds, 0);
	if (incoming.nfds != 0 ||
	    logcmp_validate_message(msg, received,
	    LOGCMP_MESSAGE_REPLY) == -1 || msg->opcode != opcode) {
		LOGCMP_PROBE_REJECT(received_opcode, received, EPROTO);
		errno = EPROTO;
		return (-1);
	}
	if (msg->status != 0) {
		LOGCMP_PROBE_REJECT(msg->opcode, received, -msg->status);
		errno = -msg->status;
		return (-1);
	}
	return (0);
}

static bool
connection_unusable(int error)
{

	return (error == ECONNRESET || error == EPIPE || error == ENOTCONN ||
	    error == ESHUTDOWN || error == EPROTO);
}

static int
client_publish_record(struct logcmp_client *client,
    const struct logcmp_record *record, size_t length)
{
	union logcmp_buffer reply;
	int error, result;

	if (client->ring == NULL) {
		result = rpc(client, LOGCMP_OP_WRITE, record, length, NULL, 0,
		    &reply);
		error = errno;
		if (result == -1 && connection_unusable(error))
			client_disconnect(client);
		if (result == 0) {
			client->inline_records++;
			client->inline_bytes += length;
			if ((client->inline_records >=
			    LOGCMP_INLINE_RECORD_THRESHOLD ||
			    client->inline_bytes >= LOGCMP_INLINE_BYTE_THRESHOLD) &&
			    (client->limits.features & LOGCMP_FEATURE_SHM_RING) != 0) {
				size_t capacity;

				capacity = MIN((size_t)client->limits.ring_size,
				    (size_t)LOGCMP_COMPACT_RING_SIZE);
				/* The inline record is committed even if promotion fails. */
				(void)client_attach_ring(client, capacity,
				    SHMRING_SHAPE_COMPACT_SPSC);
			}
			error = 0;
		}
	} else {
		bool was_empty;
		ssize_t readable;

		readable = shmring_readable(client->ring);
		if (readable == -1) {
			result = -1;
			error = errno;
			if (error == EPROTO)
				client_disconnect(client);
			goto done;
		}
		was_empty = readable == 0;
		result = shmring_write_record(client->ring, record, length);
		error = errno;
		if (result == -1 && error == EAGAIN &&
		    client->ring_shape == SHMRING_SHAPE_COMPACT_SPSC &&
		    client->limits.ring_size >= SHMRING_BULK_MIN_CAPACITY &&
		    client_promote_ring(client) == 0) {
			was_empty = true;
			result = shmring_write_record(client->ring, record, length);
			error = errno;
		}
		if (result == 0 && was_empty) {
			if (logcmp_wakeup_signal(client->wake_fd, true) == -1) {
				int wake_error;

				wake_error = errno;
				/*
				 * The record is already committed to shared memory.  A
				 * failed edge cannot retroactively make it retryable: the
				 * provider may consume it through its fallback timer.
				 */
				LOGCMP_PROBE_WAKE(record->sequence, wake_error);
				client_disconnect(client);
				result = 0;
				error = 0;
			} else {
				error = 0;
				LOGCMP_PROBE_WAKE(record->sequence, 0);
			}
		} else if (result == 0) {
			/* The pending edge or fallback timer covers this burst. */
			error = 0;
		} else if (error == EPROTO)
			client_disconnect(client);
	}
done:
	LOGCMP_PROBE_ENQUEUE(record->sequence, length,
	    result == 0 ? 0 : error);
	errno = error;
	return (result);
}

static int
client_promote_ring(struct logcmp_client *client)
{
	union logcmp_buffer reply;
	int error;

	/*
	 * Drain before detaching so committed compact-ring records cannot be
	 * stranded.  The current record has not been committed: promotion is
	 * attempted only after shmring_write_record() returned EAGAIN.
	 */
	if (rpc(client, LOGCMP_OP_FLUSH, NULL, 0, NULL, 0, &reply) == -1) {
		error = errno;
		if (connection_unusable(error))
			client_disconnect(client);
		return (errno = error, -1);
	}
	if (rpc(client, LOGCMP_OP_DETACH, NULL, 0, NULL, 0, &reply) == -1) {
		error = errno;
		/* DETACH may have committed even when its reply was lost. */
		client_disconnect(client);
		return (errno = error, -1);
	}
	shmring_close(client->ring);
	client->ring = NULL;
	client->ring_shape = 0;
	if (client->wake_fd >= 0) {
		close(client->wake_fd);
		client->wake_fd = -1;
	}
	if (client_attach_ring(client, client->limits.ring_size,
	    SHMRING_SHAPE_BULK_SPSC) == 0)
		return (0);
	error = errno;
	/* The old ring was detached; inline transport remains available. */
	errno = error;
	return (-1);
}

static int
client_emit_loss_record(struct logcmp_client *client)
{
	static const char subsystem[] = "system.Log";
	static const char category[] = "delivery";
	static const char event_name[] = "records-dropped";
	static const char message[] = "records were dropped before delivery";
	static const char key[] = "count";
	union logcmp_buffer buffer;
	struct logcmp_attribute_wire attribute;
	struct logcmp_record *record;
	struct timespec now;
	uint8_t *cursor;
	size_t length;
	uint64_t count;

	count = client->unreported_dropped;
	if (count == 0)
		return (0);
	memset(&buffer, 0, sizeof(buffer));
	record = (void *)buffer.wire.payload;
	record->sequence = ++client->sequence;
	if (clock_gettime(CLOCK_REALTIME, &now) == -1)
		return (-1);
	record->timestamp_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
	    (uint64_t)now.tv_nsec;
	record->severity = LOGCMP_SEVERITY_WARN;
	record->kind = LOGCMP_KIND_EVENT;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = sizeof(subsystem) - 1;
	record->category_length = sizeof(category) - 1;
	record->event_name_length = sizeof(event_name) - 1;
	record->attribute_count = 1;
	record->message_length = sizeof(message) - 1;
	record->attributes_length = sizeof(attribute) + sizeof(key) - 1 +
	    sizeof(count);
	cursor = (void *)(record + 1);
	memcpy(cursor, subsystem, sizeof(subsystem) - 1);
	cursor += sizeof(subsystem) - 1;
	memcpy(cursor, category, sizeof(category) - 1);
	cursor += sizeof(category) - 1;
	memcpy(cursor, event_name, sizeof(event_name) - 1);
	cursor += sizeof(event_name) - 1;
	memcpy(cursor, message, sizeof(message) - 1);
	cursor += sizeof(message) - 1;
	memset(&attribute, 0, sizeof(attribute));
	attribute.key_length = sizeof(key) - 1;
	attribute.type = LOGCMP_ATTR_UINT64;
	attribute.privacy = LOGCMP_PRIVACY_PUBLIC;
	attribute.value_length = sizeof(count);
	memcpy(cursor, &attribute, sizeof(attribute));
	cursor += sizeof(attribute);
	memcpy(cursor, key, sizeof(key) - 1);
	cursor += sizeof(key) - 1;
	memcpy(cursor, &count, sizeof(count));
	cursor += sizeof(count);
	length = cursor - (uint8_t *)record;
	if (logcmp_validate_record(record, length) == -1)
		return (-1);
	if (client_publish_record(client, record, length) == -1)
		return (-1);
	client->unreported_dropped = 0;
	return (0);
}

static void
client_disconnect(struct logcmp_client *client)
{

	shmring_close(client->ring);
	client->ring = NULL;
	client->ring_shape = 0;
	if (client->wake_fd >= 0) {
		close(client->wake_fd);
		client->wake_fd = -1;
	}
	if (client->channel != NULL) {
		service_session_close(client->channel);
		client->channel = NULL;
	}
}

static int
client_attach_ring(struct logcmp_client *client, size_t capacity,
    uint32_t shape)
{
	union logcmp_buffer reply;
	struct logcmp_attach_request attach;
	struct shmring_options options = SHMRING_OPTIONS_INITIALIZER(shape,
	    SHMRING_MODE_RECORD, capacity);
	struct shmring_fds producer, consumer;
	int fds[LOGCMP_RING_FDS], error;
	int wake[2];

	if (client == NULL || client->channel == NULL || client->ring != NULL ||
	    capacity < SHMRING_MIN_CAPACITY)
		return (errno = EINVAL, -1);
	memset(fds, -1, sizeof(fds));
	memset(&producer, -1, sizeof(producer));
	memset(&consumer, -1, sizeof(consumer));
	wake[0] = wake[1] = -1;
	options.max_record = client->limits.max_record;
	options.low_watermark = capacity / 4;
	options.high_watermark = capacity * 3 / 4;
	options.generation = ++client->ring_generation;
	if (options.generation == 0)
		options.generation = ++client->ring_generation;
	if (shmring_create_with_options(&options, &producer, &consumer) == -1 ||
	    shmring_open(&client->ring, &producer, SHMRING_ROLE_PRODUCER) == -1 ||
	    logcmp_wakeup_create(wake) == -1)
		goto fail;
	client->wake_fd = wake[LOGCMP_WAKE_PRODUCER];
	wake[LOGCMP_WAKE_PRODUCER] = -1;
	fds[LOGCMP_ATTACH_FD_CONFIG] = consumer.config_fd;
	fds[LOGCMP_ATTACH_FD_DATA] = consumer.data_fd;
	fds[LOGCMP_ATTACH_FD_HEAD] = consumer.head_fd;
	fds[LOGCMP_ATTACH_FD_TAIL] = consumer.tail_fd;
	fds[LOGCMP_ATTACH_FD_WAKE_READ] = wake[LOGCMP_WAKE_CONSUMER];
	memset(&attach, 0, sizeof(attach));
	attach.generation = options.generation;
	attach.ring_size = (uint32_t)capacity;
	attach.max_record = client->limits.max_record;
	if (rpc(client, LOGCMP_OP_ATTACH, &attach, sizeof(attach), fds,
	    nitems(fds), &reply) == -1) {
		/* ATTACH may have committed even when its reply was lost. */
		error = errno;
		service_session_close(client->channel);
		client->channel = NULL;
		errno = error;
		goto fail;
	}
	close(wake[LOGCMP_WAKE_CONSUMER]);
	shmring_fds_close(&producer);
	shmring_fds_close(&consumer);
	client->ring_shape = shape;
	client->inline_records = 0;
	client->inline_bytes = 0;
	LOGCMP_PROBE_RING_ATTACH(shape, capacity, options.generation, 0);
	return (0);

fail:
	error = errno;
	if (wake[0] >= 0)
		close(wake[0]);
	if (wake[1] >= 0)
		close(wake[1]);
	shmring_fds_close(&producer);
	shmring_fds_close(&consumer);
	shmring_close(client->ring);
	client->ring = NULL;
	client->ring_shape = 0;
	if (client->wake_fd >= 0) {
		close(client->wake_fd);
		client->wake_fd = -1;
	}
	LOGCMP_PROBE_RING_ATTACH(shape, capacity, options.generation, error);
	errno = error;
	return (-1);
}

static int
client_establish(struct logcmp_client *client)
{
	union logcmp_buffer reply;
	struct logcmp_hello hello;
	int error, fd;

	client->wake_fd = -1;
	fd = logcmp_open_channel();
	if (fd == -1)
		return (-1);
	if (service_session_create(fd, &client->channel) == -1) {
		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	memset(&hello, 0, sizeof(hello));
	hello.min_version = LOGCMP_ABI_VERSION;
	hello.max_version = LOGCMP_ABI_VERSION;
	hello.features = LOGCMP_FEATURE_INLINE | LOGCMP_FEATURE_SHM_RING |
	    LOGCMP_FEATURE_TYPED_RECORDS | LOGCMP_FEATURE_PRIVACY |
	    LOGCMP_FEATURE_TRACE_CONTEXT | LOGCMP_FEATURE_EDGE_WAKEUP |
	    LOGCMP_FEATURE_SCOPED_QUERY;
	if (rpc(client, LOGCMP_OP_HELLO, &hello, sizeof(hello), NULL, 0,
	    &reply) == -1)
		goto fail;
	memcpy(&client->limits, &reply.wire.msg + 1, sizeof(client->limits));
	if (client->limits.version != LOGCMP_ABI_VERSION ||
	    (client->limits.features & (LOGCMP_FEATURE_SHM_RING |
	    LOGCMP_FEATURE_INLINE)) == 0 ||
	    (client->limits.features & (LOGCMP_FEATURE_TYPED_RECORDS |
	    LOGCMP_FEATURE_PRIVACY | LOGCMP_FEATURE_TRACE_CONTEXT |
	    LOGCMP_FEATURE_EDGE_WAKEUP | LOGCMP_FEATURE_SCOPED_QUERY)) !=
	    (LOGCMP_FEATURE_TYPED_RECORDS | LOGCMP_FEATURE_PRIVACY |
	    LOGCMP_FEATURE_TRACE_CONTEXT | LOGCMP_FEATURE_EDGE_WAKEUP |
	    LOGCMP_FEATURE_SCOPED_QUERY) ||
	    client->limits.max_record == 0 ||
	    client->limits.max_record > LOGCMP_MAX_RECORD) {
		errno = EPROTO;
		goto fail;
	}
	if ((client->limits.features & LOGCMP_FEATURE_SHM_RING) != 0 &&
	    client->limits.ring_size < SHMRING_MIN_CAPACITY) {
		errno = EPROTO;
		goto fail;
	}
	return (0);
fail:
	error = errno;
	client_disconnect(client);
	errno = error;
	return (-1);
}

static int
client_ensure_connected(struct logcmp_client *client)
{
	int error, result;

	if (client->channel != NULL)
		return (0);
	result = client_establish(client);
	error = result == -1 ? errno : 0;
	LOGCMP_PROBE_RECONNECT(error);
	errno = error;
	return (result);
}

int
logcmp_client_open(struct logcmp_client **clientp) __no_lock_analysis
{
	struct logcmp_client *client;
	int error;

	if (clientp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*clientp = NULL;
	if (logcmp_registry_acquire() == -1)
		return (-1);
	while (logcmp_initializing) {
		error = pthread_cond_wait(&logcmp_registry_ready,
		    &logcmp_registry_lock);
		if (error != 0) {
			logcmp_registry_release();
			errno = error;
			return (-1);
		}
	}
	if (logcmp_process_client != NULL) {
		logcmp_process_client->references++;
		*clientp = logcmp_process_client;
		logcmp_registry_release();
		return (0);
	}
	logcmp_initializing = true;
	logcmp_registry_release();
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		goto fail_initializing;
	client->owner = getpid();
	client->wake_fd = -1;
	error = pthread_mutex_init(&client->lock, NULL);
	if (error != 0) {
		errno = error;
		goto fail;
	}
	if (client_establish(client) == -1)
		goto fail_mutex;
	client->sequence = 0;
	client->references = 1;
	if (logcmp_registry_acquire() == -1)
		goto fail_mutex;
	logcmp_process_client = client;
	logcmp_initializing = false;
	*clientp = client;
	(void)pthread_cond_broadcast(&logcmp_registry_ready);
	logcmp_registry_release();
	return (0);
fail_mutex:
	(void)pthread_mutex_destroy(&client->lock);
fail:
	error = errno;
	client_disconnect(client);
	free(client);
fail_initializing:
	error = errno;
	if (logcmp_registry_acquire() == 0) {
		logcmp_initializing = false;
		(void)pthread_cond_broadcast(&logcmp_registry_ready);
		logcmp_registry_release();
	}
	errno = error;
	return (-1);
}

void
logcmp_client_close(struct logcmp_client *client) __no_lock_analysis
{
	union logcmp_buffer reply;
	int error;

	if (client == NULL)
		return;
	if (logcmp_registry_acquire() == -1)
		return;
	if (client != logcmp_process_client || client->references == 0) {
		logcmp_registry_release();
		return;
	}
	if (--client->references != 0) {
		logcmp_registry_release();
		return;
	}
	logcmp_process_client = NULL;
	logcmp_registry_release();
	error = pthread_mutex_lock(&client->lock);
	if (error == 0) {
		if (client->ring != NULL && client->channel != NULL)
			(void)rpc(client, LOGCMP_OP_DETACH, NULL, 0, NULL, 0,
			    &reply);
		client_disconnect(client);
		(void)pthread_mutex_unlock(&client->lock);
	} else
		client_disconnect(client);
	(void)pthread_mutex_destroy(&client->lock);
	free(client);
}

int
logcmp_logger_create(struct logcmp_client *client, const char *subsystem,
    const char *category, struct logcmp_logger **loggerp) __no_lock_analysis
{
	struct logcmp_logger *logger;
	size_t category_length, subsystem_length;

	if (client == NULL || client->owner != getpid() || subsystem == NULL ||
	    category == NULL || loggerp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*loggerp = NULL;
	subsystem_length = strnlen(subsystem, LOGCMP_MAX_SUBSYSTEM + 1);
	category_length = strnlen(category, LOGCMP_MAX_CATEGORY + 1);
	if (!valid_identifier(subsystem, subsystem_length, LOGCMP_MAX_SUBSYSTEM) ||
	    !valid_identifier(category, category_length, LOGCMP_MAX_CATEGORY)) {
		errno = EINVAL;
		return (-1);
	}
	logger = calloc(1, sizeof(*logger));
	if (logger == NULL)
		return (-1);
	if (logcmp_registry_acquire() == -1) {
		free(logger);
		return (-1);
	}
	if (client != logcmp_process_client || client->references == 0) {
		logcmp_registry_release();
		free(logger);
		errno = ENOTCONN;
		return (-1);
	}
	client->references++;
	logcmp_registry_release();
	logger->client = client;
	logger->owner = getpid();
	logger->subsystem_length = subsystem_length;
	logger->category_length = category_length;
	memcpy(logger->subsystem, subsystem, subsystem_length + 1);
	memcpy(logger->category, category, category_length + 1);
	*loggerp = logger;
	return (0);
}

void
logcmp_logger_destroy(struct logcmp_logger *logger)
{

	if (logger == NULL)
		return;
	if (logger->owner == getpid())
		logcmp_client_close(logger->client);
	memset(logger, 0, sizeof(*logger));
	free(logger);
}

int
logcmp_emit(struct logcmp_logger *logger,
    const struct logcmp_emit_options *options) __no_lock_analysis
{
	union logcmp_buffer buffer;
	struct logcmp_attribute_wire wire_attribute;
	struct logcmp_client *client;
	struct logcmp_record *record;
	struct timespec now;
	uint8_t *cursor;
	size_t attributes_length, event_length, length, message_length,
	    redacted_length, i;
	int error, result;

	if (logger == NULL || logger->owner != getpid() || options == NULL ||
	    options->size != sizeof(*options) || options->message == NULL ||
	    options->severity < 1 || options->severity > 24 ||
	    options->kind < LOGCMP_KIND_LOG ||
	    options->kind > LOGCMP_KIND_SIGNPOST_POINT ||
	    options->message_privacy < LOGCMP_PRIVACY_PUBLIC ||
	    options->message_privacy > LOGCMP_PRIVACY_PRIVATE_HASH ||
	    options->flags != 0 || options->nattributes > LOGCMP_MAX_ATTRIBUTES ||
	    (options->nattributes != 0 && options->attributes == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	client = logger->client;
	message_length = strnlen(options->message, LOGCMP_MAX_TEXT + 1);
	event_length = options->event_name != NULL ?
	    strnlen(options->event_name, LOGCMP_MAX_EVENT_NAME + 1) : 0;
	if (!valid_text(options->message, message_length, false) ||
	    (event_length != 0 && !valid_identifier(options->event_name,
	    event_length, LOGCMP_MAX_EVENT_NAME)) ||
	    (options->kind != LOGCMP_KIND_LOG && event_length == 0) ||
	    (options->kind >= LOGCMP_KIND_SIGNPOST_BEGIN &&
	    options->signpost_id == 0)) {
		errno = EINVAL;
		return (-1);
	}
	attributes_length = 0;
	redacted_length = sizeof(struct logcmp_record) +
	    logger->subsystem_length + logger->category_length + event_length +
	    (options->message_privacy == LOGCMP_PRIVACY_PUBLIC ? message_length :
	    options->message_privacy == LOGCMP_PRIVACY_PRIVATE_HASH ?
	    LOGCMP_PRIVATE_HASH_LENGTH : LOGCMP_PRIVATE_REDACTED_LENGTH);
	for (i = 0; i < options->nattributes; i++) {
		const struct logcmp_attribute *attribute = &options->attributes[i];
		size_t key_length;

		if (attribute->size != sizeof(*attribute) ||
		    attribute->key == NULL || attribute->reserved != 0 ||
		    attribute->type < LOGCMP_ATTR_STRING ||
		    attribute->type > LOGCMP_ATTR_BOOL ||
		    attribute->privacy < LOGCMP_PRIVACY_PUBLIC ||
		    attribute->privacy > LOGCMP_PRIVACY_PRIVATE_HASH ||
		    attribute->value_length > LOGCMP_MAX_ATTRIBUTE_VALUE ||
		    (attribute->value_length != 0 && attribute->value == NULL)) {
			errno = EINVAL;
			return (-1);
		}
		key_length = strnlen(attribute->key,
		    LOGCMP_MAX_ATTRIBUTE_KEY + 1);
		if (attribute->key[0] == '_' || !valid_identifier(attribute->key,
		    key_length, LOGCMP_MAX_ATTRIBUTE_KEY) ||
		    ((attribute->type == LOGCMP_ATTR_INT64 ||
		    attribute->type == LOGCMP_ATTR_UINT64 ||
		    attribute->type == LOGCMP_ATTR_DOUBLE) &&
		    attribute->value_length != 8) ||
		    (attribute->type == LOGCMP_ATTR_BOOL &&
		    (attribute->value_length != 1 ||
		    *(const uint8_t *)attribute->value > 1)) ||
		    (attribute->type == LOGCMP_ATTR_STRING &&
		    !valid_text(attribute->value, attribute->value_length, true))) {
			errno = EINVAL;
			return (-1);
		}
		for (size_t j = 0; j < i; j++)
			if (strcmp(options->attributes[j].key,
			    attribute->key) == 0) {
				errno = EINVAL;
				return (-1);
			}
		attributes_length += sizeof(wire_attribute) + key_length +
		    attribute->value_length;
		redacted_length += sizeof(wire_attribute) + key_length +
		    (attribute->privacy == LOGCMP_PRIVACY_PUBLIC ?
		    attribute->value_length : attribute->privacy ==
		    LOGCMP_PRIVACY_PRIVATE_HASH ? LOGCMP_PRIVATE_HASH_LENGTH :
		    LOGCMP_PRIVATE_REDACTED_LENGTH);
	}
	length = sizeof(*record) + logger->subsystem_length +
	    logger->category_length + event_length + message_length +
	    attributes_length;
	error = pthread_mutex_lock(&client->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	if (client_ensure_connected(client) == -1) {
		error = errno;
		result = -1;
		goto out;
	}
	if (attributes_length > client->limits.max_fields ||
	    message_length > client->limits.max_text ||
	    length > client->limits.max_record ||
	    redacted_length > client->limits.max_record) {
		error = EMSGSIZE;
		result = -1;
		goto out;
	}
	if (client_emit_loss_record(client) == -1 && errno != EAGAIN) {
		error = errno;
		result = -1;
		goto out;
	}
	memset(&buffer, 0, sizeof(buffer));
	record = (void *)buffer.wire.payload;
	record->sequence = ++client->sequence;
	record->severity = options->severity;
	record->kind = options->kind;
	record->flags = options->flags;
	record->message_privacy = options->message_privacy;
	record->subsystem_length = logger->subsystem_length;
	record->category_length = logger->category_length;
	record->event_name_length = event_length;
	record->attribute_count = options->nattributes;
	record->message_length = (uint32_t)message_length;
	record->attributes_length = attributes_length;
	record->timestamp_ns = options->timestamp_ns;
	if (record->timestamp_ns == 0) {
		if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
			error = errno;
			result = -1;
			goto out;
		}
		record->timestamp_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
		    now.tv_nsec;
	}
	record->activity_id = options->activity_id;
	record->signpost_id = options->signpost_id;
	memcpy(record->trace_id, options->trace_id, sizeof(record->trace_id));
	memcpy(record->span_id, options->span_id, sizeof(record->span_id));
	cursor = (void *)(record + 1);
	memcpy(cursor, logger->subsystem, logger->subsystem_length);
	cursor += logger->subsystem_length;
	memcpy(cursor, logger->category, logger->category_length);
	cursor += logger->category_length;
	if (event_length != 0) {
		memcpy(cursor, options->event_name, event_length);
		cursor += event_length;
	}
	memcpy(cursor, options->message, message_length);
	cursor += message_length;
	for (i = 0; i < options->nattributes; i++) {
		const struct logcmp_attribute *attribute = &options->attributes[i];
		size_t key_length = strlen(attribute->key);

		memset(&wire_attribute, 0, sizeof(wire_attribute));
		wire_attribute.key_length = key_length;
		wire_attribute.type = attribute->type;
		wire_attribute.privacy = attribute->privacy;
		wire_attribute.value_length = attribute->value_length;
		memcpy(cursor, &wire_attribute, sizeof(wire_attribute));
		cursor += sizeof(wire_attribute);
		memcpy(cursor, attribute->key, key_length);
		cursor += key_length;
		if (attribute->value_length != 0) {
			memcpy(cursor, attribute->value, attribute->value_length);
			cursor += attribute->value_length;
		}
	}
	if (logcmp_validate_record(record, length) == -1) {
		error = errno;
		result = -1;
		goto out;
	}
	result = client_publish_record(client, record, length);
	error = errno;
	if (result == -1 && error == EAGAIN) {
		client->dropped++;
		client->dropped_by_severity[record->severity - 1]++;
		client->unreported_dropped++;
	}
out:
	(void)pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}

int
logcmp_flush(struct logcmp_client *client) __no_lock_analysis
{
	union logcmp_buffer reply;
	struct timespec begin, end;
	uint64_t duration;
	int error, have_begin, result;

	if (client == NULL || client->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	error = pthread_mutex_lock(&client->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	have_begin = 0;
	duration = 0;
	if (client_ensure_connected(client) == -1) {
		result = -1;
		error = errno;
	} else {
		have_begin = clock_gettime(CLOCK_MONOTONIC, &begin) == 0;
		result = rpc(client, LOGCMP_OP_FLUSH, NULL, 0, NULL, 0, &reply);
		error = errno;
		if (result == -1 && connection_unusable(error))
			client_disconnect(client);
	}
	if (have_begin &&
	    clock_gettime(CLOCK_MONOTONIC, &end) == 0)
		duration = (uint64_t)(end.tv_sec - begin.tv_sec) *
		    UINT64_C(1000000000) + end.tv_nsec - begin.tv_nsec;
	LOGCMP_PROBE_FLUSH(duration, result == 0 ? 0 : error);
	(void)pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}

int
logcmp_stats(struct logcmp_client *client, struct logcmp_stats *stats)
    __no_lock_analysis
{
	union logcmp_buffer reply;
	struct logcmp_stats *wire;
	int error, result;

	if (client == NULL || client->owner != getpid() || stats == NULL) {
		errno = EINVAL;
		return (-1);
	}
	error = pthread_mutex_lock(&client->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	if (client_ensure_connected(client) == -1)
		result = -1;
	else
		result = rpc(client, LOGCMP_OP_STATS, NULL, 0, NULL, 0, &reply);
	if (result == 0) {
		wire = (void *)(&reply.wire.msg + 1);
		*stats = *wire;
		stats->client_dropped += client->dropped;
		for (size_t i = 0; i < nitems(stats->client_dropped_by_severity);
		    i++)
			stats->client_dropped_by_severity[i] +=
			    client->dropped_by_severity[i];
	}
	error = errno;
	if (result == -1 && connection_unusable(error))
		client_disconnect(client);
	(void)pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}

int
logcmp_query_next(struct logcmp_client *client, uint32_t minimum_severity,
    struct logcmp_query_cursor *cursor, void *record, size_t capacity,
    size_t *record_length) __no_lock_analysis
{
	union logcmp_buffer reply;
	struct logcmp_query_request query;
	struct logcmp_query_reply *wire;
	int error, result;

	if (client == NULL || client->owner != getpid() || cursor == NULL ||
	    record == NULL || record_length == NULL ||
	    capacity < sizeof(struct logcmp_record) ||
	    minimum_severity > LOGCMP_SEVERITY_FATAL + 3 ||
	    (cursor->generation == 0 && cursor->offset != 0))
		return (errno = EINVAL, -1);
	*record_length = 0;
	error = pthread_mutex_lock(&client->lock);
	if (error != 0)
		return (errno = error, -1);
	memset(&query, 0, sizeof(query));
	query.cursor = *cursor;
	query.minimum_severity = minimum_severity;
	if (client_ensure_connected(client) == -1)
		result = -1;
	else
		result = rpc(client, LOGCMP_OP_QUERY, &query, sizeof(query), NULL,
		    0, &reply);
	if (result == 0) {
		wire = (void *)(&reply.wire.msg + 1);
		if (wire->record_length > capacity) {
			errno = EMSGSIZE;
			result = -1;
		} else {
			*cursor = wire->cursor;
			if (wire->record_length != 0)
				memcpy(record, wire + 1, wire->record_length);
			*record_length = wire->record_length;
			result = (int)wire->result;
		}
	}
	error = result == -1 ? errno : 0;
	if (result == -1 && connection_unusable(error))
		client_disconnect(client);
	LOGCMP_PROBE_QUERY(cursor->generation, cursor->offset, minimum_severity,
	    (uint32_t)*record_length, result == -1 ? error : result);
	(void)pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}

/*
 * Capability-mode-safe syslog(3) replacement (logcmp_log / logcmp_vlog).
 *
 * A process-lifetime logger opened lazily on first use and keyed to the current
 * pid, so a pdfork(2)'d worker re-establishes its own rather than reusing the
 * parent's inherited (possibly clofork-dropped) session.  NULL means "not
 * available" -> fall back to syslog(3).  Everything here is fail-soft: a log
 * call never blocks, never errors out, and preserves the caller's errno (so a
 * trailing "%m" still reports the original failure).
 */
static struct logcmp_client	*logcmp_default_client;
static struct logcmp_logger	*logcmp_default_logger;
static pid_t			 logcmp_default_pid = -1;

static uint32_t
logcmp_severity_from_priority(int priority)
{

	switch (LOG_PRI(priority)) {
	case LOG_EMERG:
	case LOG_ALERT:
	case LOG_CRIT:
		return (LOGCMP_SEVERITY_FATAL);
	case LOG_ERR:
		return (LOGCMP_SEVERITY_ERROR);
	case LOG_WARNING:
		return (LOGCMP_SEVERITY_WARN);
	case LOG_DEBUG:
		return (LOGCMP_SEVERITY_DEBUG);
	default:
		return (LOGCMP_SEVERITY_INFO);
	}
}

/*
 * logcmp_emit(3) takes a finished message string, so expand the one syslog(3)
 * conversion callers rely on -- %m -> strerror(err) -- ourselves; other
 * conversions are left for vsnprintf.  strerror text never contains '%'.
 */
static void
logcmp_expand_m(char *out, size_t outlen, const char *fmt, int err)
{
	const char *s, *m;
	size_t o;

	for (s = fmt, o = 0; *s != '\0' && o + 1 < outlen; ) {
		if (s[0] == '%' && s[1] == 'm') {
			m = strerror(err);
			while (*m != '\0' && o + 1 < outlen)
				out[o++] = *m++;
			s += 2;
		} else {
			out[o++] = *s++;
		}
	}
	out[o] = '\0';
}

/*
 * (Re)establish the process's default logger if this pid has not tried yet.
 * On a failed open the pointers stay NULL and the pid is recorded, so we do not
 * retry every call (the syslog fallback still delivers); a forked child re-tries
 * because its pid differs.  A stale inherited handle is abandoned, not closed --
 * closing a clofork-dropped descriptor would touch an unrelated fd.
 */
static void
logcmp_default_ensure(void)
{
	pid_t pid;

	pid = getpid();
	if (logcmp_default_pid == pid)
		return;
	logcmp_default_client = NULL;
	logcmp_default_logger = NULL;
	logcmp_default_pid = pid;
	if (logcmp_client_open(&logcmp_default_client) == -1) {
		logcmp_default_client = NULL;
		return;
	}
	if (logcmp_logger_create(logcmp_default_client, getprogname(), "log",
	    &logcmp_default_logger) == -1) {
		logcmp_client_close(logcmp_default_client);
		logcmp_default_client = NULL;
		logcmp_default_logger = NULL;
	}
}

void
logcmp_vlog(int priority, const char *fmt, va_list ap)
{
	int saved;

	saved = errno;
	logcmp_default_ensure();
	if (logcmp_default_logger != NULL) {
		struct logcmp_emit_options opt;
		char expfmt[256], msg[512];
		va_list aq;

		logcmp_expand_m(expfmt, sizeof(expfmt), fmt, saved);
		va_copy(aq, ap);
		(void)vsnprintf(msg, sizeof(msg), expfmt, aq);
		va_end(aq);
		memset(&opt, 0, sizeof(opt));
		opt.size = sizeof(opt);
		opt.severity = logcmp_severity_from_priority(priority);
		opt.kind = LOGCMP_KIND_LOG;
		opt.message_privacy = LOGCMP_PRIVACY_PUBLIC;
		opt.message = msg;
		if (logcmp_emit(logcmp_default_logger, &opt) == 0) {
			(void)logcmp_flush(logcmp_default_client);
			errno = saved;
			return;
		}
		/* Fail soft: fall through to syslog(3) if the emit failed. */
	}
	errno = saved;
	vsyslog(priority, fmt, ap);
	errno = saved;
}

void
logcmp_log(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	logcmp_vlog(priority, fmt, ap);
	va_end(ap);
}
