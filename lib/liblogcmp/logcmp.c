/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <shmring.h>

#include "logcmp.h"
#include "logcmp_probes.h"

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
	struct logcmp_hello_reply limits;
};

static pthread_mutex_t logcmp_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t logcmp_atfork_once = PTHREAD_ONCE_INIT;
static struct logcmp_client *logcmp_process_client;
static int logcmp_atfork_error;

static void logcmp_atfork_prepare(void) __no_lock_analysis;
static void logcmp_atfork_parent(void) __no_lock_analysis;
static void logcmp_atfork_child(void) __no_lock_analysis;
static int logcmp_registry_acquire(void) __no_lock_analysis;
static void logcmp_registry_release(void) __no_lock_analysis;

static void
logcmp_atfork_prepare(void)
{

	(void)pthread_mutex_lock(&logcmp_registry_lock);
	if (logcmp_process_client != NULL)
		(void)pthread_mutex_lock(&logcmp_process_client->lock);
}

static void
logcmp_atfork_parent(void)
{

	if (logcmp_process_client != NULL)
		(void)pthread_mutex_unlock(&logcmp_process_client->lock);
	(void)pthread_mutex_unlock(&logcmp_registry_lock);
}

static void
logcmp_atfork_child(void)
{

	if (logcmp_process_client != NULL)
		(void)pthread_mutex_unlock(&logcmp_process_client->lock);
	/*
	 * Component channels are close-on-fork authorities.  Do not let the
	 * child reuse parent bookkeeping even on kernels that report closure
	 * lazily; a later open must resolve its own serviced authority.
	 */
	logcmp_process_client = NULL;
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

int
logcmp_validate_record(const struct logcmp_record *record, size_t length)
{
	const uint8_t *message;
	const char *fields;
	size_t payload, i, line, equals;

	if (record == NULL || length < sizeof(*record) ||
	    record->severity > LOGCMP_DEBUG ||
	    (record->flags & ~LOGCMP_RECORD_F_MASK) != 0 ||
	    record->message_length == 0 ||
	    record->message_length > LOGCMP_MAX_TEXT ||
	    record->fields_length > LOGCMP_MAX_FIELDS) {
		errno = EPROTO;
		return (-1);
	}
	payload = (size_t)record->message_length + record->fields_length;
	if (payload != length - sizeof(*record) ||
	    memchr(record + 1, '\0', record->message_length) != NULL) {
		errno = EPROTO;
		return (-1);
	}
	message = (const void *)(record + 1);
	for (i = 0; i < record->message_length; i++)
		if (message[i] < 0x20 || message[i] == 0x7f) {
			errno = EPROTO;
			return (-1);
		}
	fields = (const char *)(record + 1) + record->message_length;
	line = 0;
	equals = SIZE_MAX;
	for (i = 0; i < record->fields_length; i++) {
		if (fields[i] == '\0' || fields[i] == 0x7f ||
		    ((unsigned char)fields[i] < 0x20 && fields[i] != '\n')) {
			errno = EPROTO;
			return (-1);
		}
		if (fields[i] == '=' && equals == SIZE_MAX)
			equals = i;
		if (equals == SIZE_MAX &&
		    !((fields[i] >= 'A' && fields[i] <= 'Z') ||
		    (i != line && ((fields[i] >= '0' && fields[i] <= '9') ||
		    fields[i] == '_')))) {
			errno = EPROTO;
			return (-1);
		}
		if (fields[i] == '\n') {
			if (i == line || equals == SIZE_MAX || equals == line ||
			    fields[line] == '_') {
				errno = EPROTO;
				return (-1);
			}
			line = i + 1;
			equals = SIZE_MAX;
		}
	}
	if (record->fields_length != 0 &&
	    (line == record->fields_length ||
	    equals == SIZE_MAX || equals == line || fields[line] == '_')) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
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
	    msg->opcode < LOGCMP_OP_HELLO || msg->opcode > LOGCMP_OP_DETACH ||
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
	    opcode > LOGCMP_OP_DETACH || (flags & ~LOGCMP_MSG_F_MASK) != 0) {
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
			    LOGCMP_FEATURE_SHM_RING |
			    LOGCMP_FEATURE_SYSLOG)) != 0 ||
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
		    LOGCMP_FEATURE_SHM_RING | LOGCMP_FEATURE_SYSLOG)) != 0)
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
	struct service_context *service;
	int fd, error;

	if (service_acquire(&service) == -1)
		return (-1);
	error = service_connect(service, LOGCMP_INTERFACE, &fd) == -1 ?
	    errno : 0;
	service_release(service);
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
	    &options) == -1)
		return (-1);
	received = incoming.length;
	msg = &out->wire.msg;
	if (incoming.nfds != 0 ||
	    logcmp_validate_message(msg, received,
	    LOGCMP_MESSAGE_REPLY) == -1 || msg->opcode != opcode) {
		errno = EPROTO;
		return (-1);
	}
	if (msg->status != 0) {
		errno = -msg->status;
		return (-1);
	}
	return (0);
}

int
logcmp_client_open(struct logcmp_client **clientp)
{
	union logcmp_buffer reply;
	struct logcmp_attach_request attach;
	struct logcmp_hello hello;
	struct shmring_fds producer, consumer;
	struct logcmp_client *client;
	int fds[LOGCMP_RING_FDS], error, fd;

	if (clientp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*clientp = NULL;
	if (logcmp_registry_acquire() == -1)
		return (-1);
	if (logcmp_process_client != NULL) {
		logcmp_process_client->references++;
		*clientp = logcmp_process_client;
		logcmp_registry_release();
		return (0);
	}
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		goto fail_registry;
	client->owner = getpid();
	memset(&producer, -1, sizeof(producer));
	memset(&consumer, -1, sizeof(consumer));
	fd = logcmp_open_channel();
	if (fd == -1)
		goto fail;
	if (service_session_create(fd, &client->channel) == -1) {
		error = errno;
		close(fd);
		errno = error;
		goto fail;
	}
	error = pthread_mutex_init(&client->lock, NULL);
	if (error != 0) {
		errno = error;
		goto fail;
	}
	memset(&hello, 0, sizeof(hello));
	hello.min_version = LOGCMP_ABI_VERSION;
	hello.max_version = LOGCMP_ABI_VERSION;
	hello.features = LOGCMP_FEATURE_INLINE | LOGCMP_FEATURE_SHM_RING;
	if (rpc(client, LOGCMP_OP_HELLO, &hello, sizeof(hello), NULL, 0,
	    &reply) == -1)
		goto fail_mutex;
	memcpy(&client->limits, &reply.wire.msg + 1, sizeof(client->limits));
	if (client->limits.version != LOGCMP_ABI_VERSION ||
	    (client->limits.features & (LOGCMP_FEATURE_SHM_RING |
	    LOGCMP_FEATURE_INLINE)) == 0 ||
	    client->limits.max_record == 0 ||
	    client->limits.max_record > LOGCMP_MAX_RECORD)
		goto protocol;
	client->sequence = 0;
	if ((client->limits.features & LOGCMP_FEATURE_SHM_RING) == 0) {
		client->references = 1;
		logcmp_process_client = client;
		*clientp = client;
		logcmp_registry_release();
		return (0);
	}
	if (client->limits.ring_size < SHMRING_MIN_CAPACITY)
		goto protocol;
	if (shmring_create(client->limits.ring_size, SHMRING_MODE_RECORD,
	    client->limits.max_record, 1, &producer,
	    &consumer) == -1 ||
	    shmring_open(&client->ring, &producer, SHMRING_ROLE_PRODUCER) == -1)
		goto fail_rings;
	fds[0] = consumer.config_fd;
	fds[1] = consumer.data_fd;
	fds[2] = consumer.head_fd;
	fds[3] = consumer.tail_fd;
	memset(&attach, 0, sizeof(attach));
	attach.generation = 1;
	attach.ring_size = client->limits.ring_size;
	attach.max_record = client->limits.max_record;
	if (rpc(client, LOGCMP_OP_ATTACH, &attach, sizeof(attach), fds,
	    nitems(fds), &reply) == -1)
		goto fail_rings;
	shmring_fds_close(&producer);
	shmring_fds_close(&consumer);
	client->references = 1;
	logcmp_process_client = client;
	*clientp = client;
	logcmp_registry_release();
	return (0);

protocol:
	errno = EPROTO;
fail_rings:
	error = errno;
	shmring_close(client->ring);
	shmring_fds_close(&producer);
	shmring_fds_close(&consumer);
	errno = error;
fail_mutex:
	(void)pthread_mutex_destroy(&client->lock);
fail:
	error = errno;
	if (client->channel != NULL)
		service_session_close(client->channel);
	free(client);
	errno = error;
	logcmp_registry_release();
	return (-1);

fail_registry:
	error = errno;
	logcmp_registry_release();
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
	error = pthread_mutex_lock(&client->lock);
	if (error == 0) {
		if (client->ring != NULL)
			(void)rpc(client, LOGCMP_OP_DETACH, NULL, 0, NULL, 0,
			    &reply);
		(void)pthread_mutex_unlock(&client->lock);
	}
	shmring_close(client->ring);
	service_session_close(client->channel);
	(void)pthread_mutex_destroy(&client->lock);
	free(client);
	logcmp_registry_release();
}

int
logcmp_log(struct logcmp_client *client, uint32_t severity,
    const char *message, const char *fields) __no_lock_analysis
{
	union logcmp_buffer buffer, reply;
	struct logcmp_record *record;
	size_t message_length, fields_length, length;
	int error, result;

	if (client == NULL || client->owner != getpid() || message == NULL ||
	    severity > LOGCMP_DEBUG) {
		errno = EINVAL;
		return (-1);
	}
	message_length = strlen(message);
	fields_length = fields != NULL ? strlen(fields) : 0;
	if (message_length == 0 || message_length > client->limits.max_text ||
	    fields_length > client->limits.max_fields ||
	    sizeof(*record) + message_length + fields_length >
	    client->limits.max_record) {
		errno = EMSGSIZE;
		return (-1);
	}
	error = pthread_mutex_lock(&client->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	memset(&buffer, 0, sizeof(buffer));
	record = (void *)buffer.wire.payload;
	record->sequence = ++client->sequence;
	record->severity = severity;
	record->message_length = (uint32_t)message_length;
	record->fields_length = (uint32_t)fields_length;
	memcpy(record + 1, message, message_length);
	if (fields_length != 0)
		memcpy((uint8_t *)(record + 1) + message_length, fields,
		    fields_length);
	length = sizeof(*record) + message_length + fields_length;
	if (logcmp_validate_record(record, length) == -1) {
		error = errno;
		result = -1;
		goto out;
	}
	if (client->ring == NULL) {
		result = rpc(client, LOGCMP_OP_WRITE, record, length, NULL, 0,
		    &reply);
		error = errno;
	} else {
		result = shmring_write_record(client->ring, record, length);
		if (result == -1) {
			error = errno;
			if (error == EAGAIN)
				client->dropped++;
		} else {
			/*
			 * The provider's bounded timer drains batches from the
			 * shared ring.  Do not turn every record into a control
			 * message; FLUSH is the explicit synchronous wake and
			 * ordering boundary.
			 */
			error = 0;
		}
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
	int error, result;

	if (client == NULL || client->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	error = pthread_mutex_lock(&client->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = rpc(client, LOGCMP_OP_FLUSH, NULL, 0, NULL, 0, &reply);
	error = errno;
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
	result = rpc(client, LOGCMP_OP_STATS, NULL, 0, NULL, 0, &reply);
	if (result == 0) {
		wire = (void *)(&reply.wire.msg + 1);
		*stats = *wire;
		stats->client_dropped += client->dropped;
	}
	error = errno;
	(void)pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}
