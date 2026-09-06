/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/wait.h>


#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <auditcmp.h>
#include <auditcmp_server.h>
#include <channel.h>
#include <libservice.h>
#include <logcmp.h>
#include <logcmp_server.h>
#include <shmring.h>

#include "logd_probes.h"
#include "logcmp_wakeup.h"
#include "config.h"
#include "session.h"
#include "storage.h"
#ifdef LOGCMP_TESTING
#include "logcmp_test.h"
#endif

#define	LOGD_NAME	LOGCMP_INTERFACE
#define	LOGCMP_DRAIN_TIMER_IDENT	1
#define	LOGCMP_POOL_WORK_IDENT	2
#define	LOGCMP_POOL_MAX_EVENTS	128
#define	LOGCMP_POOL_WORK_BUDGET	128
#define	LOGCMP_POOL_CONTROL_MAGIC 0x4c50434dU
#define	LOGCMP_SHUTDOWN_TIMEOUT_MS 5000U

enum pool_source_type {
	POOL_SOURCE_SESSION = 1,
	POOL_SOURCE_CONTROL,
	POOL_SOURCE_TIMER,
	POOL_SOURCE_WORK
};

union provider_buffer {
	max_align_t align;
	struct {
		struct logcmp_msg msg;
		uint8_t payload[LOGCMP_MAX_MESSAGE - sizeof(struct logcmp_msg)];
	} wire;
};

struct sink_context {
	const char	*label;
	uint64_t	 instance;
	struct logcmp_storage_session *storage;
};

struct worker_state {
	int			 source_type;
	struct worker_state	*next;
	struct worker_state	*pending_next;
	struct channel		*channel;
	struct logcmp_session	 session;
	struct auditcmp_client	*audit;
	struct sink_context	 sink;
	logcmp_sink_fn		 record_sink;
	void			*record_context;
	int			(*storage_flush)(void *, uint32_t);
	int			(*storage_query)(void *, const char *, uint32_t,
				    const struct logcmp_query_filter *,
				    struct logcmp_store_cursor *, void *, size_t,
				    size_t *, uint32_t);
	void			*storage_context;
	int			 kq;
	int			 wake_fd;
	int			 terminal_error;
	int			 channel_fd;
	char			 label[64];
	bool			 active;
	bool			 drain_pending;
	bool			 pending_queued;
	uint32_t		 ring_size;
	uint32_t		 fallback_drain_ms;
	uint32_t		 drain_batch;
};

struct pool_control_message {
	uint32_t magic;
	uint32_t reserved;
	uint64_t instance;
	char label[64];
};

struct pool_event_source {
	int source_type;
};

struct pool_state {
	struct worker_state *sessions;
	struct worker_state *garbage;
	struct pool_event_source control_source;
	struct pool_event_source timer_source;
	struct pool_event_source work_source;
	struct worker_state *pending_head;
	struct worker_state *pending_tail;
	struct auditcmp_client *audit;
	struct logcmp_storage_session *storage;
	const struct logcmp_config *config;
	_Atomic uint32_t *admitted;
	uint32_t capacity;
	uint32_t shard;
	int control_fd;
	int kq;
};

struct pool_parent {
	int control_fd;
	int process_fd;
	pthread_t watcher;
	_Atomic uint32_t *admitted;
	uint32_t capacity;
	uint32_t shard;
	_Atomic bool expected_exit;
	_Atomic bool exited;
	bool watcher_started;
};

static void
audit_policy(struct auditcmp_client *audit, const char *label,
    const char *operation, int error)
{

#ifdef LOGCMP_TESTING
	(void)audit;
	(void)label;
	(void)operation;
	(void)error;
#else
	if (audit == NULL)
		return;
	if (auditcmp_submit(audit, label, operation, error) == -1)
		syslog(LOG_WARNING, "audit %s for %s failed: %m", operation,
		    label);
#endif
}

#ifndef LOGCMP_TESTING
static int
storage_flush(void *context, uint32_t timeout_ms)
{

	return (logcmp_storage_flush(context, timeout_ms));
}

static int
storage_query(void *context, const char *label, uint32_t minimum_severity,
    const struct logcmp_query_filter *filter,
    struct logcmp_store_cursor *cursor, void *record, size_t capacity,
    size_t *length, uint32_t timeout_ms)
{

	return (logcmp_storage_query_next_filtered_for(context, label,
	    minimum_severity, filter, cursor, record, capacity, length,
	    timeout_ms));
}

static int
harden_worker_fd(int fd)
{

	return (service_harden_fd(fd, SERVICE_HARDEN_CLOFORK_ONCE));
}

/*
 * Confine a descriptor inside a leaf pool worker, which never forks again, so
 * its descriptors must latch to CAP_CLOFORK_LOCKED.  A descriptor the parent
 * handed across the pool fork with CAP_CLOFORK_ONCE has already spent that
 * ONCE and is locked; re-applying ONCE here would widen it and fail
 * ENOTCAPABLE.
 */
static int
harden_worker_leaf_fd(int fd)
{

	return (service_harden_fd(fd, 0));
}

static int
harden_transfer_fd(int fd)
{

	return (service_harden_fd(fd,
	    SERVICE_HARDEN_XFER_ONCE | SERVICE_HARDEN_CLOFORK_ONCE));
}

static int
pool_send_fd(int socket_fd, const struct pool_control_message *control,
    int fd)
{
	struct msghdr message;
	struct iovec iov;
	union {
		struct cmsghdr header;
		char bytes[CMSG_SPACE(sizeof(int))];
	} ancillary;
	struct cmsghdr *header;
	ssize_t amount;

	memset(&message, 0, sizeof(message));
	iov.iov_base = __DECONST(void *, control);
	iov.iov_len = sizeof(*control);
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = ancillary.bytes;
	message.msg_controllen = sizeof(ancillary.bytes);
	header = CMSG_FIRSTHDR(&message);
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(header), &fd, sizeof(fd));
	amount = sendmsg(socket_fd, &message, MSG_NOSIGNAL | MSG_EOR);
	if (amount == -1)
		return (-1);
	return ((size_t)amount == sizeof(*control) ? 0 : (errno = EIO, -1));
}

static int
pool_receive_fd(int socket_fd, struct pool_control_message *control, int *fd)
{
	struct msghdr message;
	struct iovec iov;
	union {
		struct cmsghdr header;
		char bytes[CMSG_SPACE(sizeof(int) * 2)];
	} ancillary;
	struct cmsghdr *header;
	int received[2];
	size_t nfds;
	ssize_t amount;

	*fd = -1;
	memset(&message, 0, sizeof(message));
	iov.iov_base = control;
	iov.iov_len = sizeof(*control);
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = ancillary.bytes;
	message.msg_controllen = sizeof(ancillary.bytes);
	/*
	 * Do not request MSG_TRUNC: this kernel reflects the recvmsg(2) input
	 * flags back into msg_flags, so a requested MSG_TRUNC would make the
	 * truncation check below fire on every message.  Without it, msg_flags
	 * still reports a genuine over-length datagram as MSG_TRUNC.
	 */
	amount = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
	if (amount <= 0)
		return (amount == 0 ? (errno = ECONNRESET, -1) : -1);
	nfds = 0;
	for (header = CMSG_FIRSTHDR(&message); header != NULL;
	    header = CMSG_NXTHDR(&message, header)) {
		if (header->cmsg_level != SOL_SOCKET ||
		    header->cmsg_type != SCM_RIGHTS ||
		    header->cmsg_len < CMSG_LEN(0))
			continue;
		nfds = MIN((header->cmsg_len - CMSG_LEN(0)) / sizeof(int),
		    nitems(received));
		memcpy(received, CMSG_DATA(header), nfds * sizeof(int));
		break;
	}
	if ((size_t)amount != sizeof(*control) ||
	    (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 || nfds != 1) {
		for (size_t i = 0; i < nfds; i++)
			close(received[i]);
		return (errno = EPROTO, -1);
	}
	*fd = received[0];
	return (0);
}

static int
syslog_sink(void *arg, const struct logcmp_record *record,
    const char *message __unused, const char *attributes __unused)
{
	struct sink_context *context;

	context = arg;
	/*
	 * logd persists the record to its own store (its serviced-delivered,
	 * tzfsd-mounted store directory) and IS the plane's log authority;
	 * consumers query it by name.  The store is the sink of record.
	 */
	if (logcmp_storage_append_for(context->storage, context->label, record,
	    sizeof(*record) + record->subsystem_length +
	    record->category_length + record->event_name_length +
	    record->message_length + record->attributes_length) == -1) {
		LOGD_PROBE_RECORD(context->label, record->severity,
		    record->message_length, errno != 0 ? errno : EIO);
		return (-1);
	}
	LOGD_PROBE_RECORD(context->label, record->severity,
	    record->message_length, 0);
	return (0);
}
#endif

#ifdef LOGCMP_TESTING
static int
harden_worker_fd(int fd)
{

	return (service_harden_fd(fd, SERVICE_HARDEN_CLOFORK_ONCE));
}
#endif

static int
send_reply(struct channel_message *request_message,
    const struct logcmp_msg *request, int error, const void *payload,
    size_t payload_length)
{
	union provider_buffer buffer;
	struct logcmp_msg *reply;
	size_t length;

	memset(&buffer, 0, sizeof(buffer));
	reply = &buffer.wire.msg;
	if (logcmp_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1)
		return (-1);
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	if (logcmp_validate_message(reply, length, LOGCMP_MESSAGE_REPLY) == -1 ||
	    logcmp_validate_fds(reply, 0, LOGCMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(reply, length)));
}

static int
trusted_sink(void *argument, const struct logcmp_record *record,
    const char *message __unused, const char *attributes __unused)
{
	struct worker_state *state;
	struct logcmp_record *trusted;
	struct timespec monotonic, realtime;
	uint8_t storage[LOGCMP_MAX_RECORD];
	size_t length;
	const char *trusted_message, *trusted_attributes;

	state = argument;
	length = sizeof(*record) + record->subsystem_length +
	    record->category_length + record->event_name_length +
	    record->message_length + record->attributes_length;
	if (length > sizeof(storage) ||
	    clock_gettime(CLOCK_REALTIME, &realtime) == -1 ||
	    clock_gettime(CLOCK_MONOTONIC, &monotonic) == -1)
		return (-1);
	memcpy(storage, record, length);
	trusted = (void *)storage;
	trusted->receive_timestamp_ns = (uint64_t)realtime.tv_sec *
	    UINT64_C(1000000000) + (uint64_t)realtime.tv_nsec;
	trusted->receive_monotonic_ns = (uint64_t)monotonic.tv_sec *
	    UINT64_C(1000000000) + (uint64_t)monotonic.tv_nsec;
	trusted_message = (const char *)(trusted + 1) +
	    trusted->subsystem_length + trusted->category_length +
	    trusted->event_name_length;
	trusted_attributes = trusted_message + trusted->message_length;
	return (state->record_sink(state->record_context, trusted,
	    trusted_message, trusted_attributes));
}

static int
drain_session(struct worker_state *state, const char *operation)
{
	uint64_t before, filtered, rate_limited, records;
	bool more;
	int error;

	before = state->session.stats.accepted;
	filtered = state->session.stats.provider_filtered;
	rate_limited = state->session.stats.provider_rate_limited;
	more = false;
	if (logcmp_session_drain_budget(&state->session, trusted_sink, state,
	    state->drain_batch != 0 ? state->drain_batch : SIZE_MAX,
	    &more) == 0) {
		state->drain_pending = more;
		records = state->session.stats.accepted - before;
		LOGD_PROBE_BATCH(state->sink.label, state->sink.instance,
		    operation, records, 0);
		if (state->session.stats.provider_filtered != filtered)
			LOGD_PROBE_DROP(state->sink.label,
			    state->session.stats.last_sequence, ECANCELED);
		if (state->session.stats.provider_rate_limited != rate_limited)
			LOGD_PROBE_DROP(state->sink.label,
			    state->session.stats.last_sequence, EDQUOT);
		return (0);
	}
	error = errno != 0 ? errno : EPROTO;
	records = state->session.stats.accepted - before;
	LOGD_PROBE_BATCH(state->sink.label, state->sink.instance,
	    operation, records, error);
	audit_policy(state->audit, state->sink.label, operation, error);
	LOGD_PROBE_DROP(state->sink.label,
	    state->session.stats.last_sequence, error);
	errno = error;
	return (-1);
}

static int
drain_session_until_idle(struct worker_state *state, const char *operation,
    uint32_t timeout_ms)
{
	struct timespec deadline, now;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
		return (-1);
	deadline.tv_sec += timeout_ms / 1000;
	deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}
	do {
		if (drain_session(state, operation) == -1)
			return (-1);
		if (!state->drain_pending)
			return (0);
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			return (-1);
	} while (now.tv_sec < deadline.tv_sec ||
	    (now.tv_sec == deadline.tv_sec && now.tv_nsec < deadline.tv_nsec));
	return (errno = ETIMEDOUT, -1);
}

static void
close_wakeup(struct worker_state *state)
{
	struct kevent change;

	if (state->wake_fd < 0)
		return;
	EV_SET(&change, state->wake_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	if (state->kq >= 0 && kevent(state->kq, &change, 1, NULL, 0, NULL) == -1 &&
	    errno != ENOENT)
		state->terminal_error = errno;
	close(state->wake_fd);
	state->wake_fd = -1;
}

static int
attach_wakeup(struct worker_state *state,
    struct channel_message *request_message)
{
	struct kevent change;
	int fd;

	if (state->wake_fd >= 0) {
		errno = EBUSY;
		return (-1);
	}
	fd = channel_message_take_fd(request_message,
	    LOGCMP_ATTACH_FD_WAKE_READ);
	if (fd == -1)
		return (-1);
	if (logcmp_wakeup_validate_consumer(fd) == -1 ||
	    harden_worker_fd(fd) == -1) {
		int error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	EV_SET(&change, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, state);
	if (kevent(state->kq, &change, 1, NULL, 0, NULL) == -1) {
		int error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	state->wake_fd = fd;
	return (0);
}

static void
handle_event(struct channel *channel __unused,
    struct channel_message *event_message, void *argument)
{
	struct worker_state *state;
	const struct logcmp_msg *message;
	size_t length;

	state = argument;
	message = channel_message_data(event_message);
	length = channel_message_length(event_message);
	if (logcmp_validate_message(message, length, LOGCMP_MESSAGE_EVENT) ==
	    -1 || logcmp_validate_fds(message,
	    channel_message_fd_count(event_message), LOGCMP_MESSAGE_EVENT) ==
	    -1) {
		state->terminal_error = EPROTO;
	} else if (drain_session(state, "batch-notify") == -1) {
		/*
		 * A wake received before ATTACH is a protocol violation.  Sink
		 * failures are session-local and also terminate this producer.
		 */
		state->terminal_error = errno;
	}
	channel_message_free(event_message);
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *request_message, void *argument)
{
	struct logcmp_hello_reply hello;
	struct logcmp_query_reply query_reply;
	struct logcmp_store_cursor store_cursor;
	struct shmring_fds ringfds;
	struct worker_state *state;
	const struct logcmp_msg *message;
	uint64_t filtered_before, rate_limited_before, rejected_before;
	size_t length, query_length;
	uint8_t query_record[LOGCMP_MAX_RECORD];
	bool attached, wake_attached;
	int query_result;
	int error;

	state = argument;
	message = channel_message_data(request_message);
	length = channel_message_length(request_message);
	if (logcmp_validate_message(message, length,
	    LOGCMP_MESSAGE_REQUEST) == -1 ||
	    logcmp_validate_fds(message,
	    channel_message_fd_count(request_message),
	    LOGCMP_MESSAGE_REQUEST) == -1) {
		state->terminal_error = EPROTO;
		channel_message_free(request_message);
		return;
	}

	error = 0;
	rejected_before = state->session.stats.rejected;
	filtered_before = state->session.stats.provider_filtered;
	rate_limited_before = state->session.stats.provider_rate_limited;
	switch (message->opcode) {
	case LOGCMP_OP_HELLO:
		memset(&hello, 0, sizeof(hello));
		hello.version = LOGCMP_ABI_VERSION;
		hello.features = LOGCMP_FEATURE_INLINE |
		    LOGCMP_FEATURE_SHM_RING | LOGCMP_FEATURE_SYSLOG |
		    LOGCMP_FEATURE_TYPED_RECORDS | LOGCMP_FEATURE_PRIVACY |
		    LOGCMP_FEATURE_TRACE_CONTEXT | LOGCMP_FEATURE_EDGE_WAKEUP |
		    LOGCMP_FEATURE_SCOPED_QUERY;
		hello.ring_size = state->ring_size;
		hello.max_record = LOGCMP_MAX_RECORD;
		hello.max_text = LOGCMP_MAX_TEXT;
		hello.max_fields = LOGCMP_MAX_FIELDS;
		if (send_reply(request_message, message, 0, &hello,
		    sizeof(hello)) == -1)
			state->terminal_error = errno;
		channel_message_free(request_message);
		return;
	case LOGCMP_OP_ATTACH:
		attached = false;
		wake_attached = false;
		ringfds.config_fd = channel_message_borrow_fd(request_message,
		    LOGCMP_ATTACH_FD_CONFIG);
		ringfds.data_fd = channel_message_borrow_fd(request_message,
		    LOGCMP_ATTACH_FD_DATA);
		ringfds.head_fd = channel_message_borrow_fd(request_message,
		    LOGCMP_ATTACH_FD_HEAD);
		ringfds.tail_fd = channel_message_borrow_fd(request_message,
		    LOGCMP_ATTACH_FD_TAIL);
		if (ringfds.config_fd == -1 || ringfds.data_fd == -1 ||
		    ringfds.head_fd == -1 || ringfds.tail_fd == -1 ||
		    logcmp_session_attach(&state->session,
		    (const void *)(message + 1), &ringfds) == -1) {
			error = errno != 0 ? errno : EPROTO;
			break;
		}
		attached = true;
		if (attach_wakeup(state, request_message) == -1)
			error = errno != 0 ? errno : EPROTO;
		else
			wake_attached = true;
		if (error != 0) {
			if (wake_attached)
				close_wakeup(state);
			if (attached)
				(void)logcmp_session_detach(&state->session);
		}
		break;
	case LOGCMP_OP_WRITE:
		if (logcmp_session_submit(&state->session,
		    (const void *)(message + 1), length - sizeof(*message),
		    trusted_sink, state) == -1)
			error = errno != 0 ? errno : EPROTO;
		break;
	case LOGCMP_OP_FLUSH:
		{
			struct timespec begin, end;
			uint64_t before, duration;
			int have_begin;

			before = state->session.stats.accepted;
			duration = 0;
			have_begin = clock_gettime(CLOCK_MONOTONIC, &begin) == 0;
			if (drain_session_until_idle(state, "explicit-flush",
			    LOGCMP_STORAGE_TIMEOUT_MS) == -1)
				error = errno;
			else if (state->storage_flush(state->storage_context,
			    LOGCMP_STORAGE_TIMEOUT_MS) == -1)
				error = errno != 0 ? errno : EIO;
			if (have_begin && clock_gettime(CLOCK_MONOTONIC, &end) == 0)
				duration = (uint64_t)(end.tv_sec - begin.tv_sec) *
				    UINT64_C(1000000000) + end.tv_nsec - begin.tv_nsec;
			LOGD_PROBE_FLUSH(state->sink.label, state->sink.instance,
			    state->session.stats.accepted - before, duration, error);
		}
		break;
	case LOGCMP_OP_STATS:
		if (send_reply(request_message, message, 0,
		    &state->session.stats, sizeof(state->session.stats)) == -1)
			state->terminal_error = errno;
		channel_message_free(request_message);
		return;
	case LOGCMP_OP_DETACH:
		if (drain_session_until_idle(state, "detach",
		    LOGCMP_STORAGE_TIMEOUT_MS) == -1)
			error = errno != 0 ? errno : EIO;
		else if (logcmp_session_detach(&state->session) == -1)
			error = errno != 0 ? errno : EPROTO;
		else
			close_wakeup(state);
		break;
	case LOGCMP_OP_QUERY: {
		const struct logcmp_query_request *query;
		struct logcmp_query_filter filter;

		query = (const void *)(message + 1);
		store_cursor.generation = query->cursor.generation;
		store_cursor.offset = query->cursor.offset;
		/*
		 * The filter narrows within the caller's own label only; scoping
		 * still comes from state->sink.label passed below, never from the
		 * request, so a filter can never reach another label's records.
		 */
		memset(&filter, 0, sizeof(filter));
		filter.from_ns = query->from_ns;
		filter.to_ns = query->to_ns;
		filter.match_flags = query->match_flags;
		filter.subsystem_length = query->subsystem_length;
		filter.category_length = query->category_length;
		filter.subsystem = query->subsystem;
		filter.category = query->category;
		query_length = 0;
		query_result = state->storage_query(state->storage_context,
		    state->sink.label, query->minimum_severity, &filter,
		    &store_cursor, query_record,
		    sizeof(query_record), &query_length,
		    LOGCMP_STORAGE_TIMEOUT_MS);
		if (query_result == -1) {
			error = errno != 0 ? errno : EIO;
			LOGD_PROBE_QUERY(state->sink.label,
			    store_cursor.generation, store_cursor.offset,
			    query->minimum_severity, 0, error);
			break;
		}
		memset(&query_reply, 0, sizeof(query_reply));
		query_reply.cursor.generation = store_cursor.generation;
		query_reply.cursor.offset = store_cursor.offset;
		query_reply.result = (uint32_t)query_result;
		query_reply.record_length = (uint32_t)query_length;
		{
			uint8_t response[sizeof(query_reply) + LOGCMP_MAX_RECORD];

			memcpy(response, &query_reply, sizeof(query_reply));
			if (query_length != 0)
				memcpy(response + sizeof(query_reply), query_record,
				    query_length);
			if (send_reply(request_message, message, 0, response,
			    sizeof(query_reply) + query_length) == -1)
				state->terminal_error = errno;
		}
		LOGD_PROBE_QUERY(state->sink.label, store_cursor.generation,
		    store_cursor.offset, query->minimum_severity,
		    (uint32_t)query_length, query_result);
		channel_message_free(request_message);
		return;
	}
	default:
		state->terminal_error = EPROTO;
		channel_message_free(request_message);
		return;
	}
	if (state->session.stats.provider_filtered != filtered_before)
		LOGD_PROBE_DROP(state->sink.label,
		    state->session.stats.last_sequence, ECANCELED);
	if (state->session.stats.provider_rate_limited != rate_limited_before)
		LOGD_PROBE_DROP(state->sink.label,
		    state->session.stats.last_sequence, EDQUOT);
	if (error != 0) {
		if (state->session.stats.rejected == rejected_before)
			state->session.stats.rejected++;
		audit_policy(state->audit, state->sink.label, "request-denied",
		    error);
		LOGD_PROBE_DROP(state->sink.label,
		    state->session.stats.last_sequence, error);
	}
	if (send_reply(request_message, message, error, NULL, 0) == -1)
		state->terminal_error = errno;
	channel_message_free(request_message);
}

#ifdef LOGCMP_TESTING
struct test_backend {
	int error;
};

static int
test_sink(void *context, const struct logcmp_record *record __unused,
    const char *message __unused, const char *attributes __unused)
{
	struct test_backend *backend;

	backend = context;
	if (record->receive_timestamp_ns == 0 ||
	    record->receive_monotonic_ns == 0)
		return (errno = EPROTO, -1);
	return (backend->error == 0 ? 0 : (errno = backend->error, -1));
}

int
logcmp_test_trusted_submit(const struct logcmp_record *record,
    logcmp_sink_fn sink, void *context)
{
	struct worker_state state;

	if (record == NULL || sink == NULL)
		return (errno = EINVAL, -1);
	memset(&state, 0, sizeof(state));
	state.record_sink = sink;
	state.record_context = context;
	return (trusted_sink(&state, record, NULL, NULL));
}

static int
test_storage_flush(void *context, uint32_t timeout_ms __unused)
{
	struct test_backend *backend;

	backend = context;
	return (backend->error == 0 ? 0 : (errno = backend->error, -1));
}

static int
test_storage_query(void *context, const char *label __unused,
    uint32_t minimum_severity __unused,
    const struct logcmp_query_filter *filter __unused,
    struct logcmp_store_cursor *cursor, void *record __unused,
    size_t capacity __unused, size_t *length, uint32_t timeout_ms __unused)
{
	struct test_backend *backend;

	backend = context;
	if (backend->error != 0)
		return (errno = backend->error, -1);
	cursor->generation = 1;
	cursor->offset = 0;
	*length = 0;
	return (0);
}

int
logcmp_test_serve(int fd, const char *label, uint32_t ring_size,
    int backend_error)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct kevent changes[2], event;
	struct test_backend backend;
	struct worker_state state;
	struct channel *channel;
	int channel_descriptor, result, wants_write;

	if (fd < 0 || label == NULL || label[0] == '\0' ||
	    ring_size < SHMRING_MIN_CAPACITY || backend_error < 0)
		return (errno = EINVAL, -1);
	memset(&state, 0, sizeof(state));
	backend.error = backend_error;
	state.kq = kqueuex(KQUEUE_CLOEXEC);
	state.wake_fd = -1;
	state.ring_size = ring_size;
	state.sink.label = label;
	state.record_sink = test_sink;
	state.record_context = &backend;
	state.storage_flush = test_storage_flush;
	state.storage_query = test_storage_query;
	state.storage_context = &backend;
	logcmp_session_init(&state.session, LOGCMP_MAX_RECORD);
	channel = NULL;
	if (state.kq == -1 ||
	    logcmp_session_configure(&state.session, LOGCMP_SEVERITY_TRACE,
	    0, 0) == -1 || channel_create(fd, &options, &channel) == -1 ||
	    channel_set_request_handler(channel, handle_request, &state) == -1 ||
	    channel_set_event_handler(channel, handle_event, &state) == -1)
		goto fail;
	channel_descriptor = channel_fd(channel);
	EV_SET(&changes[0], channel_descriptor, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	EV_SET(&changes[1], channel_descriptor, EVFILT_WRITE,
	    EV_ADD | EV_DISABLE, 0, 0, NULL);
	if (kevent(state.kq, changes, nitems(changes), NULL, 0, NULL) == -1)
		goto fail;
	result = 0;
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		EV_SET(&changes[0], channel_descriptor, EVFILT_WRITE,
		    wants_write ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
		if (kevent(state.kq, changes, 1, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			result = 1;
			break;
		}
		if ((event.flags & EV_ERROR) != 0) {
			result = 1;
			break;
		}
		if (state.wake_fd >= 0 &&
		    event.ident == (uintptr_t)state.wake_fd) {
			if (logcmp_wakeup_drain(state.wake_fd) == -1 ||
			    drain_session(&state, "test-wakeup") == -1) {
				result = 1;
				break;
			}
			continue;
		}
		if (event.ident != (uintptr_t)channel_descriptor)
			continue;
		if (event.filter == EVFILT_WRITE && channel_flush(channel) == -1) {
			result = 1;
			break;
		}
		if (event.filter == EVFILT_READ && channel_dispatch(channel) == -1)
			break;
		if (state.terminal_error != 0) {
			result = 1;
			break;
		}
	}
	close_wakeup(&state);
	logcmp_session_destroy(&state.session);
	channel_destroy(channel);
	close(state.kq);
	return (result);

fail:
	result = errno;
	close_wakeup(&state);
	logcmp_session_destroy(&state.session);
	if (channel != NULL)
		channel_destroy(channel);
	if (state.kq >= 0)
		close(state.kq);
	errno = result;
	return (-1);
}
#endif

#ifndef LOGCMP_TESTING

static int
pool_change(struct pool_state *pool, uintptr_t ident, int16_t filter,
    uint16_t flags, uint32_t fflags, intptr_t data, void *udata)
{
	struct kevent change;

	EV_SET(&change, ident, filter, flags, fflags, data, udata);
	return (kevent(pool->kq, &change, 1, NULL, 0, NULL));
}

static void pool_remove_session(struct pool_state *, struct worker_state *);

static void
pool_unqueue_session(struct pool_state *pool, struct worker_state *state)
{
	struct worker_state **cursor;

	if (!state->pending_queued)
		return;
	cursor = &pool->pending_head;
	while (*cursor != NULL && *cursor != state)
		cursor = &(*cursor)->pending_next;
	if (*cursor == state)
		*cursor = state->pending_next;
	if (pool->pending_tail == state) {
		pool->pending_tail = pool->pending_head;
		while (pool->pending_tail != NULL &&
		    pool->pending_tail->pending_next != NULL)
			pool->pending_tail = pool->pending_tail->pending_next;
	}
	state->pending_next = NULL;
	state->pending_queued = false;
}

static int
pool_queue_session(struct pool_state *pool, struct worker_state *state)
{

	if (!state->active || !state->drain_pending || state->pending_queued)
		return (0);
	state->pending_queued = true;
	state->pending_next = NULL;
	if (pool->pending_tail == NULL)
		pool->pending_head = state;
	else
		pool->pending_tail->pending_next = state;
	pool->pending_tail = state;
	return (pool_change(pool, LOGCMP_POOL_WORK_IDENT, EVFILT_USER, 0,
	    NOTE_TRIGGER, 0, &pool->work_source));
}

static void
pool_run_pending(struct pool_state *pool)
{
	struct worker_state *state;
	uint32_t work;

	for (work = 0; work < LOGCMP_POOL_WORK_BUDGET &&
	    (state = pool->pending_head) != NULL; work++) {
		pool->pending_head = state->pending_next;
		if (pool->pending_head == NULL)
			pool->pending_tail = NULL;
		state->pending_next = NULL;
		state->pending_queued = false;
		if (!state->active)
			continue;
		if (drain_session(state, "fair-drain") == -1) {
			state->terminal_error = errno;
			pool_remove_session(pool, state);
			continue;
		}
		if (pool_queue_session(pool, state) == -1) {
			state->terminal_error = errno;
			pool_remove_session(pool, state);
		}
	}
	if (pool->pending_head != NULL)
		(void)pool_change(pool, LOGCMP_POOL_WORK_IDENT, EVFILT_USER, 0,
		    NOTE_TRIGGER, 0, &pool->work_source);
}

static void
pool_remove_session(struct pool_state *pool, struct worker_state *state)
{
	struct worker_state **cursor;
	int error;

	if (!state->active)
		return;
	error = state->terminal_error;
	cursor = &pool->sessions;
	while (*cursor != NULL && *cursor != state)
		cursor = &(*cursor)->next;
	if (*cursor == state)
		*cursor = state->next;
	pool_unqueue_session(pool, state);
	state->active = false;
	(void)pool_change(pool, state->channel_fd, EVFILT_READ, EV_DELETE,
	    0, 0, NULL);
	close_wakeup(state);
	logcmp_session_destroy(&state->session);
	channel_destroy(state->channel);
	state->channel = NULL;
	atomic_fetch_sub_explicit(pool->admitted, 1, memory_order_release);
	LOGD_PROBE_SESSION_END(state->sink.label, state->sink.instance, error);
	state->next = pool->garbage;
	pool->garbage = state;
}

static void
pool_collect(struct pool_state *pool)
{
	struct worker_state *state;

	while ((state = pool->garbage) != NULL) {
		pool->garbage = state->next;
		free(state);
	}
}

static int
pool_add_session(struct pool_state *pool)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct pool_control_message control;
	struct worker_state *state;
	int fd, error;

	fd = -1;
	if (pool_receive_fd(pool->control_fd, &control, &fd) == -1)
		return (-1);
	if (control.magic != LOGCMP_POOL_CONTROL_MAGIC ||
	    control.reserved != 0 || control.instance == 0 ||
	    strnlen(control.label, sizeof(control.label)) == 0 ||
	    strnlen(control.label, sizeof(control.label)) ==
	    sizeof(control.label) ||
	    atomic_load_explicit(pool->admitted, memory_order_acquire) >
	    pool->capacity) {
		close(fd);
		atomic_fetch_sub_explicit(pool->admitted, 1, memory_order_release);
		return (errno = EPROTO, -1);
	}
	state = calloc(1, sizeof(*state));
	if (state == NULL) {
		error = errno;
		close(fd);
		atomic_fetch_sub_explicit(pool->admitted, 1, memory_order_release);
		return (errno = error, -1);
	}
	state->source_type = POOL_SOURCE_SESSION;
	state->kq = pool->kq;
	state->wake_fd = -1;
	state->channel_fd = -1;
	state->ring_size = pool->config->ring_size;
	state->fallback_drain_ms = pool->config->fallback_drain_ms;
	state->drain_batch = pool->config->drain_batch;
	strlcpy(state->label, control.label, sizeof(state->label));
	state->sink.label = state->label;
	state->sink.instance = control.instance;
	state->sink.storage = pool->storage;
	state->audit = pool->audit;
	state->record_sink = syslog_sink;
	state->record_context = &state->sink;
	state->storage_flush = storage_flush;
	state->storage_query = storage_query;
	state->storage_context = pool->storage;
	logcmp_session_init(&state->session, LOGCMP_MAX_RECORD);
	/*
	 * Seed the accepted counter with the records already durably held for
	 * this consumer's label so that stats.accepted is a cumulative total
	 * that survives the consumer closing and reopening its client, rather
	 * than resetting to zero for each new session.  Best-effort: a failed
	 * query just leaves the counter at zero for this session.
	 */
	{
		uint64_t persisted = 0;

		if (logcmp_storage_count(pool->storage, state->label,
		    strlen(state->label), &persisted) == 0)
			state->session.stats.accepted = persisted;
	}
	if (logcmp_session_configure(&state->session,
	    pool->config->minimum_severity,
	    pool->config->rate_limit_interval_ms,
	    pool->config->rate_limit_burst) == -1 ||
	    harden_worker_leaf_fd(fd) == -1 ||
	    channel_create(fd, &options, &state->channel) == -1 ||
	    channel_set_request_handler(state->channel, handle_request,
	    state) == -1 || channel_set_event_handler(state->channel,
	    handle_event, state) == -1) {
		error = errno != 0 ? errno : EIO;
		if (state->channel != NULL)
			channel_destroy(state->channel);
		else
			close(fd);
		logcmp_session_destroy(&state->session);
		free(state);
		atomic_fetch_sub_explicit(pool->admitted, 1, memory_order_release);
		return (errno = error, -1);
	}
	state->channel_fd = channel_fd(state->channel);
	if (pool_change(pool, state->channel_fd, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, state) == -1 ||
	    pool_change(pool, state->channel_fd, EVFILT_WRITE,
	    EV_ADD | EV_DISABLE, 0, 0, state) == -1) {
		error = errno;
		channel_destroy(state->channel);
		logcmp_session_destroy(&state->session);
		free(state);
		atomic_fetch_sub_explicit(pool->admitted, 1, memory_order_release);
		return (errno = error, -1);
	}
	state->active = true;
	state->next = pool->sessions;
	pool->sessions = state;
	LOGD_PROBE_POOL_ADMIT(pool->shard, state->sink.label,
	    atomic_load_explicit(pool->admitted, memory_order_acquire), 0);
	LOGD_PROBE_SESSION(state->sink.label, state->sink.instance, 0);
	return (0);
}

static int
pool_worker(int control_fd, int audit_fd,
    struct logcmp_storage_session *storage, const struct logcmp_config *config,
    _Atomic uint32_t *admitted, uint32_t capacity, uint32_t shard)
{
	struct pool_state pool;
	struct kevent events[LOGCMP_POOL_MAX_EVENTS];
	struct pool_event_source *source;
	struct worker_state *state, *next;
	int count, error, i, wants_write;

	memset(&pool, 0, sizeof(pool));
	pool.control_fd = control_fd;
	pool.storage = storage;
	pool.config = config;
	pool.admitted = admitted;
	pool.capacity = capacity;
	pool.shard = shard;
	pool.control_source.source_type = POOL_SOURCE_CONTROL;
	pool.timer_source.source_type = POOL_SOURCE_TIMER;
	pool.work_source.source_type = POOL_SOURCE_WORK;
	pool.kq = kqueuex(KQUEUE_CLOEXEC);
	if (pool.kq == -1 || logcmp_storage_session_activate(storage) == -1 ||
	    harden_worker_leaf_fd(storage->control_fd) == -1 ||
	    auditcmp_client_adopt(audit_fd, &pool.audit) == -1 ||
	    harden_worker_leaf_fd(control_fd) == -1 ||
	    harden_worker_leaf_fd(pool.kq) == -1 ||
	    pool_change(&pool, control_fd, EVFILT_READ, EV_ADD | EV_ENABLE,
	    0, 0, &pool.control_source) == -1 ||
	    pool_change(&pool, LOGCMP_DRAIN_TIMER_IDENT, EVFILT_TIMER,
	    EV_ADD | EV_ENABLE, NOTE_MSECONDS, config->fallback_drain_ms,
	    &pool.timer_source) == -1 ||
	    pool_change(&pool, LOGCMP_POOL_WORK_IDENT, EVFILT_USER,
	    EV_ADD | EV_CLEAR, 0, 0, &pool.work_source) == -1)
		return (1);
	if (service_worker_enter_capability_mode(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1)
		return (1);
	error = 0;
	if (write(control_fd, &error, sizeof(error)) != sizeof(error))
		return (1);
	LOGD_PROBE_POOL_START(shard, capacity, 0);
	for (;;) {
		count = kevent(pool.kq, NULL, 0, events, nitems(events), NULL);
		if (count == -1) {
			if (errno == EINTR)
				continue;
			return (1);
		}
		for (i = 0; i < count; i++) {
			source = events[i].udata;
			if (source == NULL || source->source_type == 0)
				continue;
			if (source->source_type == POOL_SOURCE_CONTROL) {
				if ((events[i].flags & EV_EOF) != 0)
					goto shutdown;
				if (pool_add_session(&pool) == -1)
					syslog(LOG_WARNING, "pool admission rejected: %m");
				continue;
			}
			if (source->source_type == POOL_SOURCE_TIMER) {
				for (state = pool.sessions; state != NULL; state = next) {
					next = state->next;
					if (state->session.ring == NULL)
						continue;
					if (drain_session(state, "timer-drain") == -1) {
						state->terminal_error = errno;
						pool_remove_session(&pool, state);
					} else if (pool_queue_session(&pool, state) == -1) {
						state->terminal_error = errno;
						pool_remove_session(&pool, state);
					}
				}
				continue;
			}
			if (source->source_type == POOL_SOURCE_WORK) {
				pool_run_pending(&pool);
				continue;
			}
			state = (void *)source;
			if (!state->active)
				continue;
			if ((events[i].flags & EV_EOF) != 0) {
				state->terminal_error = ECONNRESET;
				pool_remove_session(&pool, state);
				continue;
			}
			if (state->wake_fd >= 0 && events[i].filter == EVFILT_READ &&
			    events[i].ident == (uintptr_t)state->wake_fd) {
				if (logcmp_wakeup_drain(state->wake_fd) == -1 ||
				    drain_session(state, "edge-wakeup") == -1)
					state->terminal_error = errno;
			} else if (events[i].filter == EVFILT_WRITE) {
				if (channel_flush(state->channel) == -1)
					state->terminal_error = errno;
			} else if (events[i].filter == EVFILT_READ &&
			    channel_dispatch(state->channel) == -1)
				state->terminal_error = errno;
			if (state->terminal_error != 0) {
				pool_remove_session(&pool, state);
				continue;
			}
			if (pool_queue_session(&pool, state) == -1) {
				state->terminal_error = errno;
				pool_remove_session(&pool, state);
				continue;
			}
			wants_write = channel_wants_write(state->channel);
			if (wants_write == -1 || pool_change(&pool,
			    state->channel_fd, EVFILT_WRITE,
			    wants_write ? EV_ENABLE : EV_DISABLE, 0, 0, state) == -1) {
				state->terminal_error = errno != 0 ? errno : EIO;
				pool_remove_session(&pool, state);
			}
		}
		pool_collect(&pool);
	}

shutdown:
	LOGD_PROBE_POOL_SHUTDOWN(shard,
	    atomic_load_explicit(admitted, memory_order_acquire), 0);
	for (state = pool.sessions; state != NULL; state = next) {
		next = state->next;
		if (state->session.ring != NULL &&
		    drain_session_until_idle(state, "pool-shutdown",
		    LOGCMP_SHUTDOWN_TIMEOUT_MS) == -1) {
			state->terminal_error = errno;
			audit_policy(state->audit, state->sink.label,
			    "shutdown-drain", errno);
		}
		pool_remove_session(&pool, state);
	}
	(void)logcmp_storage_flush(storage, LOGCMP_STORAGE_TIMEOUT_MS);
	pool_collect(&pool);
	return (0);
}

static void *
pool_watch(void *argument)
{
	struct pool_parent *pool;
	int status;

	pool = argument;
	while (pdwait(pool->process_fd, &status, WEXITED, NULL, NULL) == -1)
		if (errno != EINTR)
			break;
	atomic_store_explicit(&pool->exited, true, memory_order_release);
	if (!atomic_load_explicit(&pool->expected_exit, memory_order_acquire))
		_exit(1);
	return (NULL);
}

static int
start_pool(struct pool_parent *parent,
    int storage_control, const struct logcmp_config *config,
    _Atomic uint32_t *admitted, uint32_t capacity, uint32_t shard)
{
	struct logcmp_storage_session storage;
	int sockets[2], audit_fd, child_error, error, flags, pd;
	ssize_t amount;
	pid_t pid;

	memset(&storage, 0, sizeof(storage));
	storage.control_fd = -1;
	storage.producer_fds = (struct shmring_fds){ -1, -1, -1, -1 };
	audit_fd = -1;
	if (logcmp_storage_attach_pool(storage_control, &storage) == -1 ||
	    logcmp_storage_session_prepare_fork(&storage) == -1 ||
	    auditcmp_client_prepare(&audit_fd) == -1 ||
	    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == -1)
		goto fail;
	if (harden_worker_fd(sockets[1]) == -1)
		goto fail_sockets;
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1)
		goto fail_sockets;
	if (pid == 0) {
		close(sockets[0]);
		close(storage_control);
		_exit(pool_worker(sockets[1], audit_fd, &storage,
		    config, admitted, capacity, shard));
	}
	close(sockets[1]);
	logcmp_storage_session_close(&storage);
	close(audit_fd);
	amount = read(sockets[0], &child_error, sizeof(child_error));
	if (amount != sizeof(child_error) || child_error != 0) {
		error = amount == sizeof(child_error) ? child_error : EIO;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(sockets[0]);
		return (errno = error, -1);
	}
	flags = fcntl(sockets[0], F_GETFL);
	if (flags == -1 || fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK) == -1 ||
	    cap_xfer_limit(sockets[0], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(sockets[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(sockets[0], CAP_CLOEXEC_LOCKED) == -1 ||
	    cap_xfer_limit(pd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(pd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(pd, CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(sockets[0]);
		return (errno = error, -1);
	}
	parent->control_fd = sockets[0];
	parent->process_fd = pd;
	parent->admitted = admitted;
	parent->capacity = capacity;
	parent->shard = shard;
	atomic_init(&parent->expected_exit, false);
	atomic_init(&parent->exited, false);
	error = pthread_create(&parent->watcher, NULL, pool_watch, parent);
	if (error != 0) {
		(void)pdkill(pd, SIGKILL);
		while (pdwait(pd, NULL, WEXITED, NULL, NULL) == -1 && errno == EINTR)
			;
		close(pd);
		close(sockets[0]);
		return (errno = error, -1);
	}
	parent->watcher_started = true;
	return (0);

fail_sockets:
	error = errno;
	close(sockets[0]);
	close(sockets[1]);
	goto fail_common;
fail:
	error = errno != 0 ? errno : EIO;
fail_common:
	if (audit_fd >= 0)
		close(audit_fd);
	logcmp_storage_session_close(&storage);
	return (errno = error, -1);
}

static int
shutdown_pools(struct pool_parent *pools, uint32_t npools)
{
	struct timespec deadline, now, pause;
	uint32_t i;
	int error, join_error;
	bool complete;

	error = 0;
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
		error = errno;
	else {
		deadline.tv_sec += LOGCMP_SHUTDOWN_TIMEOUT_MS / 1000;
		deadline.tv_nsec +=
		    (long)(LOGCMP_SHUTDOWN_TIMEOUT_MS % 1000) * 1000000L;
		if (deadline.tv_nsec >= 1000000000L) {
			deadline.tv_sec++;
			deadline.tv_nsec -= 1000000000L;
		}
	}
	for (i = 0; i < npools; i++) {
		atomic_store_explicit(&pools[i].expected_exit, true,
		    memory_order_release);
		if (pools[i].control_fd >= 0) {
			close(pools[i].control_fd);
			pools[i].control_fd = -1;
		}
	}
	pause.tv_sec = 0;
	pause.tv_nsec = 10000000L;
	for (; error == 0;) {
		complete = true;
		for (i = 0; i < npools; i++)
			if (!atomic_load_explicit(&pools[i].exited,
			    memory_order_acquire))
				complete = false;
		if (complete)
			break;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			error = errno;
			break;
		}
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec &&
		    now.tv_nsec >= deadline.tv_nsec)) {
			error = ETIMEDOUT;
			break;
		}
		(void)nanosleep(&pause, NULL);
	}
	if (error != 0) {
		for (i = 0; i < npools; i++)
			if (pools[i].process_fd >= 0 &&
			    !atomic_load_explicit(&pools[i].exited,
			    memory_order_acquire) &&
			    pdkill(pools[i].process_fd, SIGKILL) == -1 &&
			    errno != ESRCH)
				syslog(LOG_ERR, "cannot kill stuck shard %u: %m",
				    pools[i].shard);
	}
	for (i = 0; i < npools; i++) {
		if (pools[i].watcher_started) {
			join_error = pthread_join(pools[i].watcher, NULL);
			pools[i].watcher_started = false;
			if (join_error != 0 && error == 0)
				error = join_error;
		}
		if (pools[i].process_fd >= 0) {
			close(pools[i].process_fd);
			pools[i].process_fd = -1;
		}
	}
	return (error == 0 ? 0 : (errno = error, -1));
}

static int
shutdown_storage(int *control_fdp, int *process_fdp)
{
	struct timespec deadline, now, pause;
	int error, result, status;

	if (*control_fdp >= 0) {
		close(*control_fdp);
		*control_fdp = -1;
	}
	if (*process_fdp < 0)
		return (0);
	error = 0;
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
		error = errno;
	else
		deadline.tv_sec += LOGCMP_SHUTDOWN_TIMEOUT_MS / 1000;
	pause = (struct timespec){ .tv_nsec = 10000000L };
	while (error == 0) {
		result = pdwait(*process_fdp, &status, WEXITED | WNOHANG, NULL, NULL);
		if (result > 0 || (result == -1 && errno == ECHILD))
			break;
		if (result == -1) {
			if (errno == EINTR)
				continue;
			error = errno;
			break;
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			error = errno;
			break;
		}
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec &&
		    now.tv_nsec >= deadline.tv_nsec)) {
			error = ETIMEDOUT;
			break;
		}
		(void)nanosleep(&pause, NULL);
	}
	if (error != 0) {
		(void)pdkill(*process_fdp, SIGKILL);
		while (pdwait(*process_fdp, &status, WEXITED, NULL, NULL) == -1 &&
		    errno == EINTR)
			;
	}
	close(*process_fdp);
	*process_fdp = -1;
	return (error == 0 ? 0 : (errno = error, -1));
}

static int
dispatch_to_pool(struct pool_parent *pools, uint32_t npools,
    uint32_t *cursor, int fd, const char *label, uint64_t instance)
{
	struct pool_control_message message;
	uint32_t current, i, index;
	int last_error;

	memset(&message, 0, sizeof(message));
	message.magic = LOGCMP_POOL_CONTROL_MAGIC;
	message.instance = instance;
	strlcpy(message.label, label, sizeof(message.label));
	if (harden_transfer_fd(fd) == -1)
		return (-1);
	last_error = ENOSPC;
	for (i = 0; i < npools; i++) {
		index = (*cursor + i) % npools;
		for (;;) {
			current = atomic_load_explicit(pools[index].admitted,
			    memory_order_acquire);
			if (current >= pools[index].capacity)
				break;
			if (atomic_compare_exchange_weak_explicit(
			    pools[index].admitted, &current, current + 1,
			    memory_order_acq_rel, memory_order_acquire)) {
				if (pool_send_fd(pools[index].control_fd, &message,
				    fd) == 0) {
					*cursor = (index + 1) % npools;
					return (0);
				}
				last_error = errno != 0 ? errno : EIO;
				atomic_fetch_sub_explicit(pools[index].admitted, 1,
				    memory_order_release);
				LOGD_PROBE_POOL_ADMIT(pools[index].shard, label,
				    current, last_error);
				break;
			}
		}
	}
	return (errno = last_error, -1);
}

static int
managed_config_path(char *path, size_t path_size)
{
	const char *unit_dir;

	unit_dir = getenv(SERVICE_UNIT_DIR_ENV);
	if (unit_dir == NULL || unit_dir[0] == '\0')
		return (errno = ENOENT, -1);
	if (snprintf(path, path_size, "%s/Config/%s", unit_dir,
	    LOGCMP_CONFIG_NAME) >= (int)path_size)
		return (errno = ENAMETOOLONG, -1);
	return (0);
}

/*
 * Capability-cleanup reclaim (docs/capability-lifecycle-cleanup.md).  serviced
 * pushes SVC_OP_RECLAIM_LABEL over the provider control channel when a consumer
 * bundle is uninstalled; libservice dispatches it to this handler on the control
 * thread while we serve.  The persistent per-label store lives in the separate
 * storage-manager process, so -- exactly like retention -- we route the prune
 * through the storage control channel rather than touching the store from here.
 * The store side is idempotent, so a repeated push, or one for a label that
 * never logged, is a harmless no-op.  This is best-effort: a transport failure
 * only logs, since the store prune is idempotent and safe to re-drive.
 *
 * RECONCILE GAP: this is PUSH-ONLY.  The store keys records by label but cannot
 * cheaply enumerate the distinct labels it holds, so logd runs no reconciliation
 * sweep (service_label_is_live over its own labels) to catch a retirement pushed
 * while it was down.  A future per-label index in the store would let a periodic
 * sweep re-derive the held-label set and reclaim any authority reports retired.
 */
static int logd_reclaim_control = -1;

static void
logd_reclaim_label(const char *label, void *ctx __unused)
{

	if (logd_reclaim_control < 0)
		return;
	if (logcmp_storage_reclaim(logd_reclaim_control, label) == -1)
		syslog(LOG_WARNING, "capability-cleanup reclaim failed: %m");
}

int
main(void)
{
	cap_rights_t rights;
	struct pool_parent *pools;
	struct service_identity identity;
	struct service_context *context;
	struct service_listener *listener;
	struct service_provider *provider;
	struct logcmp_config config;
	char config_path[PATH_MAX];
	_Atomic uint32_t *admitted;
	uint64_t instance;
	uint32_t capacity, cursor, i, remainder, started_pools;
	int fd, storage_control, storage_dir, storage_process;

	openlog("logd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	/* ps(1) shows the unit name, not the ld-elf.so.1 launcher. */
	service_set_proctitle();
	/*
	 * Born in capability mode: load the managed config from the serviced-
	 * delivered Config descriptor (service_config_open), never a global path.
	 * Fall back to the managed path for a legacy/pre-capmode launch.
	 */
	{
		int cfgfd;

		if (service_config_open(LOGCMP_CONFIG_NAME, &cfgfd) == 0) {
			if (logcmp_config_load_fd(cfgfd, &config) == -1) {
				syslog(LOG_ERR, "cannot load managed "
				    "configuration: %m");
				return (1);
			}
		} else if (managed_config_path(config_path,
		    sizeof(config_path)) == -1 ||
		    logcmp_config_load(config_path, &config) == -1) {
			syslog(LOG_ERR, "cannot load managed configuration: %m");
			return (1);
		}
	}
	storage_control = -1;
	storage_dir = -1;
	storage_process = -1;
	pools = NULL;
	started_pools = 0;
	admitted = MAP_FAILED;
	context = NULL;
	if (service_acquire(&context) == -1 ||
	    service_storage_open(context, "state", &storage_dir) == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1)
		goto fail;
	service_release(context);
	context = NULL;
	/*
	 * The segment store creates and reopens files under this directory with
	 * openat(2); an openat(2)ed file never carries a right or status-flag
	 * fcntl its parent directory lacks.  The directory therefore has to hold
	 * every right the store limits its file descriptors to (see store.c's
	 * harden_file) and keep the GETFL|SETFL fcntls the store uses to set
	 * O_APPEND, or storage startup fails ENOTCAPABLE.
	 */
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_PREAD, CAP_PWRITE,
	    CAP_SEEK, CAP_FCNTL, CAP_LOOKUP, CAP_CREATE, CAP_UNLINKAT,
	    CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET, CAP_FSTAT, CAP_FSTATAT,
	    CAP_FTRUNCATE, CAP_FSYNC);
	if (storage_dir == -1 || cap_rights_limit(storage_dir, &rights) == -1 ||
	    cap_fcntls_limit(storage_dir,
	    CAP_FCNTL_GETFL | CAP_FCNTL_SETFL) == -1 ||
	    cap_xfer_limit(storage_dir, CAP_XFER_NONE) == -1 ||
	    cap_cloexec_limit(storage_dir, CAP_CLOEXEC_LOCKED) == -1 ||
	    logcmp_storage_start(storage_dir, config.segment_size,
	    config.max_segments, config.retention_max_age,
	    config.retention_max_bytes,
	    &storage_control, &storage_process) == -1)
		goto fail;
	close(storage_dir);
	storage_dir = -1;
	/*
	 * Route serviced's retirement pushes to the storage manager, which owns
	 * the store.  Registered before service_provider_ready() so no push can
	 * arrive unhandled once we are servable.
	 */
	logd_reclaim_control = storage_control;
	service_set_reclaim_handler(logd_reclaim_label, NULL);
	pools = calloc(config.ingress_shards, sizeof(*pools));
	admitted = mmap(NULL, config.ingress_shards * sizeof(*admitted),
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (pools == NULL || admitted == MAP_FAILED)
		goto fail;
	for (i = 0; i < config.ingress_shards; i++)
		atomic_init(&admitted[i], 0);
	capacity = config.max_sessions / config.ingress_shards;
	remainder = config.max_sessions % config.ingress_shards;
	for (i = 0; i < config.ingress_shards; i++) {
		pools[i].control_fd = -1;
		pools[i].process_fd = -1;
		if (start_pool(&pools[i], storage_control, &config,
		    &admitted[i], capacity + (i < remainder ? 1 : 0), i) == -1)
			goto fail;
		started_pools++;
	}
	if (service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1 ||
	    service_provider_expose(provider, LOGD_NAME,
	    &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	cursor = 0;
	instance = 0;
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			if (errno == EINTR)
				continue;
			if (service_provider_quiescing(provider) == 1) {
				int shutdown_error;

				shutdown_error = shutdown_pools(pools,
				    config.ingress_shards) == -1 ? errno : 0;
				if (shutdown_storage(&storage_control,
				    &storage_process) == -1 && shutdown_error == 0)
					shutdown_error = errno;
				if (service_provider_quiesce_complete(provider,
				    shutdown_error) == -1)
					return (1);
				return (shutdown_error == 0 ? 0 : 1);
			}
			goto fail;
		}
		if (++instance == 0)
			instance++;
		if (dispatch_to_pool(pools, config.ingress_shards, &cursor, fd,
		    identity.client_label, instance) == -1)
			syslog(LOG_WARNING, "session for %s rejected: %m",
			    identity.client_label);
		close(fd);
	}

fail:
	if (context != NULL)
		service_release(context);
	if (pools != NULL && started_pools != 0)
		(void)shutdown_pools(pools, started_pools);
	if (storage_dir >= 0)
		close(storage_dir);
	if (storage_control >= 0)
		(void)shutdown_storage(&storage_control, &storage_process);
	else if (storage_process >= 0)
		(void)shutdown_storage(&storage_control, &storage_process);
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
#endif
