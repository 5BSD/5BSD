/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libservice.h>
#include <logcmp.h>
#include <logcmp_server.h>

#include "logd_probes.h"
#include "storage.h"
#include "store.h"

#define	STORAGE_MAGIC		0x4c535450U	/* LSTP */
#define	STORAGE_VERSION		1U
#define	STORAGE_MAX_SESSIONS	256U
#define	STORAGE_LABEL_MAX	63U
#define	STORAGE_DRAIN_BATCH	256U
#define	STORAGE_MULTIPLEX_LABEL	"@multiplex"
#define	STORAGE_RECORD_VERSION	1U

enum storage_operation {
	STORAGE_OP_READY = 1,
	STORAGE_OP_ATTACH,
	STORAGE_OP_NOTIFY,
	STORAGE_OP_FLUSH,
	STORAGE_OP_QUERY,
	STORAGE_OP_COUNT
};

struct storage_count_request {
	uint16_t label_length;
	uint16_t reserved;
	char label[STORAGE_LABEL_MAX + 1];
};

struct storage_count_reply {
	uint64_t count;
};

struct storage_message {
	uint32_t magic;
	uint16_t version;
	uint16_t operation;
	int32_t status;
	uint32_t flags;
	uint32_t length;
	uint32_t reserved;
};

struct storage_session {
	int fd;
	char label[STORAGE_LABEL_MAX + 1];
	struct shmring *ring;
	bool pending;
	bool multiplex;
};

struct storage_query {
	struct logcmp_store_cursor cursor;
	uint64_t from_ns;
	uint64_t to_ns;
	uint32_t minimum_severity;
	uint32_t match_flags;
	uint16_t label_length;
	uint16_t reserved;
	uint16_t subsystem_length;
	uint16_t category_length;
	char label[STORAGE_LABEL_MAX + 1];
	char subsystem[LOGCMP_MAX_SUBSYSTEM];
	char category[LOGCMP_MAX_CATEGORY];
};

struct storage_record {
	uint16_t version;
	uint16_t label_length;
	uint32_t record_length;
	char label[STORAGE_LABEL_MAX + 1];
	uint8_t record[LOGCMP_MAX_RECORD];
};

struct storage_query_reply {
	struct logcmp_store_cursor cursor;
	uint32_t result;
	uint32_t record_length;
	uint8_t record[LOGCMP_MAX_RECORD];
};

union storage_buffer {
	max_align_t align;
	struct {
		struct storage_message message;
		uint8_t payload[sizeof(struct storage_query_reply)];
	} wire;
};

static void
message_init(struct storage_message *message, uint16_t operation,
    int status, uint32_t length)
{

	memset(message, 0, sizeof(*message));
	message->magic = STORAGE_MAGIC;
	message->version = STORAGE_VERSION;
	message->operation = operation;
	message->status = status;
	message->length = length;
}

static bool
message_valid(const struct storage_message *message, size_t received,
    bool reply)
{

	return (received >= sizeof(*message) &&
	    received == sizeof(*message) + message->length &&
	    message->magic == STORAGE_MAGIC &&
	    message->version == STORAGE_VERSION &&
	    message->operation >= STORAGE_OP_READY &&
	    message->operation <= STORAGE_OP_COUNT &&
	    message->flags == 0 && message->reserved == 0 &&
	    (reply || message->status == 0) &&
	    (!reply || (message->status <= 0 && message->status >= -ELAST)));
}

static int
message_error(const struct storage_message *message, size_t received)
{

	if (received < sizeof(*message))
		return (EMSGSIZE);
	if (received < sizeof(*message) + message->length)
		return (EBADMSG);
	if (received > sizeof(*message) + message->length)
		return (EOVERFLOW);
	if (message->magic != STORAGE_MAGIC)
		return (EBADMSG);
	if (message->version != STORAGE_VERSION)
		return (EPROTONOSUPPORT);
	if (message->operation < STORAGE_OP_READY ||
	    message->operation > STORAGE_OP_COUNT)
		return (ENOSYS);
	if (message->flags != 0 || message->reserved != 0 ||
	    message->status != 0)
		return (EINVAL);
	return (EPROTO);
}

static int
wait_fd(int fd, short events, uint32_t timeout_ms)
{
	struct pollfd descriptor;
	int result;

	descriptor.fd = fd;
	descriptor.events = events;
	descriptor.revents = 0;
	do {
		result = poll(&descriptor, 1, (int)MIN(timeout_ms, INT_MAX));
	} while (result == -1 && errno == EINTR);
	if (result == 0) {
		errno = ETIMEDOUT;
		return (-1);
	}
	if (result == -1)
		return (-1);
	if ((descriptor.revents & events) == 0) {
		errno = ECONNRESET;
		return (-1);
	}
	return (0);
}

static int
deadline_create(uint32_t timeout_ms, struct timespec *deadline)
{

	if (clock_gettime(CLOCK_MONOTONIC, deadline) == -1)
		return (-1);
	deadline->tv_sec += timeout_ms / 1000;
	deadline->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}
	return (0);
}

static int
deadline_remaining(const struct timespec *deadline, uint32_t *remaining)
{
	struct timespec now;
	uint64_t milliseconds;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (-1);
	if (now.tv_sec > deadline->tv_sec || (now.tv_sec == deadline->tv_sec &&
	    now.tv_nsec >= deadline->tv_nsec)) {
		errno = ETIMEDOUT;
		return (-1);
	}
	milliseconds = (uint64_t)(deadline->tv_sec - now.tv_sec) * 1000;
	if (deadline->tv_nsec >= now.tv_nsec)
		milliseconds += (uint64_t)(deadline->tv_nsec - now.tv_nsec +
		    999999L) / 1000000;
	else {
		milliseconds -= 1000;
		milliseconds += (uint64_t)(1000000000L + deadline->tv_nsec -
		    now.tv_nsec + 999999L) / 1000000;
	}
	*remaining = (uint32_t)MIN(milliseconds, UINT32_MAX);
	return (0);
}

static int
send_packet(int fd, const void *data, size_t length, const int *fds,
    size_t nfds)
{
	union {
		struct cmsghdr header;
		uint8_t bytes[CMSG_SPACE(sizeof(int) * (SHMRING_NFDS + 1))];
	} control;
	struct iovec iov;
	struct msghdr message;
	struct cmsghdr *cmsg;
	ssize_t amount;

	memset(&message, 0, sizeof(message));
	iov.iov_base = __DECONST(void *, data);
	iov.iov_len = length;
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	if (nfds != 0) {
		if (fds == NULL || nfds > SHMRING_NFDS + 1)
			return (errno = EINVAL, -1);
		memset(&control, 0, sizeof(control));
		message.msg_control = control.bytes;
		message.msg_controllen = sizeof(control.bytes);
		cmsg = CMSG_FIRSTHDR(&message);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
		memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * nfds);
	}
	do {
		amount = sendmsg(fd, &message, MSG_NOSIGNAL | MSG_EOR);
	} while (amount == -1 && errno == EINTR);
	if (amount == -1)
		return (-1);
	if ((size_t)amount != length) {
		errno = amount == 0 ? EAGAIN : EIO;
		return (-1);
	}
	return (0);
}

static int
send_packet_until(int fd, const void *data, size_t length,
    const struct timespec *deadline)
{
	uint32_t remaining;

	for (;;) {
		if (send_packet(fd, data, length, NULL, 0) == 0)
			return (0);
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS)
			return (-1);
		if (deadline_remaining(deadline, &remaining) == -1 ||
		    wait_fd(fd, POLLOUT, remaining) == -1)
			return (-1);
	}
}

static ssize_t
receive_packet(int fd, void *data, size_t capacity, int *fds,
    size_t fd_capacity, size_t *nfdsp)
{
	union {
		struct cmsghdr header;
		uint8_t bytes[CMSG_SPACE(sizeof(int) * (SHMRING_NFDS + 2))];
	} control;
	struct iovec iov;
	struct msghdr message;
	struct cmsghdr *cmsg;
	ssize_t amount;
	int fd_storage[SHMRING_NFDS + 2];
	size_t nfds, i, stored;
	bool invalid;

	if (nfdsp != NULL)
		*nfdsp = 0;
	memset(&message, 0, sizeof(message));
	memset(&control, 0, sizeof(control));
	iov.iov_base = data;
	iov.iov_len = capacity;
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	do {
		amount = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
	} while (amount == -1 && errno == EINTR);
	if (amount <= 0)
		return (amount);
	if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
		errno = EMSGSIZE;
		return (-1);
	}
	stored = 0;
	invalid = false;
	for (cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&message, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
			invalid = true;
			continue;
		}
		nfds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		if (nfds > nitems(fd_storage))
			nfds = nitems(fd_storage);
		memcpy(fd_storage, CMSG_DATA(cmsg), nfds * sizeof(int));
		for (i = 0; i < nfds; i++) {
			if (fds != NULL && stored < fd_capacity)
				fds[stored++] = fd_storage[i];
			else {
				close(fd_storage[i]);
				invalid = true;
			}
		}
	}
	if (invalid) {
		for (i = 0; i < stored; i++)
			close(fds[i]);
		errno = EPROTO;
		return (-1);
	}
	if (nfdsp != NULL)
		*nfdsp = stored;
	return (amount);
}

static int
send_status(int fd, uint16_t operation, int error)
{
	struct storage_message reply;

	message_init(&reply, operation, error == 0 ? 0 : -error, 0);
	return (send_packet(fd, &reply, sizeof(reply), NULL, 0));
}

static int
socket_type(int fd)
{
	int type;
	socklen_t length;

	length = sizeof(type);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == -1)
		return (-1);
	if (length != sizeof(type) || type != SOCK_SEQPACKET) {
		errno = EPROTOTYPE;
		return (-1);
	}
	return (0);
}

static int
handle_control(int fd, struct storage_session *sessions, size_t *nsessions)
{
	union storage_buffer buffer;
	struct storage_message *message;
	struct shmring_fds ringfds;
	int received_fds[SHMRING_NFDS + 1], session_fd, error;
	size_t nfds;
	ssize_t amount;

	session_fd = -1;
	nfds = 0;
	amount = receive_packet(fd, &buffer, sizeof(buffer), received_fds,
	    nitems(received_fds), &nfds);
	if (amount <= 0)
		return (amount == 0 ? 1 : -1);
	if (nfds == nitems(received_fds)) {
		session_fd = received_fds[0];
		ringfds = (struct shmring_fds){ received_fds[1], received_fds[2],
		    received_fds[3], received_fds[4] };
	}
	message = &buffer.wire.message;
	if (!message_valid(message, (size_t)amount, false) ||
	    message->operation != STORAGE_OP_ATTACH || message->length == 0 ||
	    message->length > STORAGE_LABEL_MAX ||
	    nfds != nitems(received_fds) || session_fd < 0 ||
	    memchr(message + 1, '\0', message->length) != NULL ||
	    *nsessions >= STORAGE_MAX_SESSIONS || socket_type(session_fd) == -1 ||
	    shmring_open(&sessions[*nsessions].ring, &ringfds,
	    SHMRING_ROLE_CONSUMER) == -1 ||
	    service_harden_fd(session_fd, SERVICE_HARDEN_CLOFORK_ONCE) == -1) {
		error = errno != 0 ? errno : EPROTO;
		for (size_t i = 0; i < nfds; i++)
			close(received_fds[i]);
		if (*nsessions < STORAGE_MAX_SESSIONS &&
		    sessions[*nsessions].ring != NULL) {
			shmring_close(sessions[*nsessions].ring);
			sessions[*nsessions].ring = NULL;
		}
		(void)send_status(fd, STORAGE_OP_ATTACH, error);
		return (0);
	}
	for (size_t i = 1; i < nfds; i++)
		close(received_fds[i]);
	sessions[*nsessions].fd = session_fd;
	memcpy(sessions[*nsessions].label, message + 1, message->length);
	sessions[*nsessions].label[message->length] = '\0';
	sessions[*nsessions].multiplex = strcmp(sessions[*nsessions].label,
	    STORAGE_MULTIPLEX_LABEL) == 0;
	(*nsessions)++;
	return (send_status(fd, STORAGE_OP_ATTACH, 0));
}

static int
drain_storage_session(struct storage_session *session,
    struct logcmp_store *store, size_t budget, bool *pending)
{
	struct storage_record envelope;
	size_t drained;
	ssize_t length;

	if (pending != NULL)
		*pending = false;
	for (drained = 0; drained < budget; drained++) {
		length = shmring_read_record(session->ring, &envelope,
		    sizeof(envelope));
		if (length == -1)
			return (errno == EAGAIN ? 0 : -1);
		if ((size_t)length < offsetof(struct storage_record, record) ||
		    envelope.version != STORAGE_RECORD_VERSION ||
		    envelope.label_length == 0 ||
		    envelope.label_length > STORAGE_LABEL_MAX ||
		    envelope.record_length > LOGCMP_MAX_RECORD ||
		    (size_t)length != offsetof(struct storage_record, record) +
		    envelope.record_length ||
		    memchr(envelope.label, '\0', envelope.label_length) != NULL ||
		    (!session->multiplex &&
		    (strlen(session->label) != envelope.label_length ||
		    memcmp(session->label, envelope.label,
		    envelope.label_length) != 0)))
			return (errno = EPROTO, -1);
		envelope.label[envelope.label_length] = '\0';
		if (logcmp_validate_record((const void *)envelope.record,
		    envelope.record_length) == -1 ||
		    logcmp_store_append(store, envelope.label,
		    (const void *)envelope.record, envelope.record_length,
		    false) == -1)
			return (-1);
	}
	/* The exact-boundary case may cause one harmless extra drain turn. */
	if (pending != NULL)
		*pending = true;
	return (0);
}

static int
handle_session(struct storage_session *session, struct logcmp_store *store)
{
	union storage_buffer buffer;
	struct storage_message *message;
	struct storage_query *query;
	struct storage_query_reply query_reply;
	size_t record_length;
	int error;
	ssize_t amount;

	amount = receive_packet(session->fd, &buffer, sizeof(buffer), NULL, 0,
	    NULL);
	if (amount <= 0)
		return (1);
	message = &buffer.wire.message;
	if (!message_valid(message, (size_t)amount, false)) {
		(void)send_status(session->fd, STORAGE_OP_NOTIFY,
		    message_error(message, (size_t)amount));
		return (1);
	}
	error = 0;
	switch (message->operation) {
	case STORAGE_OP_NOTIFY:
		if (message->length != 0 ||
		    drain_storage_session(session, store, STORAGE_DRAIN_BATCH,
		    &session->pending) == -1) {
			error = errno != 0 ? errno : EPROTO;
			(void)send_status(session->fd, STORAGE_OP_NOTIFY, error);
			return (1);
		}
		break;
	case STORAGE_OP_FLUSH:
		if (message->length != 0)
			error = EPROTO;
		else if (drain_storage_session(session, store, SIZE_MAX,
		    &session->pending) == -1)
			error = errno != 0 ? errno : EIO;
		else if (logcmp_store_flush(store) == -1)
			error = errno != 0 ? errno : EIO;
		if (send_status(session->fd, STORAGE_OP_FLUSH, error) == -1)
			return (1);
		break;
	case STORAGE_OP_QUERY:
		if (message->length != sizeof(*query)) {
			error = EPROTO;
			(void)send_status(session->fd, STORAGE_OP_QUERY, error);
			return (1);
		}
		query = (void *)(message + 1);
		if (query->reserved != 0 || query->label_length == 0 ||
		    query->label_length > STORAGE_LABEL_MAX ||
		    memchr(query->label, '\0', query->label_length) != NULL ||
		    (!session->multiplex &&
		    (strlen(session->label) != query->label_length ||
		    memcmp(session->label, query->label,
		    query->label_length) != 0)) ||
		    query->minimum_severity > LOGCMP_SEVERITY_FATAL + 3 ||
		    (query->match_flags & ~LOGCMP_QUERY_MATCH_MASK) != 0 ||
		    query->subsystem_length > LOGCMP_MAX_SUBSYSTEM ||
		    query->category_length > LOGCMP_MAX_CATEGORY ||
		    (query->to_ns != 0 && query->from_ns > query->to_ns)) {
			error = EINVAL;
			(void)send_status(session->fd, STORAGE_OP_QUERY, error);
			break;
		}
		memset(&query_reply, 0, sizeof(query_reply));
		query_reply.cursor = query->cursor;
		if (drain_storage_session(session, store, SIZE_MAX,
		    &session->pending) == -1) {
			error = errno != 0 ? errno : EIO;
			(void)send_status(session->fd, STORAGE_OP_QUERY, error);
			break;
		}
		query->label[query->label_length] = '\0';
		{
			struct logcmp_query_filter filter;

			memset(&filter, 0, sizeof(filter));
			filter.from_ns = query->from_ns;
			filter.to_ns = query->to_ns;
			filter.match_flags = query->match_flags;
			filter.subsystem_length = query->subsystem_length;
			filter.category_length = query->category_length;
			filter.subsystem = query->subsystem;
			filter.category = query->category;
			query_reply.result = logcmp_store_query_next_filtered(store,
			    query->label, query->minimum_severity, &filter,
			    &query_reply.cursor, query_reply.record,
			    sizeof(query_reply.record), &record_length);
		}
		if ((int32_t)query_reply.result == -1) {
			error = errno != 0 ? errno : EIO;
			if (error == EILSEQ)
				LOGD_PROBE_CORRUPTION(
				    query_reply.cursor.generation,
				    query_reply.cursor.offset, error);
			(void)send_status(session->fd, STORAGE_OP_QUERY, error);
			break;
		}
		query_reply.record_length = (uint32_t)record_length;
		message_init(&buffer.wire.message, STORAGE_OP_QUERY, 0,
		    offsetof(struct storage_query_reply, record) + record_length);
		memcpy(buffer.wire.payload, &query_reply,
		    offsetof(struct storage_query_reply, record) + record_length);
		if (send_packet(session->fd, &buffer,
		    sizeof(buffer.wire.message) + buffer.wire.message.length,
		    NULL, 0) == -1)
			return (1);
		break;
	case STORAGE_OP_COUNT: {
		struct storage_count_request *count_req;
		struct storage_count_reply count_reply;

		if (message->length != sizeof(*count_req)) {
			(void)send_status(session->fd, STORAGE_OP_COUNT, EPROTO);
			return (1);
		}
		count_req = (void *)(message + 1);
		if (count_req->reserved != 0 || count_req->label_length == 0 ||
		    count_req->label_length > STORAGE_LABEL_MAX ||
		    memchr(count_req->label, '\0', count_req->label_length) != NULL ||
		    (!session->multiplex &&
		    (strlen(session->label) != count_req->label_length ||
		    memcmp(session->label, count_req->label,
		    count_req->label_length) != 0))) {
			(void)send_status(session->fd, STORAGE_OP_COUNT, EINVAL);
			break;
		}
		count_req->label[count_req->label_length] = '\0';
		memset(&count_reply, 0, sizeof(count_reply));
		count_reply.count = logcmp_store_label_count(store,
		    count_req->label);
		message_init(&buffer.wire.message, STORAGE_OP_COUNT, 0,
		    sizeof(count_reply));
		memcpy(buffer.wire.payload, &count_reply, sizeof(count_reply));
		if (send_packet(session->fd, &buffer,
		    sizeof(buffer.wire.message) + sizeof(count_reply), NULL, 0) == -1)
			return (1);
		break;
	}
	default:
		return (1);
	}
	return (0);
}

/*
 * Bounded periodic retention pass.  Runs at most once per second so age-based
 * pruning happens even without rotations, without turning the storage loop into
 * a directory-scanning hot path.  Best-effort: a failed pass is retried next
 * second and never disturbs ingestion.
 */
static void
maybe_enforce_retention(struct logcmp_store *store, struct timespec *last)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return;
	if (last->tv_sec != 0 && now.tv_sec < last->tv_sec + 1)
		return;
	*last = now;
	(void)logcmp_store_enforce_retention(store);
}

int
logcmp_storage_manager_run(int dirfd, int control_fd, uint64_t segment_limit,
    uint32_t max_segments, uint64_t retention_max_age, uint64_t retention_max_bytes,
    bool sandbox)
{
	struct storage_session sessions[STORAGE_MAX_SESSIONS];
	struct logcmp_store *store;
	struct pollfd descriptors[STORAGE_MAX_SESSIONS + 1];
	struct timespec retention_at;
	size_t i, nsessions;
	int error, result;
	bool control_open = true;
	bool retention_enabled;

	if (logcmp_store_open(dirfd, segment_limit, max_segments, &store) == -1) {
		error = errno != 0 ? errno : EIO;
		/*
		 * The store surfaces unrecoverable active-segment corruption as
		 * EILSEQ (store.h).  As the owner, quarantine the bad segment
		 * aside and reopen with a fresh one so a single corrupt record
		 * from an unclean shutdown does not brick the logging plane.
		 * The quarantined segment is preserved for post-mortem.  If the
		 * quarantine or the reopen still fails, surface the error.
		 */
		if (error == EILSEQ) {
			LOGD_PROBE_QUARANTINE(0, error);
			if (logcmp_store_quarantine(dirfd) == 0 &&
			    logcmp_store_open(dirfd, segment_limit, max_segments,
			    &store) == 0)
				error = 0;
			else
				error = errno != 0 ? errno : EIO;
		}
		if (error != 0) {
			if (error == EILSEQ)
				LOGD_PROBE_CORRUPTION(0, 0, error);
			(void)send_status(control_fd, STORAGE_OP_READY, error);
			return (1);
		}
	}
	logcmp_store_set_retention(store, retention_max_age, retention_max_bytes);
	retention_enabled = retention_max_age != 0 || retention_max_bytes != 0;
	retention_at = (struct timespec){ 0, 0 };
	memset(sessions, 0, sizeof(sessions));
	if (sandbox && service_worker_enter_capability_mode(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1) {
		error = errno != 0 ? errno : EPERM;
		(void)send_status(control_fd, STORAGE_OP_READY, error);
		logcmp_store_close(store);
		return (1);
	}
	if (send_status(control_fd, STORAGE_OP_READY, 0) == -1) {
		logcmp_store_close(store);
		close(dirfd);
		return (1);
	}
	nsessions = 0;
	for (;;) {
		if (retention_enabled)
			maybe_enforce_retention(store, &retention_at);
		/*
		 * Finish bounded drain work before blocking.  Each session gets at
		 * most one batch per round so a hot producer cannot monopolize the
		 * persistent writer.
		 */
		for (i = nsessions; i-- > 0;) {
			if (!sessions[i].pending)
				continue;
			if (drain_storage_session(&sessions[i], store,
			    STORAGE_DRAIN_BATCH, &sessions[i].pending) == 0)
				continue;
			close(sessions[i].fd);
			shmring_close(sessions[i].ring);
			if (i + 1 < nsessions)
				memmove(&sessions[i], &sessions[i + 1],
				    (nsessions - i - 1) * sizeof(sessions[0]));
			nsessions--;
		}
		descriptors[0] = (struct pollfd){
		    .fd = control_open ? control_fd : -1, .events = POLLIN };
		for (i = 0; i < nsessions; i++)
			descriptors[i + 1] = (struct pollfd){
			    .fd = sessions[i].fd, .events = POLLIN };
		do {
			result = poll(descriptors, nsessions + 1, 10);
		} while (result == -1 && errno == EINTR);
		if (result == -1)
			break;
		if (result == 0) {
			for (i = nsessions; i-- > 0;) {
				if (drain_storage_session(&sessions[i], store,
				    STORAGE_DRAIN_BATCH, &sessions[i].pending) == 0)
					continue;
				close(sessions[i].fd);
				shmring_close(sessions[i].ring);
				if (i + 1 < nsessions)
					memmove(&sessions[i], &sessions[i + 1],
					    (nsessions - i - 1) * sizeof(sessions[0]));
				nsessions--;
			}
			continue;
		}
		/*
		 * The attach-control channel closing means the provider will not
		 * request new sessions, but sessions already handed out stay live
		 * until their producers drain.  Stop watching control and keep
		 * serving; exit only once the last session is gone.  Tearing the
		 * whole manager down here would revoke every worker's storage the
		 * moment the last attach completed.
		 */
		if ((descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			control_open = false;
			if (nsessions == 0)
				break;
			continue;
		}
		if ((descriptors[0].revents & POLLIN) != 0 &&
		    handle_control(control_fd, sessions, &nsessions) != 0)
			break;
		/* The control handler may have grown sessions after poll(). */
		if ((descriptors[0].revents & POLLIN) != 0)
			continue;
		/*
		 * Walk backwards so removing a ready session cannot invalidate the
		 * poll-to-session index of an entry we have not processed yet.
		 */
		for (i = nsessions; i-- > 0;) {
			if ((descriptors[i + 1].revents &
			    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) == 0)
				continue;
			if (handle_session(&sessions[i], store) == 0)
				continue;
			close(sessions[i].fd);
			shmring_close(sessions[i].ring);
			if (i + 1 < nsessions)
				memmove(&sessions[i], &sessions[i + 1],
				    (nsessions - i - 1) * sizeof(sessions[0]));
			nsessions--;
		}
		if (!control_open && nsessions == 0)
			break;
	}
	for (i = 0; i < nsessions; i++) {
		close(sessions[i].fd);
		shmring_close(sessions[i].ring);
	}
	logcmp_store_close(store);
	close(dirfd);
	return (0);
}

static int
receive_status(int fd, uint16_t operation, uint32_t timeout_ms)
{
	struct storage_message reply;
	ssize_t amount;

	if (wait_fd(fd, POLLIN, timeout_ms) == -1)
		return (-1);
	amount = receive_packet(fd, &reply, sizeof(reply), NULL, 0, NULL);
	if (amount <= 0 || !message_valid(&reply, amount, true) ||
	    reply.length != 0) {
		errno = amount == 0 ? ECONNRESET : EPROTO;
		return (-1);
	}
	if (reply.status != 0) {
		errno = -reply.status;
		return (-1);
	}
	if (reply.operation != operation) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int
receive_status_until(int fd, uint16_t operation,
    const struct timespec *deadline)
{
	uint32_t remaining;

	if (deadline_remaining(deadline, &remaining) == -1)
		return (-1);
	return (receive_status(fd, operation, remaining));
}

int
logcmp_storage_test_start(int dirfd, uint64_t segment_limit,
    uint32_t max_segments, uint64_t retention_max_age,
    uint64_t retention_max_bytes, int *control_fdp, pid_t *pidp)
{
	int sockets[2], error;
	pid_t pid;

	if (dirfd < 0 || control_fdp == NULL ||
	    max_segments < LOGCMP_STORE_SEGMENTS_MIN ||
	    max_segments > LOGCMP_STORE_SEGMENTS_MAX) {
		errno = EINVAL;
		return (-1);
	}
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == -1)
		return (-1);
	pid = fork();
	if (pid == -1) {
		error = errno;
		close(sockets[0]);
		close(sockets[1]);
		errno = error;
		return (-1);
	}
	if (pid == 0) {
		close(sockets[0]);
		_exit(logcmp_storage_manager_run(dirfd, sockets[1], segment_limit,
		    max_segments, retention_max_age, retention_max_bytes, false));
	}
	close(sockets[1]);
	if (receive_status(sockets[0], STORAGE_OP_READY,
	    LOGCMP_STORAGE_TIMEOUT_MS) == -1 ||
	    service_harden_fd(sockets[0], 0) == -1) {
		error = errno;
		close(sockets[0]);
		errno = error;
		return (-1);
	}
	*control_fdp = sockets[0];
	if (pidp != NULL)
		*pidp = pid;
	return (0);
}

int
logcmp_storage_start(int dirfd, uint64_t segment_limit, uint32_t max_segments,
    uint64_t retention_max_age, uint64_t retention_max_bytes,
    int *control_fdp, int *process_fdp)
{
	int sockets[2], pd, error;
	pid_t pid;

	if (dirfd < 0 || control_fdp == NULL || process_fdp == NULL ||
	    max_segments < LOGCMP_STORE_SEGMENTS_MIN ||
	    max_segments > LOGCMP_STORE_SEGMENTS_MAX) {
		errno = EINVAL;
		return (-1);
	}
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == -1)
		return (-1);
	if (cap_clofork_limit(dirfd, CAP_CLOFORK_ONCE) == -1 ||
	    service_harden_fd(sockets[0], 0) == -1 ||
	    service_harden_fd(sockets[1], SERVICE_HARDEN_CLOFORK_ONCE) == -1) {
		error = errno;
		close(sockets[0]);
		close(sockets[1]);
		return (errno = error, -1);
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		error = errno;
		close(sockets[0]);
		close(sockets[1]);
		errno = error;
		return (-1);
	}
	if (pid == 0) {
		close(sockets[0]);
		_exit(logcmp_storage_manager_run(dirfd, sockets[1], segment_limit,
		    max_segments, retention_max_age, retention_max_bytes, true));
	}
	close(sockets[1]);
	if (receive_status(sockets[0], STORAGE_OP_READY,
	    LOGCMP_STORAGE_TIMEOUT_MS) == -1 ||
	    service_harden_fd(sockets[0], 0) == -1 ||
	    service_harden_fd(pd, 0) == -1) {
		error = errno;
		(void)pdkill(pd, SIGKILL);
		while (pdwait(pd, NULL, WEXITED, NULL, NULL) == -1 && errno == EINTR)
			;
		close(pd);
		close(sockets[0]);
		errno = error;
		return (-1);
	}
	*control_fdp = sockets[0];
	*process_fdp = pd;
	return (0);
}

int
logcmp_storage_attach(int control_fd, const char *label,
    struct logcmp_storage_session *session)
{
	union storage_buffer buffer;
	struct storage_message *message;
	struct shmring_fds consumer;
	uint64_t generation;
	int sockets[2], attached[SHMRING_NFDS + 1], error, flags;
	size_t length;

	if (control_fd < 0 || label == NULL || session == NULL ||
	    (length = strnlen(label, STORAGE_LABEL_MAX + 1)) == 0 ||
	    length > STORAGE_LABEL_MAX) {
		errno = EINVAL;
		return (-1);
	}
	memset(session, 0, sizeof(*session));
	session->control_fd = -1;
	session->producer_fds = (struct shmring_fds){ -1, -1, -1, -1 };
	consumer = (struct shmring_fds){ -1, -1, -1, -1 };
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == -1)
		return (-1);
	arc4random_buf(&generation, sizeof(generation));
	if (generation == 0)
		generation = 1;
	if (shmring_create(LOGCMP_STORAGE_RING_SIZE, SHMRING_MODE_RECORD,
	    sizeof(struct storage_record), generation, &session->producer_fds,
	    &consumer) == -1)
		goto fail;
	message = &buffer.wire.message;
	message_init(message, STORAGE_OP_ATTACH, 0, length);
	memcpy(message + 1, label, length);
	attached[0] = sockets[1];
	attached[1] = consumer.config_fd;
	attached[2] = consumer.data_fd;
	attached[3] = consumer.head_fd;
	attached[4] = consumer.tail_fd;
	if (cap_xfer_limit(sockets[1], CAP_XFER_ONCE) == -1 ||
	    send_packet(control_fd, &buffer, sizeof(*message) + length,
	    attached, nitems(attached)) == -1 ||
	    receive_status(control_fd, STORAGE_OP_ATTACH,
	    LOGCMP_STORAGE_TIMEOUT_MS) == -1 ||
	    cap_xfer_limit(sockets[0], CAP_XFER_NONE) == -1 ||
	    cap_cloexec_limit(sockets[0], CAP_CLOEXEC_LOCKED) == -1) {
		goto fail;
	}
	flags = fcntl(sockets[0], F_GETFL);
	if (flags == -1 || fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK) == -1)
		goto fail;
	close(sockets[1]);
	shmring_fds_close(&consumer);
	session->control_fd = sockets[0];
	memcpy(session->label, label, length);
	session->label[length] = '\0';
	session->multiplex = strcmp(label, STORAGE_MULTIPLEX_LABEL) == 0;
	return (0);

fail:
	error = errno;
	close(sockets[0]);
	close(sockets[1]);
	shmring_fds_close(&session->producer_fds);
	shmring_fds_close(&consumer);
	errno = error;
	return (-1);
}

int
logcmp_storage_attach_pool(int control_fd,
    struct logcmp_storage_session *session)
{

	return (logcmp_storage_attach(control_fd, STORAGE_MULTIPLEX_LABEL,
	    session));
}

int
logcmp_storage_session_prepare_fork(struct logcmp_storage_session *session)
{
	int descriptors[SHMRING_NFDS + 1];
	size_t i;

	if (session == NULL || session->control_fd < 0 || session->ring != NULL)
		return (errno = EINVAL, -1);
	descriptors[0] = session->control_fd;
	descriptors[1] = session->producer_fds.config_fd;
	descriptors[2] = session->producer_fds.data_fd;
	descriptors[3] = session->producer_fds.head_fd;
	descriptors[4] = session->producer_fds.tail_fd;
	for (i = 0; i < nitems(descriptors); i++) {
		if (descriptors[i] < 0 ||
		    service_harden_fd(descriptors[i],
		    SERVICE_HARDEN_CLOFORK_ONCE) == -1)
			return (-1);
	}
	return (0);
}

int
logcmp_storage_session_activate(struct logcmp_storage_session *session)
{
	int error;

	if (session == NULL || session->control_fd < 0 || session->ring != NULL)
		return (errno = EINVAL, -1);
	if (shmring_open(&session->ring, &session->producer_fds,
	    SHMRING_ROLE_PRODUCER) == -1)
		return (-1);
	error = errno;
	shmring_fds_close(&session->producer_fds);
	errno = error;
	return (0);
}

void
logcmp_storage_session_close(struct logcmp_storage_session *session)
{
	if (session == NULL)
		return;
	shmring_close(session->ring);
	shmring_fds_close(&session->producer_fds);
	if (session->control_fd >= 0)
		close(session->control_fd);
	memset(session, 0, sizeof(*session));
	session->control_fd = -1;
	session->producer_fds = (struct shmring_fds){ -1, -1, -1, -1 };
}

int
logcmp_storage_append_for(struct logcmp_storage_session *session,
    const char *label, const struct logcmp_record *record, size_t length)
{
	struct storage_record envelope;
	struct storage_message message;
	bool was_empty;
	size_t label_length;

	if (session == NULL || session->control_fd < 0 || session->ring == NULL ||
	    label == NULL ||
	    (label_length = strnlen(label, STORAGE_LABEL_MAX + 1)) == 0 ||
	    label_length > STORAGE_LABEL_MAX ||
	    record == NULL || length > LOGCMP_MAX_RECORD ||
	    logcmp_validate_record(record, length) == -1) {
		if (errno == 0)
			errno = EINVAL;
		return (-1);
	}
	if (!session->multiplex && strcmp(session->label, label) != 0)
		return (errno = EACCES, -1);
	memset(&envelope, 0, offsetof(struct storage_record, record));
	envelope.version = STORAGE_RECORD_VERSION;
	envelope.label_length = (uint16_t)label_length;
	envelope.record_length = (uint32_t)length;
	memcpy(envelope.label, label, label_length);
	memcpy(envelope.record, record, length);
	was_empty = shmring_readable(session->ring) == 0;
	if (shmring_write_record(session->ring, &envelope,
	    offsetof(struct storage_record, record) + length) == -1)
		return (-1);
	if (was_empty) {
		message_init(&message, STORAGE_OP_NOTIFY, 0, 0);
		if (send_packet(session->control_fd, &message, sizeof(message),
		    NULL, 0) == -1 && errno != EAGAIN && errno != EWOULDBLOCK &&
		    errno != ENOBUFS)
			return (-1);
	}
	return (0);
}

int
logcmp_storage_append(struct logcmp_storage_session *session,
    const struct logcmp_record *record, size_t length)
{

	return (logcmp_storage_append_for(session,
	    session != NULL ? session->label : NULL, record, length));
}

int
logcmp_storage_flush(struct logcmp_storage_session *session,
    uint32_t timeout_ms)
{
	struct storage_message message;
	struct timespec deadline;

	if (session == NULL || session->control_fd < 0 || session->ring == NULL ||
	    timeout_ms == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (deadline_create(timeout_ms, &deadline) == -1)
		return (-1);
	message_init(&message, STORAGE_OP_FLUSH, 0, 0);
	if (send_packet_until(session->control_fd, &message, sizeof(message),
	    &deadline) == -1)
		return (-1);
	return (receive_status_until(session->control_fd, STORAGE_OP_FLUSH,
	    &deadline));
}

int
logcmp_storage_count(struct logcmp_storage_session *session, const char *label,
    size_t label_length, uint64_t *countp)
{
	union storage_buffer buffer;
	struct storage_message *message;
	struct storage_count_request *request;
	struct storage_count_reply *reply;
	struct timespec deadline;
	uint32_t remaining;
	ssize_t amount;

	if (session == NULL || session->control_fd < 0 || countp == NULL ||
	    label == NULL || label_length == 0 ||
	    label_length > STORAGE_LABEL_MAX)
		return (errno = EINVAL, -1);
	message = &buffer.wire.message;
	message_init(message, STORAGE_OP_COUNT, 0, sizeof(*request));
	request = (void *)(message + 1);
	memset(request, 0, sizeof(*request));
	request->label_length = (uint16_t)label_length;
	memcpy(request->label, label, label_length);
	if (deadline_create(LOGCMP_STORAGE_TIMEOUT_MS, &deadline) == -1)
		return (-1);
	if (send_packet_until(session->control_fd, &buffer,
	    sizeof(*message) + sizeof(*request), &deadline) == -1)
		return (-1);
	if (deadline_remaining(&deadline, &remaining) == -1 ||
	    wait_fd(session->control_fd, POLLIN, remaining) == -1)
		return (-1);
	amount = receive_packet(session->control_fd, &buffer, sizeof(buffer),
	    NULL, 0, NULL);
	if (amount <= 0 || !message_valid(message, (size_t)amount, true)) {
		errno = amount == 0 ? ECONNRESET : EPROTO;
		return (-1);
	}
	if (message->status != 0)
		return (errno = -message->status, -1);
	if (message->operation != STORAGE_OP_COUNT ||
	    message->length != sizeof(*reply))
		return (errno = EPROTO, -1);
	reply = (void *)(message + 1);
	*countp = reply->count;
	return (0);
}

int
logcmp_storage_query_next_filtered_for(struct logcmp_storage_session *session,
    const char *label, uint32_t minimum_severity,
    const struct logcmp_query_filter *filter,
    struct logcmp_store_cursor *cursor, void *record, size_t capacity,
    size_t *record_length, uint32_t timeout_ms)
{
	union storage_buffer buffer;
	struct storage_message *message;
	struct storage_query *query;
	struct storage_query_reply *reply;
	struct logcmp_store_cursor working_cursor;
	struct timespec deadline;
	uint32_t remaining;
	ssize_t amount;
	size_t label_length;

	if (session == NULL || session->control_fd < 0 || session->ring == NULL ||
	    label == NULL ||
	    (label_length = strnlen(label, STORAGE_LABEL_MAX + 1)) == 0 ||
	    label_length > STORAGE_LABEL_MAX ||
	    cursor == NULL || record == NULL || record_length == NULL ||
	    capacity < sizeof(struct logcmp_record) || timeout_ms == 0 ||
	    minimum_severity > LOGCMP_SEVERITY_FATAL + 3)
		return (errno = EINVAL, -1);
	if (filter != NULL &&
	    ((filter->match_flags & ~LOGCMP_QUERY_MATCH_MASK) != 0 ||
	    filter->subsystem_length > LOGCMP_MAX_SUBSYSTEM ||
	    filter->category_length > LOGCMP_MAX_CATEGORY ||
	    (filter->to_ns != 0 && filter->from_ns > filter->to_ns)))
		return (errno = EINVAL, -1);
	if (!session->multiplex && strcmp(session->label, label) != 0)
		return (errno = EACCES, -1);
	*record_length = 0;
	if (deadline_create(timeout_ms, &deadline) == -1)
		return (-1);
	working_cursor = *cursor;

again:
	message = &buffer.wire.message;
	message_init(message, STORAGE_OP_QUERY, 0, sizeof(*query));
	query = (void *)(message + 1);
	memset(query, 0, sizeof(*query));
	query->cursor = working_cursor;
	query->minimum_severity = minimum_severity;
	query->label_length = (uint16_t)label_length;
	memcpy(query->label, label, label_length);
	if (filter != NULL) {
		query->from_ns = filter->from_ns;
		query->to_ns = filter->to_ns;
		query->match_flags = filter->match_flags;
		query->subsystem_length = filter->subsystem_length;
		query->category_length = filter->category_length;
		if (filter->subsystem_length != 0)
			memcpy(query->subsystem, filter->subsystem,
			    filter->subsystem_length);
		if (filter->category_length != 0)
			memcpy(query->category, filter->category,
			    filter->category_length);
	}
	if (send_packet_until(session->control_fd, &buffer,
	    sizeof(*message) + sizeof(*query), &deadline) == -1 ||
	    deadline_remaining(&deadline, &remaining) == -1 ||
	    wait_fd(session->control_fd, POLLIN, remaining) == -1)
		return (-1);
	amount = receive_packet(session->control_fd, &buffer, sizeof(buffer),
	    NULL, 0, NULL);
	message = &buffer.wire.message;
	if (amount <= 0 || !message_valid(message, (size_t)amount, true) ||
	    message->operation != STORAGE_OP_QUERY) {
		errno = amount == 0 ? ECONNRESET : EPROTO;
		return (-1);
	}
	if (message->status != 0) {
		if (message->length != 0)
			return (errno = EPROTO, -1);
		return (errno = -message->status, -1);
	}
	if (message->length < offsetof(struct storage_query_reply, record))
		return (errno = EPROTO, -1);
	reply = (void *)(message + 1);
	if (reply->result > LOGCMP_STORE_QUERY_CONTINUE ||
	    reply->record_length > LOGCMP_MAX_RECORD ||
	    message->length != offsetof(struct storage_query_reply, record) +
	    reply->record_length || (reply->result != LOGCMP_STORE_QUERY_RECORD &&
	    reply->record_length != 0) || (reply->result == 1 &&
	    (reply->record_length < sizeof(struct logcmp_record) ||
	    logcmp_validate_record((const void *)reply->record,
	    reply->record_length) == -1)))
		return (errno = EPROTO, -1);
	working_cursor = reply->cursor;
	if (reply->result == LOGCMP_STORE_QUERY_CONTINUE)
		goto again;
	if (reply->record_length > capacity)
		return (errno = EMSGSIZE, -1);
	*cursor = working_cursor;
	if (reply->record_length != 0)
		memcpy(record, reply->record, reply->record_length);
	*record_length = reply->record_length;
	return ((int)reply->result);
}

int
logcmp_storage_query_next_for(struct logcmp_storage_session *session,
    const char *label, uint32_t minimum_severity,
    struct logcmp_store_cursor *cursor, void *record, size_t capacity,
    size_t *record_length, uint32_t timeout_ms)
{

	return (logcmp_storage_query_next_filtered_for(session, label,
	    minimum_severity, NULL, cursor, record, capacity, record_length,
	    timeout_ms));
}

int
logcmp_storage_query_next(struct logcmp_storage_session *session,
    uint32_t minimum_severity, struct logcmp_store_cursor *cursor,
    void *record, size_t capacity, size_t *record_length, uint32_t timeout_ms)
{

	return (logcmp_storage_query_next_for(session,
	    session != NULL ? session->label : NULL, minimum_severity, cursor,
	    record, capacity, record_length, timeout_ms));
}
