/* Event-loop composition tests for a mediated virtio-fs connection. */
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "virtio_fs_connection_wait.c"
#include "virtio_fs_host.c"
#include "virtio_fs_backend.c"
#include "virtio_fs_backend_io.c"
#include "virtio_fs_backend_client.c"
#include "virtio_fs_pending.c"
#include "virtio_fs_dispatch.c"
#include "virtio_fs_chain.c"
#include "virtio_fs_outbox.c"
#include "virtio_fs_queue.c"
#include "virtio_fs_connection.c"

#define	DOC_VERSION		1U
#define	DOC_HELLO_SIZE		20U
#define	DOC_FEATURES		7U
#define	DOC_NOTIFICATION	(UINT32_C(1) << 3)
#define	DOC_MAX_MESSAGE		4096U
#define	DOC_MAX_INFLIGHT	8U
#define	DOC_MAX_PENDING		16384U
#define	DOC_FUSE_INIT		26U
#define	DOC_FUSE_INIT_IN	56U
#define	DOC_FUSE_INIT_OUT	24U
#define	DOC_FUSE_OUT_HEADER	16U
#define	DOC_CONTROL_ID_BIT	(UINT64_C(1) << 63)

struct completion {
	uintptr_t cookie;
	size_t used;
	unsigned int calls;
	struct virtio_fs_connection *connection;
	uint32_t pending_at_completion;
	uint32_t outgoing_at_completion;
	int progress_at_completion;
	bool progress_during_completion;
	bool inspected_connection;
};

struct notification {
	uint8_t bytes[32];
	size_t length;
	unsigned int calls;
	bool would_block;
};

static int
receive_notification(void *arg, const void *payload, size_t length)
{
	struct notification *notification;

	notification = arg;
	notification->calls++;
	if (notification->would_block)
		return (EAGAIN);
	if (length > sizeof(notification->bytes))
		return (EMSGSIZE);
	memcpy(notification->bytes, payload, length);
	notification->length = length;
	return (0);
}

static void
complete(void *arg, uintptr_t cookie, size_t used)
{
	struct completion *completion;

	completion = arg;
	completion->cookie = cookie;
	completion->used = used;
	completion->calls++;
	if (completion->connection != NULL) {
		completion->pending_at_completion =
		    virtio_fs_connection_pending(completion->connection);
		completion->outgoing_at_completion =
		    virtio_fs_connection_outgoing(completion->connection);
		if (completion->progress_during_completion)
			completion->progress_at_completion =
			    virtio_fs_connection_progress(completion->connection, false,
			    false);
		completion->inspected_connection = true;
	}
}

static struct virtio_fs_backend_hello
offer(void)
{

	return ((struct virtio_fs_backend_hello) {
		.minimum_version = DOC_VERSION,
		.maximum_version = DOC_VERSION,
		.features = DOC_FEATURES,
		.maximum_message = DOC_MAX_MESSAGE,
		.maximum_inflight = DOC_MAX_INFLIGHT,
		.maximum_pending_bytes = DOC_MAX_PENDING,
	});
}

static void
activate_features(int peer, struct virtio_fs_connection *connection,
    uint32_t features, int expected_error)
{
	struct virtio_fs_backend_header request, reply;
	struct virtio_fs_backend_hello selection;
	uint8_t payload[DOC_HELLO_SIZE], wire[DOC_HELLO_SIZE];
	size_t payload_len;

	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true),
	    EAGAIN);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(peer, &request,
	    payload, sizeof(payload), &payload_len), 0);
	ATF_REQUIRE_EQ(payload_len, DOC_HELLO_SIZE);
	ATF_REQUIRE_EQ(virtio_fs_backend_hello_decode(payload, payload_len,
	    &selection), 0);
	selection.features &= features;
	ATF_REQUIRE_EQ(virtio_fs_backend_hello_encode(&selection, wire), 0);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_HELLO_REPLY,
		.payload_len = DOC_HELLO_SIZE,
		.request_id = request.request_id,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(peer, &reply, wire), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false),
	    expected_error);
	ATF_CHECK_EQ(virtio_fs_connection_active(connection),
	    expected_error == 0);
}

static void
activate(int peer, struct virtio_fs_connection *connection)
{

	activate_features(peer, connection, DOC_FEATURES, 0);
}

ATF_TC_WITHOUT_HEAD(round_trip_and_readiness);
ATF_TC_BODY(round_trip_and_readiness, tc)
{
	struct virtio_fs_backend_header request_header, reply;
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	struct iovec iov[2];
	uint8_t request[DOC_FUSE_INIT_IN], backend_request[DOC_FUSE_INIT_IN];
	uint8_t response[DOC_FUSE_INIT_OUT], output[DOC_FUSE_INIT_OUT];
	size_t payload_len;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt(sockets[0], geteuid(),
	    getegid(), &hello, 4, 2, complete, &completion, &connection), 0);
	ATF_CHECK_EQ(virtio_fs_connection_fd(connection), sockets[0]);
	ATF_CHECK_EQ(virtio_fs_connection_events(connection),
	    VIRTIO_FS_CONNECTION_WRITE);
	activate(sockets[1], connection);
	ATF_CHECK_EQ(virtio_fs_connection_events(connection),
	    VIRTIO_FS_CONNECTION_READ);

	memset(request, 0, sizeof(request));
	le32enc(request, sizeof(request));
	le32enc(request + 4, DOC_FUSE_INIT);
	le64enc(request + 8, 77);
	le32enc(request + 40, 7);
	le32enc(request + 44, 31);
	memset(output, 0xa5, sizeof(output));
	iov[0] = (struct iovec){ request, sizeof(request) };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_connection_submit(connection,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x1234), 0);
	ATF_CHECK_EQ(virtio_fs_connection_pending(connection), 1);
	ATF_CHECK_EQ(virtio_fs_connection_events(connection),
	    VIRTIO_FS_CONNECTION_READ | VIRTIO_FS_CONNECTION_WRITE);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1],
	    &request_header, backend_request, sizeof(backend_request),
	    &payload_len), 0);
	ATF_CHECK_EQ(payload_len, sizeof(request));
	ATF_CHECK(memcmp(backend_request, request, sizeof(request)) == 0);

	memset(response, 0, sizeof(response));
	le32enc(response, sizeof(response));
	le64enc(response + 8, 77);
	le32enc(response + 16, 7);
	le32enc(response + 20, 31);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_RESPONSE,
		.payload_len = sizeof(response),
		.request_id = request_header.request_id,
		.incarnation = request_header.incarnation,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &reply,
	    response), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false),
	    0);
	ATF_CHECK_EQ(completion.calls, 1);
	ATF_CHECK_EQ(completion.cookie, (uintptr_t)0x1234);
	ATF_CHECK_EQ(completion.used, sizeof(response));
	ATF_CHECK(memcmp(output, response, sizeof(output)) == 0);
	ATF_CHECK_EQ(virtio_fs_connection_pending(connection), 0);
	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

/* An event-loop callback must return well inside this bound. */
#define	PROMPT_MS	50

struct partial {
	struct virtio_fs_connection *connection;
	struct completion completion;
	uint8_t request[DOC_FUSE_INIT_IN];
	uint8_t output[DOC_FUSE_INIT_OUT];
	int sockets[2];
};

static long
elapsed_ms(const struct timespec *start)
{
	struct timespec now;

	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &now), 0);
	return ((now.tv_sec - start->tv_sec) * 1000 +
	    (now.tv_nsec - start->tv_nsec) / 1000000);
}

/* Activate a connection and submit one FUSE_INIT request. */
static void
partial_setup(struct partial *partial)
{
	struct virtio_fs_backend_hello hello;
	struct iovec iov[2];

	memset(partial, 0, sizeof(*partial));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, partial->sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt(partial->sockets[0],
	    geteuid(), getegid(), &hello, 4, 2, complete, &partial->completion,
	    &partial->connection), 0);
	activate(partial->sockets[1], partial->connection);
	le32enc(partial->request, sizeof(partial->request));
	le32enc(partial->request + 4, DOC_FUSE_INIT);
	le64enc(partial->request + 8, 77);
	le32enc(partial->request + 40, 7);
	le32enc(partial->request + 44, 31);
	iov[0] = (struct iovec){ partial->request, sizeof(partial->request) };
	iov[1] = (struct iovec){ partial->output, sizeof(partial->output) };
	ATF_REQUIRE_EQ(virtio_fs_connection_submit(partial->connection,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x77), 0);
}

/* Flush the request to the backend and encode the backend's reply frame. */
static void
partial_reply(struct partial *partial, uint8_t *frame, size_t length)
{
	struct virtio_fs_backend_header reply, request;
	uint8_t received[DOC_FUSE_INIT_IN];
	size_t received_len;

	ATF_REQUIRE_EQ(length, 40 + DOC_FUSE_INIT_OUT);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(partial->connection,
	    false, true), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(partial->sockets[1],
	    &request, received, sizeof(received), &received_len), 0);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_RESPONSE,
		.payload_len = DOC_FUSE_INIT_OUT,
		.request_id = request.request_id,
		.incarnation = request.incarnation,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_header_encode(&reply, frame), 0);
	memset(frame + 40, 0, DOC_FUSE_INIT_OUT);
	le32enc(frame + 40, DOC_FUSE_INIT_OUT);
	le64enc(frame + 48, 77);
	le32enc(frame + 56, 7);
	le32enc(frame + 60, 31);
}

/*
 * A backend that sends part of a record and stalls must not hold the event
 * loop: the callback returns EAGAIN at once with readiness still armed, and
 * the frame completes when the rest arrives.
 */
ATF_TC_WITHOUT_HEAD(partial_response_does_not_block_event_loop);
ATF_TC_BODY(partial_response_does_not_block_event_loop, tc)
{
	struct partial partial;
	struct timespec deadline, start;
	uint8_t frame[40 + DOC_FUSE_INIT_OUT];

	partial_setup(&partial);
	partial_reply(&partial, frame, sizeof(frame));

	ATF_REQUIRE_EQ(send(partial.sockets[1], frame, 30, 0), 30);
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &start), 0);
	ATF_CHECK_EQ(virtio_fs_connection_progress(partial.connection, true,
	    false), EAGAIN);
	ATF_CHECK(elapsed_ms(&start) < PROMPT_MS);
	ATF_CHECK((virtio_fs_connection_events(partial.connection) &
	    VIRTIO_FS_CONNECTION_READ) != 0);
	ATF_CHECK(virtio_fs_connection_deadline(partial.connection,
	    &deadline));
	ATF_CHECK_EQ(partial.completion.calls, 0);

	ATF_REQUIRE_EQ(send(partial.sockets[1], frame + 30, 20, 0), 20);
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &start), 0);
	ATF_CHECK_EQ(virtio_fs_connection_progress(partial.connection, true,
	    false), EAGAIN);
	ATF_CHECK(elapsed_ms(&start) < PROMPT_MS);
	ATF_CHECK_EQ(partial.completion.calls, 0);

	ATF_REQUIRE_EQ(send(partial.sockets[1], frame + 50, sizeof(frame) - 50,
	    MSG_EOR), (ssize_t)(sizeof(frame) - 50));
	ATF_CHECK_EQ(virtio_fs_connection_progress(partial.connection, true,
	    false), 0);
	ATF_CHECK_EQ(partial.completion.calls, 1);
	ATF_CHECK_EQ(partial.completion.cookie, (uintptr_t)0x77);
	ATF_CHECK_EQ(partial.completion.used, DOC_FUSE_INIT_OUT);
	ATF_CHECK(memcmp(partial.output, frame + 40, DOC_FUSE_INIT_OUT) == 0);
	ATF_CHECK(!virtio_fs_connection_deadline(partial.connection,
	    &deadline));
	virtio_fs_connection_destroy(partial.connection);
	ATF_REQUIRE_EQ(close(partial.sockets[1]), 0);
}

/*
 * A backend that drains its receive buffer slowly must not hold the event
 * loop either: the unsent tail of a frame stays queued with write readiness
 * armed and goes out, unbroken, on later callbacks.
 */
ATF_TC_WITHOUT_HEAD(slow_draining_send_does_not_block_event_loop);
ATF_TC_BODY(slow_draining_send_does_not_block_event_loop, tc)
{
	struct virtio_fs_backend_header header;
	struct partial partial;
	struct timespec deadline, start;
	struct iovec vector;
	struct msghdr message;
	uint8_t frame[2 * (40 + DOC_FUSE_INIT_IN)];
	size_t received;
	ssize_t piece;
	int error, size;
	bool eor;

	partial_setup(&partial);
	size = 64;
	ATF_REQUIRE_EQ(setsockopt(partial.sockets[1], SOL_SOCKET, SO_RCVBUF,
	    &size, sizeof(size)), 0);

	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &start), 0);
	ATF_CHECK_EQ(virtio_fs_connection_progress(partial.connection, false,
	    true), EAGAIN);
	ATF_CHECK(elapsed_ms(&start) < PROMPT_MS);
	ATF_CHECK((virtio_fs_connection_events(partial.connection) &
	    VIRTIO_FS_CONNECTION_WRITE) != 0);
	ATF_CHECK(virtio_fs_connection_deadline(partial.connection,
	    &deadline));

	received = 0;
	eor = false;
	while (!eor) {
		vector.iov_base = frame + received;
		vector.iov_len = sizeof(frame) - received;
		memset(&message, 0, sizeof(message));
		message.msg_iov = &vector;
		message.msg_iovlen = 1;
		piece = recvmsg(partial.sockets[1], &message, MSG_DONTWAIT);
		ATF_REQUIRE_MSG(piece > 0, "recvmsg: %zd", piece);
		received += (size_t)piece;
		eor = (message.msg_flags & MSG_EOR) != 0;
		ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &start), 0);
		error = virtio_fs_connection_progress(partial.connection, false,
		    true);
		ATF_CHECK(elapsed_ms(&start) < PROMPT_MS);
		ATF_REQUIRE(error == 0 || error == EAGAIN);
	}
	ATF_REQUIRE_EQ(received, 40 + DOC_FUSE_INIT_IN);
	ATF_CHECK(!virtio_fs_connection_deadline(partial.connection,
	    &deadline));
	ATF_CHECK_EQ(virtio_fs_connection_events(partial.connection),
	    VIRTIO_FS_CONNECTION_READ);
	ATF_REQUIRE_EQ(virtio_fs_backend_header_decode(frame, 40, &header), 0);
	ATF_CHECK_EQ(header.type, VIRTIO_FS_BACKEND_REQUEST);
	ATF_CHECK_EQ(header.payload_len, DOC_FUSE_INIT_IN);
	ATF_CHECK(memcmp(frame + 40, partial.request, DOC_FUSE_INIT_IN) == 0);
	virtio_fs_connection_destroy(partial.connection);
	ATF_REQUIRE_EQ(close(partial.sockets[1]), 0);
}

/*
 * A readiness callback that runs after the progress deadline (the event loop
 * was late) but finds the peer ready is not a stalled peer: the frame moves
 * and the connection stays up, in both directions.
 */
ATF_TC_WITHOUT_HEAD(late_callback_with_ready_peer_does_not_expire);
ATF_TC_BODY(late_callback_with_ready_peer_does_not_expire, tc)
{
	struct partial partial;
	struct timespec deadline;
	uint8_t frame[40 + DOC_FUSE_INIT_OUT], sink[256];
	int error, size;

	partial_setup(&partial);
	partial_reply(&partial, frame, sizeof(frame));
	ATF_REQUIRE_EQ(send(partial.sockets[1], frame, 30, 0), 30);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(partial.connection, true,
	    false), EAGAIN);
	ATF_REQUIRE_EQ(send(partial.sockets[1], frame + 30, sizeof(frame) - 30,
	    MSG_EOR), (ssize_t)(sizeof(frame) - 30));
	do {
		partial.connection->stream.receive_deadline =
		    (struct timespec){ 0, 0 };
		error = virtio_fs_connection_progress(partial.connection,
		    true, false);
	} while (error == EAGAIN);
	ATF_CHECK_EQ(error, 0);
	ATF_CHECK_EQ(partial.completion.calls, 1);
	ATF_CHECK(virtio_fs_connection_active(partial.connection));
	virtio_fs_connection_destroy(partial.connection);
	ATF_REQUIRE_EQ(close(partial.sockets[1]), 0);

	partial_setup(&partial);
	size = 64;
	ATF_REQUIRE_EQ(setsockopt(partial.sockets[1], SOL_SOCKET, SO_RCVBUF,
	    &size, sizeof(size)), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(partial.connection, false,
	    true), EAGAIN);
	while (virtio_fs_connection_deadline(partial.connection, &deadline)) {
		ATF_REQUIRE(recv(partial.sockets[1], sink, sizeof(sink),
		    MSG_DONTWAIT) > 0);
		partial.connection->stream.send_deadline =
		    (struct timespec){ 0, 0 };
		error = virtio_fs_connection_progress(partial.connection,
		    false, true);
		ATF_REQUIRE_MSG(error == 0 || error == EAGAIN, "error %d",
		    error);
	}
	ATF_CHECK_EQ(virtio_fs_connection_error(partial.connection), 0);
	ATF_CHECK(virtio_fs_connection_active(partial.connection));
	virtio_fs_connection_destroy(partial.connection);
	ATF_REQUIRE_EQ(close(partial.sockets[1]), 0);
}

/*
 * The progress deadline replaces the old blocking wait: the deadline timer
 * calls progress() for both directions, and once the deadline has passed
 * with the peer still stalled the connection fails, its descriptor closes,
 * and retained requests complete.
 */
ATF_TC_WITHOUT_HEAD(stalled_partial_frame_expires);
ATF_TC_BODY(stalled_partial_frame_expires, tc)
{
	struct partial partial;
	struct timespec deadline;
	uint8_t byte, frame[40 + DOC_FUSE_INIT_OUT];

	partial_setup(&partial);
	partial_reply(&partial, frame, sizeof(frame));
	ATF_REQUIRE_EQ(send(partial.sockets[1], frame, 30, 0), 30);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(partial.connection, true,
	    false), EAGAIN);
	ATF_REQUIRE(virtio_fs_connection_deadline(partial.connection,
	    &deadline));
	ATF_CHECK_EQ(virtio_fs_connection_progress(partial.connection, true,
	    true), EAGAIN);
	ATF_CHECK(virtio_fs_connection_active(partial.connection));

	partial.connection->stream.receive_deadline =
	    (struct timespec){ 0, 0 };
	ATF_CHECK_EQ(virtio_fs_connection_progress(partial.connection, true,
	    true), ETIMEDOUT);
	ATF_CHECK_EQ(virtio_fs_connection_error(partial.connection), ETIMEDOUT);
	ATF_CHECK_EQ(virtio_fs_connection_fd(partial.connection), -1);
	ATF_CHECK_EQ(partial.completion.calls, 1);
	ATF_CHECK_EQ(partial.completion.cookie, (uintptr_t)0x77);
	ATF_CHECK_EQ(virtio_fs_connection_progress(partial.connection, true,
	    false), ETIMEDOUT);
	ATF_CHECK_EQ(recv(partial.sockets[1], &byte, 1, MSG_DONTWAIT), 0);
	virtio_fs_connection_destroy(partial.connection);
	ATF_REQUIRE_EQ(close(partial.sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(wait_progress_honors_protocol_deadline);
ATF_TC_BODY(wait_progress_honors_protocol_deadline, tc)
{
	struct partial partial;
	struct timespec deadline;
	uint8_t frame[40 + DOC_FUSE_INIT_OUT];

	partial_setup(&partial);
	partial_reply(&partial, frame, sizeof(frame));
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &deadline), 0);
	deadline.tv_sec += 5;
	ATF_REQUIRE_EQ(send(partial.sockets[1], frame, 30, 0), 30);
	/* Partial input yields EAGAIN internally without completing the request. */
	ATF_REQUIRE_EQ(virtio_fs_connection_wait_progress(partial.connection,
	    &deadline), 0);
	ATF_CHECK(virtio_fs_connection_active(partial.connection));
	ATF_CHECK_EQ(partial.completion.calls, 0);
	/* Protocol expiry must win over the later operation deadline. */
	partial.connection->stream.receive_deadline = (struct timespec){ 0 };
	ATF_CHECK_EQ(virtio_fs_connection_wait_progress(partial.connection,
	    &deadline), ETIMEDOUT);
	ATF_CHECK_EQ(virtio_fs_connection_error(partial.connection), ETIMEDOUT);
	ATF_CHECK_EQ(partial.completion.calls, 1);
	ATF_CHECK_EQ(virtio_fs_connection_wait_progress(partial.connection,
	    &deadline), ETIMEDOUT);
	ATF_CHECK_EQ(partial.completion.calls, 1);
	virtio_fs_connection_destroy(partial.connection);
	ATF_REQUIRE_EQ(close(partial.sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(protocol_failure_completes_pending);
ATF_TC_BODY(protocol_failure_completes_pending, tc)
{
	struct virtio_fs_backend_header malformed;
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	struct iovec iov[2];
	uint8_t request[DOC_FUSE_INIT_IN], output[DOC_FUSE_INIT_OUT];
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt(sockets[0], geteuid(),
	    getegid(), &hello, 4, 2, complete, &completion, &connection), 0);
	activate(sockets[1], connection);
	memset(request, 0, sizeof(request));
	le32enc(request, sizeof(request));
	le32enc(request + 4, DOC_FUSE_INIT);
	le64enc(request + 8, 88);
	le32enc(request + 40, 7);
	iov[0] = (struct iovec){ request, sizeof(request) };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_connection_submit(connection,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 9), 0);
	malformed = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_RESPONSE,
		.request_id = UINT64_C(999),
		.incarnation = 1,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &malformed,
	    NULL), 0);
	ATF_CHECK_EQ(virtio_fs_connection_progress(connection, true, false),
	    ENOENT);
	ATF_CHECK_EQ(virtio_fs_connection_error(connection), ENOENT);
	ATF_CHECK_EQ(virtio_fs_connection_fd(connection), -1);
	ATF_CHECK_EQ(completion.calls, 1);
	ATF_CHECK_EQ(completion.cookie, (uintptr_t)9);
	ATF_CHECK_EQ(completion.used, DOC_FUSE_OUT_HEADER);
	ATF_CHECK_EQ((int32_t)le32dec(output + 4), -5);
	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(connect_path_is_authenticated_and_event_driven);
ATF_TC_BODY(connect_path_is_authenticated_and_event_driven, tc)
{
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	struct sockaddr_un address;
	char path[] = "/tmp/vfsb-connection.XXXXXX";
	int listener, peer, placeholder;

	memset(&completion, 0, sizeof(completion));
	placeholder = mkstemp(path);
	ATF_REQUIRE(placeholder >= 0);
	ATF_REQUIRE_EQ(close(placeholder), 0);
	ATF_REQUIRE_EQ(unlink(path), 0);
	listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	ATF_REQUIRE(listener >= 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	address.sun_len = (uint8_t)(offsetof(struct sockaddr_un, sun_path) +
	    strlen(path) + 1);
	memcpy(address.sun_path, path, strlen(path) + 1);
	ATF_REQUIRE_EQ(bind(listener, (struct sockaddr *)&address,
	    address.sun_len), 0);
	ATF_REQUIRE_EQ(listen(listener, 1), 0);
	hello = offer();
	ATF_REQUIRE_EQ(virtio_fs_connection_connect(path, geteuid(),
	    getegid(), &hello, 4, 2, complete, &completion, &connection), 0);
	peer = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	ATF_REQUIRE(peer >= 0);
	activate(peer, connection);
	ATF_CHECK(virtio_fs_connection_active(connection));
	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(peer), 0);
	ATF_REQUIRE_EQ(close(listener), 0);
	ATF_REQUIRE_EQ(unlink(path), 0);
}

ATF_TC_WITHOUT_HEAD(adopt_failure_preserves_caller_ownership);
ATF_TC_BODY(adopt_failure_preserves_caller_ownership, tc)
{
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	ATF_CHECK_EQ(virtio_fs_connection_adopt(sockets[0], geteuid(),
	    getegid(), &hello, 0, 1, complete, &completion, &connection),
	    EINVAL);
	ATF_CHECK_EQ(virtio_fs_connection_adopt(sockets[0], geteuid(),
	    getegid() + 1, &hello, 1, 1, complete, &completion, &connection),
	    EACCES);
	ATF_CHECK(fcntl(sockets[0], F_GETFD) >= 0);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(preactive_empty_reset_is_synchronous);
ATF_TC_BODY(preactive_empty_reset_is_synchronous, tc)
{
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	size_t discarded;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt(sockets[0], geteuid(),
	    getegid(), &hello, 4, 2, complete, &completion, &connection), 0);
	ATF_CHECK_EQ(virtio_fs_connection_reset_queue(connection, 3,
	    &discarded), 0);
	ATF_CHECK_EQ(discarded, 0);
	ATF_CHECK_EQ(virtio_fs_connection_reset(connection, &discarded), 0);
	ATF_CHECK_EQ(discarded, 0);
	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(required_backend_features_are_enforced);
ATF_TC_BODY(required_backend_features_are_enforced, tc)
{
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt_required(sockets[0],
	    geteuid(), getegid(), &hello, 4, 2,
	    VIRTIO_FS_BACKEND_F_CANCEL, complete, &completion,
	    &connection), 0);
	activate_features(sockets[1], connection,
	    VIRTIO_FS_BACKEND_F_FREEZE, ENOTSUP);
	ATF_CHECK_EQ(virtio_fs_connection_error(connection), ENOTSUP);
	ATF_CHECK_EQ(virtio_fs_connection_fd(connection), -1);
	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);

	hello.features = VIRTIO_FS_BACKEND_F_FREEZE;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	ATF_CHECK_EQ(virtio_fs_connection_adopt_required(sockets[0],
	    geteuid(), getegid(), &hello, 4, 2,
	    VIRTIO_FS_BACKEND_F_CANCEL, complete, &completion,
	    &connection), EINVAL);
	ATF_CHECK(fcntl(sockets[0], F_GETFD) >= 0);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(checkpoint_admission_and_session_are_transactional);
ATF_TC_BODY(checkpoint_admission_and_session_are_transactional, tc)
{
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_connection *connection;
	struct virtio_fs_session fuse, restored;
	struct completion completion;
	struct iovec iov[2];
	uint8_t output[DOC_FUSE_INIT_OUT], request[DOC_FUSE_INIT_IN];
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt(sockets[0], geteuid(),
	    getegid(), &hello, 4, 2, complete, &completion, &connection), 0);
	activate(sockets[1], connection);

	memset(&backend, 0xa5, sizeof(backend));
	ATF_REQUIRE_EQ(virtio_fs_connection_checkpoint_contract(connection,
	    &backend), 0);
	ATF_CHECK_EQ(backend.phase, VIRTIO_FS_BACKEND_QUIESCED);
	ATF_CHECK_EQ(backend.pending_control_id, 0);
	ATF_CHECK_EQ(backend.version, DOC_VERSION);
	ATF_CHECK_EQ(backend.features, DOC_FEATURES);
	ATF_CHECK_EQ(backend.maximum_message, DOC_MAX_MESSAGE);

	memset(&fuse, 0xa5, sizeof(fuse));
	memset(&backend, 0xa5, sizeof(backend));
	ATF_REQUIRE_EQ(virtio_fs_connection_pause(connection, &fuse,
	    &backend), 0);
	ATF_CHECK(!fuse.initialized);
	ATF_CHECK_EQ(fuse.byte_order, VIRTIO_FS_BYTE_ORDER_UNKNOWN);
	ATF_CHECK_EQ(backend.phase, VIRTIO_FS_BACKEND_ACTIVE);
	ATF_CHECK_EQ(backend.version, DOC_VERSION);
	ATF_CHECK_EQ(backend.features, DOC_FEATURES);
	ATF_CHECK_EQ(backend.maximum_message, DOC_MAX_MESSAGE);

	memset(request, 0, sizeof(request));
	le32enc(request, sizeof(request));
	le32enc(request + 4, DOC_FUSE_INIT);
	le64enc(request + 8, 71);
	le32enc(request + 40, 7);
	le32enc(request + 44, 31);
	memset(output, 0, sizeof(output));
	iov[0] = (struct iovec){ request, sizeof(request) };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_CHECK_EQ(virtio_fs_connection_submit(connection,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x71), EBUSY);

	restored = (struct virtio_fs_session) {
		.byte_order = VIRTIO_FS_BYTE_ORDER_LITTLE,
		.initialized = true,
		.incarnation = 9,
	};
	ATF_REQUIRE_EQ(virtio_fs_connection_restore_session(connection,
	    &restored), 0);
	virtio_fs_connection_resume(connection);

	/*
	 * Use two ordinary LOOKUP requests so the second submit tests only
	 * admission rollback, not replacement-INIT serialization.
	 */
	le32enc(request + 4, 1);
	request[40] = 'x';
	request[41] = '\0';
	ATF_REQUIRE_EQ(virtio_fs_connection_submit(connection,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x71), 0);
	memset(&fuse, 0xa5, sizeof(fuse));
	ATF_CHECK_EQ(virtio_fs_connection_pause(connection, &fuse, &backend),
	    EBUSY);
	/*
	 * A failed pause must reopen admission because the checkpoint
	 * coordinator will not invoke the matching resume callback.
	 */
	le64enc(request + 8, 72);
	ATF_REQUIRE_EQ(virtio_fs_connection_submit(connection,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x72), 0);

	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(quiesce_drains_with_admission_closed);
ATF_TC_BODY(quiesce_drains_with_admission_closed, tc)
{
	struct virtio_fs_backend_header inbound, reply;
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	struct timespec deadline;
	struct iovec iov[2];
	uint8_t backend_request[DOC_FUSE_INIT_IN];
	uint8_t output[DOC_FUSE_INIT_OUT], request[DOC_FUSE_INIT_IN];
	uint8_t response[DOC_FUSE_INIT_OUT];
	size_t payload_len;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &deadline), 0);
	deadline.tv_sec += 5;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt_required(sockets[0],
	    geteuid(), getegid(), &hello, 4, 2,
	    VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER, complete, &completion,
	    &connection), 0);
	activate(sockets[1], connection);

	memset(request, 0, sizeof(request));
	le32enc(request, sizeof(request));
	le32enc(request + 4, DOC_FUSE_INIT);
	le64enc(request + 8, 81);
	le32enc(request + 40, 7);
	le32enc(request + 44, 31);
	iov[0] = (struct iovec){ request, sizeof(request) };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_connection_submit(connection,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x81), 0);

	/*
	 * The first quiesce attempt owns admission while the accepted request
	 * drains.  A new request cannot enter, and no fixed-delay retry is
	 * involved.
	 */
	ATF_CHECK_EQ(virtio_fs_connection_begin_quiesce(connection),
	    EINPROGRESS);
	le64enc(request + 8, 82);
	ATF_CHECK_EQ(virtio_fs_connection_submit(connection,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x82), EBUSY);

	ATF_REQUIRE_EQ(virtio_fs_connection_wait_progress(connection, &deadline),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &inbound,
	    backend_request, sizeof(backend_request), &payload_len), 0);
	memset(response, 0, sizeof(response));
	le32enc(response, sizeof(response));
	le64enc(response + 8, 81);
	le32enc(response + 16, 7);
	le32enc(response + 20, 31);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_RESPONSE,
		.payload_len = sizeof(response),
		.request_id = inbound.request_id,
		.incarnation = inbound.incarnation,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &reply,
	    response), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_wait_progress(connection, &deadline),
	    0);
	ATF_CHECK_EQ(virtio_fs_connection_pending(connection), 0);
	ATF_CHECK_EQ(completion.calls, 1);

	ATF_REQUIRE_EQ(virtio_fs_connection_begin_quiesce(connection), 0);
	ATF_CHECK_EQ(virtio_fs_connection_control_status(connection),
	    EINPROGRESS);
	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(backend_state_freeze_and_thaw_are_event_driven);
ATF_TC_BODY(backend_state_freeze_and_thaw_are_event_driven, tc)
{
	static const uint8_t backend_state[] = {
		0x56, 0x46, 0x53, 0x42, 0x01, 0x23, 0x45, 0x67,
	};
	struct virtio_fs_backend_header request, reply;
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_connection *connection;
	struct virtio_fs_session fuse;
	struct completion completion;
	uint8_t payload[DOC_MAX_MESSAGE], copied[sizeof(backend_state)];
	size_t payload_len, state_len;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt_required(sockets[0],
	    geteuid(), getegid(), &hello, 4, 2,
	    VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER, complete, &completion,
	    &connection), 0);
	activate(sockets[1], connection);

	ATF_REQUIRE_EQ(virtio_fs_connection_begin_quiesce(connection), 0);
	ATF_CHECK_EQ(virtio_fs_connection_control_status(connection),
	    EINPROGRESS);
	ATF_CHECK_EQ(virtio_fs_connection_events(connection),
	    VIRTIO_FS_CONNECTION_READ | VIRTIO_FS_CONNECTION_WRITE);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &request,
	    payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(request.type, VIRTIO_FS_BACKEND_QUIESCE);
	ATF_CHECK((request.request_id & DOC_CONTROL_ID_BIT) != 0);
	ATF_CHECK_EQ(payload_len, 0);

	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_QUIESCE_REPLY,
		.payload_len = sizeof(backend_state),
		.request_id = request.request_id,
		.incarnation = request.incarnation,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &reply,
	    backend_state), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false),
	    0);
	ATF_CHECK_EQ(virtio_fs_connection_control_status(connection), 0);
	ATF_CHECK_EQ(virtio_fs_connection_checkpoint_size(connection),
	    sizeof(backend_state));

	state_len = 0;
	ATF_CHECK_EQ(virtio_fs_connection_checkpoint_copy(connection,
	    (struct virtio_fs_session *)(void *)connection,
	    &backend, copied, sizeof(copied), &state_len), EINVAL);
	ATF_CHECK_EQ(virtio_fs_connection_checkpoint_copy(connection, &fuse,
	    (struct virtio_fs_backend_session *)(void *)
	    connection->receive_buffer, copied, sizeof(copied), &state_len),
	    EINVAL);
	ATF_CHECK_EQ(virtio_fs_connection_checkpoint_copy(connection, &fuse,
	    &backend, connection->checkpoint_backend_state,
	    connection->checkpoint_backend_state_len, &state_len), EINVAL);
	ATF_CHECK_EQ(virtio_fs_connection_checkpoint_copy(connection, &fuse,
	    &backend, copied, sizeof(copied),
	    &connection->checkpoint_backend_state_len), EINVAL);
	ATF_CHECK_EQ(virtio_fs_connection_checkpoint_copy(connection, &fuse,
	    (struct virtio_fs_backend_session *)(void *)&fuse, copied,
	    sizeof(copied), &state_len), EINVAL);
	ATF_CHECK_EQ(state_len, 0);
	ATF_CHECK_EQ(virtio_fs_connection_checkpoint_copy(connection, &fuse,
	    &backend, copied, sizeof(copied) - 1, &state_len), EMSGSIZE);
	ATF_CHECK_EQ(state_len, sizeof(backend_state));
	ATF_REQUIRE_EQ(virtio_fs_connection_checkpoint_copy(connection, &fuse,
	    &backend, copied, sizeof(copied), &state_len), 0);
	ATF_CHECK(!fuse.initialized);
	ATF_CHECK_EQ(backend.phase, VIRTIO_FS_BACKEND_QUIESCED);
	ATF_CHECK_EQ(state_len, sizeof(backend_state));
	ATF_CHECK(memcmp(copied, backend_state, sizeof(copied)) == 0);

	ATF_REQUIRE_EQ(virtio_fs_connection_begin_thaw(connection, copied,
	    sizeof(copied)), 0);
	ATF_CHECK_EQ(virtio_fs_connection_control_status(connection),
	    EINPROGRESS);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &request,
	    payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(request.type, VIRTIO_FS_BACKEND_THAW);
	ATF_CHECK_EQ(payload_len, sizeof(backend_state));
	ATF_CHECK(memcmp(payload, backend_state, sizeof(backend_state)) == 0);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_THAW_REPLY,
		.request_id = request.request_id,
		.incarnation = request.incarnation,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &reply,
	    NULL), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false),
	    0);
	ATF_CHECK_EQ(virtio_fs_connection_control_status(connection), 0);
	ATF_CHECK_EQ(virtio_fs_connection_checkpoint_size(connection), 0);

	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

/* A real wire peer responds slowly; no mevent dispatcher drives the client. */
static void *
startup_wire_peer(void *arg)
{
	struct virtio_fs_backend_header request, reply;
	struct virtio_fs_backend_hello selection;
	static const uint8_t state[] = { 0x56, 0x46, 0x53, 0x42 };
	uint8_t payload[DOC_MAX_MESSAGE], wire[DOC_HELLO_SIZE];
	size_t length;
	int fd = *(int *)arg;
	struct pollfd ready = { .fd = fd, .events = POLLIN };

	ATF_REQUIRE_EQ(poll(&ready, 1, 5000), 1);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fd, &request,
	    payload, sizeof(payload), &length), 0);
	ATF_REQUIRE_EQ(request.type, VIRTIO_FS_BACKEND_HELLO);
	ATF_REQUIRE_EQ(virtio_fs_backend_hello_decode(payload, length,
	    &selection), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_hello_encode(&selection, wire), 0);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_HELLO_REPLY,
		.payload_len = sizeof(wire),
		.request_id = request.request_id,
	};
	usleep(5000);
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(fd, &reply, wire), 0);
	ATF_REQUIRE_EQ(poll(&ready, 1, 5000), 1);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fd, &request,
	    payload, sizeof(payload), &length), 0);
	ATF_REQUIRE_EQ(request.type, VIRTIO_FS_BACKEND_QUIESCE);
	ATF_REQUIRE_EQ(length, 0);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_QUIESCE_REPLY,
		.payload_len = sizeof(state),
		.request_id = request.request_id,
		.incarnation = request.incarnation,
	};
	usleep(5000);
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(fd, &reply, state), 0);
	ATF_REQUIRE_EQ(poll(&ready, 1, 5000), 1);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fd, &request,
	    payload, sizeof(payload), &length), 0);
	ATF_REQUIRE_EQ(request.type, VIRTIO_FS_BACKEND_THAW);
	ATF_REQUIRE_EQ(length, sizeof(state));
	ATF_REQUIRE(memcmp(payload, state, sizeof(state)) == 0);
	reply.type = VIRTIO_FS_BACKEND_THAW_REPLY;
	reply.payload_len = 0;
	reply.request_id = request.request_id;
	reply.incarnation = request.incarnation;
	usleep(5000);
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(fd, &reply, NULL), 0);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(startup_checkpoint_without_event_dispatch);
ATF_TC_BODY(startup_checkpoint_without_event_dispatch, tc)
{
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_connection *connection;
	struct virtio_fs_session fuse;
	struct completion completion;
	struct timespec deadline;
	pthread_t peer;
	uint8_t state[4];
	size_t length;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
	    0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt_required(sockets[0],
	    geteuid(), getegid(), &hello, 4, 2, DOC_FEATURES,
	    complete, &completion, &connection), 0);
	ATF_REQUIRE_EQ(pthread_create(&peer, NULL, startup_wire_peer, &sockets[1]), 0);
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &deadline), 0);
	deadline.tv_sec += 5;
	while (!virtio_fs_connection_active(connection))
		ATF_REQUIRE_EQ(virtio_fs_connection_wait_progress(connection,
		    &deadline), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_begin_quiesce(connection), 0);
	while (virtio_fs_connection_control_status(connection) == EINPROGRESS)
		ATF_REQUIRE_EQ(virtio_fs_connection_wait_progress(connection,
		    &deadline), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_control_status(connection), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_checkpoint_copy(connection, &fuse,
	    &backend, state, sizeof(state), &length), 0);
	ATF_CHECK_EQ(length, sizeof(state));
	ATF_CHECK(!fuse.initialized);
	ATF_CHECK_EQ(backend.phase, VIRTIO_FS_BACKEND_QUIESCED);
	ATF_REQUIRE_EQ(virtio_fs_connection_begin_thaw(connection, state, length), 0);
	while (virtio_fs_connection_control_status(connection) == EINPROGRESS)
		ATF_REQUIRE_EQ(virtio_fs_connection_wait_progress(connection,
		    &deadline), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_control_status(connection), 0);
	ATF_CHECK_EQ(virtio_fs_connection_checkpoint_size(connection), 0);
	ATF_REQUIRE_EQ(pthread_join(peer, NULL), 0);
	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(backend_freeze_failure_rolls_back_admission);
ATF_TC_BODY(backend_freeze_failure_rolls_back_admission, tc)
{
	struct virtio_fs_backend_header request, reply;
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_connection *connection;
	struct virtio_fs_session fuse;
	struct completion completion;
	uint8_t payload[DOC_MAX_MESSAGE];
	size_t payload_len;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt_required(sockets[0],
	    geteuid(), getegid(), &hello, 4, 2,
	    VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER, complete, &completion,
	    &connection), 0);
	activate(sockets[1], connection);
	ATF_REQUIRE_EQ(virtio_fs_connection_begin_quiesce(connection), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &request,
	    payload, sizeof(payload), &payload_len), 0);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_QUIESCE_REPLY,
		.request_id = request.request_id,
		.incarnation = request.incarnation,
		.status = -EBUSY,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &reply,
	    NULL), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false),
	    0);
	ATF_CHECK_EQ(virtio_fs_connection_control_status(connection), EIO);

	/* A rejected freeze is transactional: guest admission is restored. */
	ATF_REQUIRE_EQ(virtio_fs_connection_pause(connection, &fuse,
	    &backend), 0);
	virtio_fs_connection_resume(connection);

	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(malformed_control_reply_fails_connection);
ATF_TC_BODY(malformed_control_reply_fails_connection, tc)
{
	struct virtio_fs_backend_header request, reply;
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	uint8_t payload[DOC_MAX_MESSAGE];
	size_t payload_len;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt_required(sockets[0],
	    geteuid(), getegid(), &hello, 4, 2,
	    VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER, complete, &completion,
	    &connection), 0);
	activate(sockets[1], connection);

	ATF_REQUIRE_EQ(virtio_fs_connection_begin_quiesce(connection), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &request,
	    payload, sizeof(payload), &payload_len), 0);
	ATF_REQUIRE_EQ(request.type, VIRTIO_FS_BACKEND_QUIESCE);

	/*
	 * A reply for the active request with the wrong control type is a
	 * protocol violation, not a retryable backend refusal.  The connection
	 * must fail closed rather than remain stuck in QUIESCING with guest
	 * admission paused.
	 */
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_THAW_REPLY,
		.request_id = request.request_id,
		.incarnation = request.incarnation,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &reply,
	    NULL), 0);
	ATF_CHECK_EQ(virtio_fs_connection_progress(connection, true, false),
	    EPROTO);
	ATF_CHECK(!virtio_fs_connection_active(connection));
	ATF_CHECK_EQ(virtio_fs_connection_error(connection), EPROTO);
	ATF_CHECK_EQ(virtio_fs_connection_control_status(connection), EPROTO);
	ATF_CHECK_EQ(virtio_fs_connection_fd(connection), -1);
	ATF_CHECK_EQ(virtio_fs_connection_pending(connection), 0);
	ATF_CHECK_EQ(virtio_fs_connection_outgoing(connection), 0);

	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(backend_thaw_failure_retains_retryable_state);
ATF_TC_BODY(backend_thaw_failure_retains_retryable_state, tc)
{
	static const uint8_t state[] = { 0x76, 0x66, 0x73, 0x31 };
	struct virtio_fs_backend_header request, reply;
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	uint8_t payload[DOC_MAX_MESSAGE];
	size_t payload_len;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt_required(sockets[0],
	    geteuid(), getegid(), &hello, 4, 2,
	    VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER, complete, &completion,
	    &connection), 0);
	activate(sockets[1], connection);

	ATF_REQUIRE_EQ(virtio_fs_connection_begin_quiesce(connection), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &request,
	    payload, sizeof(payload), &payload_len), 0);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_QUIESCE_REPLY,
		.payload_len = sizeof(state),
		.request_id = request.request_id,
		.incarnation = request.incarnation,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &reply,
	    state), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_connection_control_status(connection), 0);

	ATF_REQUIRE_EQ(virtio_fs_connection_begin_thaw_saved(connection), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &request,
	    payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(request.type, VIRTIO_FS_BACKEND_THAW);
	ATF_CHECK_EQ(payload_len, sizeof(state));
	ATF_CHECK(memcmp(payload, state, sizeof(state)) == 0);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_THAW_REPLY,
		.request_id = request.request_id,
		.incarnation = request.incarnation,
		.status = -EBUSY,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &reply,
	    NULL), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false),
	    0);
	ATF_CHECK_EQ(virtio_fs_connection_control_status(connection), EIO);

	/*
	 * A failed destination thaw must retain both the quiesced phase and
	 * the imported opaque state.  Retrying is preferable to reopening
	 * guest admission with only part of the backend reconstructed.
	 */
	ATF_REQUIRE_EQ(virtio_fs_connection_begin_thaw_saved(connection), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &request,
	    payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(request.type, VIRTIO_FS_BACKEND_THAW);
	ATF_CHECK_EQ(payload_len, sizeof(state));
	ATF_CHECK(memcmp(payload, state, sizeof(state)) == 0);

	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(destroy_withdraws_queue_before_completion);
ATF_TC_BODY(destroy_withdraws_queue_before_completion, tc)
{
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	struct iovec iov[2];
	uint8_t output[DOC_FUSE_INIT_OUT], request[DOC_FUSE_INIT_IN];
	int sockets[2];

	/*
	 * Connection destruction fails retained requests synchronously.  The
	 * completion path is also used by the PCI device's pressure probes, so it
	 * must be able to query the connection while the queue is being drained.
	 * The queue pointer must already be withdrawn at that point.
	 */
	memset(&completion, 0, sizeof(completion));
	hello = offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt(sockets[0], geteuid(),
	    getegid(), &hello, 4, 2, complete, &completion, &connection), 0);
	activate(sockets[1], connection);
	memset(request, 0, sizeof(request));
	le32enc(request, sizeof(request));
	le32enc(request + 4, DOC_FUSE_INIT);
	le64enc(request + 8, 0x86);
	le32enc(request + 40, 7);
	le32enc(request + 44, 31);
	memset(output, 0, sizeof(output));
	iov[0] = (struct iovec){ request, sizeof(request) };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_connection_submit(connection,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x86), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_pending(connection), 1);
	completion.connection = connection;
	completion.progress_during_completion = true;
	virtio_fs_connection_destroy(connection);
	ATF_CHECK_EQ(completion.calls, 1);
	ATF_CHECK(completion.inspected_connection);
	ATF_CHECK_EQ(completion.pending_at_completion, 0);
	ATF_CHECK_EQ(completion.outgoing_at_completion, 0);
	ATF_CHECK_EQ(completion.progress_at_completion, ECANCELED);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(notification_is_negotiated_and_retried);
ATF_TC_BODY(notification_is_negotiated_and_retried, tc)
{
	struct virtio_fs_backend_header frame, request, reply;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_session fuse;
	struct virtio_fs_backend_hello hello;
	struct virtio_fs_connection *connection;
	struct completion completion;
	struct notification notification;
	uint8_t payload[] = { 1, 2, 3, 4, 5 };
	uint8_t state[] = { 0x51, 0x52, 0x53 }, copied[3], received[32];
	size_t length;
	int sockets[2];

	memset(&completion, 0, sizeof(completion));
	memset(&notification, 0, sizeof(notification));
	hello = offer();
	hello.features |= DOC_NOTIFICATION;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_adopt_required(sockets[0], geteuid(),
	    getegid(), &hello, 4, 2, DOC_NOTIFICATION, complete, &completion,
	    &connection), 0);
	activate_features(sockets[1], connection,
	    DOC_FEATURES | DOC_NOTIFICATION, 0);
	notification.would_block = true;
	ATF_REQUIRE_EQ(virtio_fs_connection_set_notification(connection,
	    receive_notification, &notification), 0);
	frame = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_NOTIFICATION,
		.payload_len = sizeof(payload),
		.incarnation = 1,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &frame,
	    payload), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false), 0);
	ATF_CHECK_EQ(notification.calls, 1);
	ATF_CHECK_EQ(notification.length, 0);
	/* A retained unsolicited frame is not serializable state. */
	ATF_CHECK_EQ(virtio_fs_connection_checkpoint_contract(connection,
	    &(struct virtio_fs_backend_session){ 0 }), EBUSY);
	ATF_CHECK_EQ(virtio_fs_connection_begin_quiesce(connection), EBUSY);
	notification.would_block = false;
	ATF_REQUIRE_EQ(virtio_fs_connection_retry_notification(connection), 0);
	ATF_CHECK_EQ(notification.calls, 2);
	ATF_CHECK_EQ(notification.length, sizeof(payload));
	ATF_CHECK(memcmp(notification.bytes, payload, sizeof(payload)) == 0);
	ATF_CHECK_EQ(virtio_fs_connection_retry_notification(connection), 0);
	ATF_CHECK_EQ(notification.calls, 2);
	/* Once delivered, the retained notification must no longer prevent
	 * checkpoint admission or be replayed by thaw. */
	ATF_REQUIRE_EQ(virtio_fs_connection_begin_quiesce(connection), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &request,
	    received, sizeof(received), &length), 0);
	ATF_REQUIRE_EQ(request.type, VIRTIO_FS_BACKEND_QUIESCE);
	ATF_REQUIRE_EQ(length, 0);
	reply = (struct virtio_fs_backend_header) {
		.version = DOC_VERSION,
		.type = VIRTIO_FS_BACKEND_QUIESCE_REPLY,
		.payload_len = sizeof(state),
		.request_id = request.request_id,
		.incarnation = request.incarnation,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &reply, state), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_control_status(connection), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_checkpoint_copy(connection, &fuse,
	    &backend, copied, sizeof(copied), &length), 0);
	ATF_REQUIRE_EQ(length, sizeof(state));
	ATF_CHECK(memcmp(copied, state, sizeof(state)) == 0);
	ATF_CHECK_EQ(backend.phase, VIRTIO_FS_BACKEND_QUIESCED);
	ATF_CHECK_EQ(notification.calls, 2);
	ATF_REQUIRE_EQ(virtio_fs_connection_begin_thaw(connection, copied,
	    length), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, false, true), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &request,
	    received, sizeof(received), &length), 0);
	ATF_REQUIRE_EQ(request.type, VIRTIO_FS_BACKEND_THAW);
	ATF_REQUIRE_EQ(length, sizeof(state));
	ATF_CHECK(memcmp(received, state, sizeof(state)) == 0);
	reply.type = VIRTIO_FS_BACKEND_THAW_REPLY;
	reply.payload_len = 0;
	reply.request_id = request.request_id;
	reply.incarnation = request.incarnation;
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &reply, NULL), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_control_status(connection), 0);
	ATF_CHECK_EQ(virtio_fs_connection_retry_notification(connection), 0);
	ATF_CHECK_EQ(notification.calls, 2);
	payload[0] = 9;
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[1], &frame,
	    payload), 0);
	ATF_REQUIRE_EQ(virtio_fs_connection_progress(connection, true, false), 0);
	ATF_CHECK_EQ(notification.calls, 3);
	ATF_CHECK_EQ(notification.length, sizeof(payload));
	ATF_CHECK(memcmp(notification.bytes, payload, sizeof(payload)) == 0);
	ATF_CHECK_EQ(virtio_fs_connection_retry_notification(connection), 0);
	ATF_CHECK_EQ(notification.calls, 3);
	virtio_fs_connection_destroy(connection);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, round_trip_and_readiness);
	ATF_TP_ADD_TC(tp, partial_response_does_not_block_event_loop);
	ATF_TP_ADD_TC(tp, slow_draining_send_does_not_block_event_loop);
	ATF_TP_ADD_TC(tp, late_callback_with_ready_peer_does_not_expire);
	ATF_TP_ADD_TC(tp, stalled_partial_frame_expires);
	ATF_TP_ADD_TC(tp, wait_progress_honors_protocol_deadline);
	ATF_TP_ADD_TC(tp, protocol_failure_completes_pending);
	ATF_TP_ADD_TC(tp, connect_path_is_authenticated_and_event_driven);
	ATF_TP_ADD_TC(tp, adopt_failure_preserves_caller_ownership);
	ATF_TP_ADD_TC(tp, preactive_empty_reset_is_synchronous);
	ATF_TP_ADD_TC(tp, required_backend_features_are_enforced);
	ATF_TP_ADD_TC(tp,
	    checkpoint_admission_and_session_are_transactional);
	ATF_TP_ADD_TC(tp, quiesce_drains_with_admission_closed);
	ATF_TP_ADD_TC(tp, backend_state_freeze_and_thaw_are_event_driven);
	ATF_TP_ADD_TC(tp, startup_checkpoint_without_event_dispatch);
	ATF_TP_ADD_TC(tp, backend_freeze_failure_rolls_back_admission);
	ATF_TP_ADD_TC(tp, malformed_control_reply_fails_connection);
	ATF_TP_ADD_TC(tp, backend_thaw_failure_retains_retryable_state);
	ATF_TP_ADD_TC(tp, destroy_withdraws_queue_before_completion);
	ATF_TP_ADD_TC(tp, notification_is_negotiated_and_retried);
	return (atf_no_error());
}
