/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_backend_io.h"
#include "virtio_state_range.h"

#define	VFSB_CONTROL_FDS	16U

static int
virtio_fs_backend_path_split(const char *path, char **parentp, char **namep)
{
	char *copy, *slash;

	if (path == NULL || path[0] != '/' || parentp == NULL || namep == NULL)
		return (EINVAL);
	copy = strdup(path);
	if (copy == NULL)
		return (ENOMEM);
	slash = strrchr(copy, '/');
	if (slash == NULL || slash[1] == '\0') {
		free(copy);
		return (EINVAL);
	}
	*namep = strdup(slash + 1);
	if (*namep == NULL) {
		free(copy);
		return (ENOMEM);
	}
	if (slash == copy)
		slash[1] = '\0';
	else
		*slash = '\0';
	*parentp = copy;
	return (0);
}

int
virtio_fs_backend_connect_finish(int fd, uid_t expected_uid,
    gid_t expected_gid)
{
	socklen_t error_len;
	int error;

	error = 0;
	error_len = sizeof(error);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0)
		return (errno);
	if (error_len != sizeof(error))
		return (EPROTO);
	if (error != 0)
		return (error);
	return (virtio_fs_backend_authenticate(fd, expected_uid,
	    expected_gid));
}

int
virtio_fs_backend_connect_start(const char *path, uid_t expected_uid,
    gid_t expected_gid, int *result_fd, bool *connecting)
{
	struct sockaddr_un address;
	char *name, *parent;
	size_t name_len;
	int dfd, error, fd;

	if (result_fd == NULL || connecting == NULL)
		return (EINVAL);
	*result_fd = -1;
	*connecting = false;
	error = virtio_fs_backend_path_split(path, &parent, &name);
	if (error != 0)
		return (error);
	name_len = strlen(name);
	if (name_len == 0 || name_len >= sizeof(address.sun_path)) {
		free(name);
		free(parent);
		return (ENAMETOOLONG);
	}
	dfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	error = errno;
	free(parent);
	if (dfd < 0) {
		free(name);
		return (error);
	}
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		error = errno;
		(void)close(dfd);
		free(name);
		return (error);
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	address.sun_len = (uint8_t)(offsetof(struct sockaddr_un, sun_path) +
	    name_len + 1);
	memcpy(address.sun_path, name, name_len + 1);
	free(name);
	if (connectat(dfd, fd, (struct sockaddr *)&address,
	    address.sun_len) != 0) {
		error = errno;
		(void)close(dfd);
		if (error != EINPROGRESS) {
			(void)close(fd);
			return (error);
		}
		*connecting = true;
	} else {
		(void)close(dfd);
		error = virtio_fs_backend_connect_finish(fd, expected_uid,
		    expected_gid);
		if (error != 0) {
			(void)close(fd);
			return (error);
		}
	}
	*result_fd = fd;
	return (0);
}

static void
virtio_fs_backend_discard_rights(struct msghdr *message)
{
	const unsigned char *end, *start;
	struct cmsghdr *control;
	size_t available, bytes, count, i;
	int *fds;

	end = (const unsigned char *)message->msg_control +
	    message->msg_controllen;
	for (control = CMSG_FIRSTHDR(message); control != NULL;
	    control = CMSG_NXTHDR(message, control)) {
		start = (const unsigned char *)control;
		if (start + sizeof(*control) > end ||
		    control->cmsg_len < CMSG_LEN(0))
			break;
		available = MIN((size_t)(end - start),
		    (size_t)control->cmsg_len);
		if (control->cmsg_level == SOL_SOCKET &&
		    control->cmsg_type == SCM_RIGHTS &&
		    available >= CMSG_LEN(0)) {
			bytes = available - CMSG_LEN(0);
			count = bytes / sizeof(*fds);
			fds = (int *)(void *)CMSG_DATA(control);
			for (i = 0; i < count; i++)
				(void)close(fds[i]);
		}
		if (control->cmsg_len > (size_t)(end - start))
			break;
	}
}

int
virtio_fs_backend_authenticate(int fd, uid_t expected_uid,
    gid_t expected_gid)
{
	struct sockaddr_un peer;
	socklen_t peer_len, type_len;
	gid_t peer_gid;
	uid_t peer_uid;
	int type;

	type_len = sizeof(type);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len) != 0)
		return (errno);
	if (type_len != sizeof(type) || type != SOCK_SEQPACKET)
		return (EPROTOTYPE);
	peer_len = sizeof(peer);
	if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0)
		return (errno);
	if (peer_len < offsetof(struct sockaddr_un, sun_path) ||
	    peer.sun_family != AF_UNIX)
		return (EAFNOSUPPORT);
	if (getpeereid(fd, &peer_uid, &peer_gid) != 0)
		return (errno);
	if ((expected_uid != (uid_t)-1 && peer_uid != expected_uid) ||
	    (expected_gid != (gid_t)-1 && peer_gid != expected_gid))
		return (EACCES);
	return (0);
}

/*
 * Upper bound on the time between two pieces of a record that has started to
 * move.  The peer is actively sending or receiving that record, so the gap is
 * short in practice; on expiry the transport fails.
 */
#ifndef VIRTIO_FS_BACKEND_RECORD_TIMEOUT_MS
#define	VIRTIO_FS_BACKEND_RECORD_TIMEOUT_MS	5000
#endif

static int
virtio_fs_backend_deadline_set(struct timespec *deadline)
{

	if (clock_gettime(CLOCK_MONOTONIC, deadline) != 0)
		return (errno);
	deadline->tv_sec += VIRTIO_FS_BACKEND_RECORD_TIMEOUT_MS / 1000;
	deadline->tv_nsec += (long)(VIRTIO_FS_BACKEND_RECORD_TIMEOUT_MS %
	    1000) * 1000000L;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}
	return (0);
}

static bool
virtio_fs_backend_deadline_passed(const struct timespec *deadline)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return (true);
	return (timespeccmp(&now, deadline, >=));
}

/*
 * Point "vectors" at bytes [done, total) of the frame laid out by "source".
 */
static int
virtio_fs_backend_tail(struct iovec *vectors, const struct iovec *source,
    int source_count, size_t done, size_t total)
{
	size_t limit, skip;
	int count, i;

	skip = done;
	limit = total - done;
	count = 0;
	for (i = 0; i < source_count && limit > 0; i++) {
		if (skip >= source[i].iov_len) {
			skip -= source[i].iov_len;
			continue;
		}
		vectors[count].iov_base = (char *)source[i].iov_base + skip;
		vectors[count].iov_len = MIN(source[i].iov_len - skip, limit);
		limit -= vectors[count].iov_len;
		skip = 0;
		count++;
	}
	return (count);
}

void
virtio_fs_backend_stream_init(struct virtio_fs_backend_stream *stream)
{

	memset(stream, 0, sizeof(*stream));
}

void
virtio_fs_backend_stream_fini(struct virtio_fs_backend_stream *stream)
{

	free(stream->send_tail);
	virtio_fs_backend_stream_init(stream);
}

bool
virtio_fs_backend_stream_sending(const struct virtio_fs_backend_stream *stream)
{

	return (stream->send_tail != NULL);
}

bool
virtio_fs_backend_stream_receiving(
    const struct virtio_fs_backend_stream *stream)
{

	return (stream->receive_done != 0);
}

/*
 * Report the earliest progress deadline of a partly transferred frame.
 */
bool
virtio_fs_backend_stream_deadline(const struct virtio_fs_backend_stream *stream,
    struct timespec *deadline)
{

	if (stream->send_tail != NULL && (stream->receive_done == 0 ||
	    timespeccmp(&stream->send_deadline, &stream->receive_deadline, <)))
		*deadline = stream->send_deadline;
	else if (stream->receive_done != 0)
		*deadline = stream->receive_deadline;
	else
		return (false);
	return (true);
}

int
virtio_fs_backend_stream_flush(struct virtio_fs_backend_stream *stream, int fd)
{
	struct iovec vector;
	struct msghdr message;
	ssize_t sent;
	int error;

	if (stream->send_tail == NULL)
		return (0);
	vector.iov_base = stream->send_tail + stream->send_done;
	vector.iov_len = stream->send_len - stream->send_done;
	memset(&message, 0, sizeof(message));
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	do {
		sent = sendmsg(fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL |
		    MSG_EOR);
	} while (sent < 0 && errno == EINTR);
	if (sent < 0) {
		error = errno;
		/* Only a peer that took nothing in time has stalled. */
		if ((error == EAGAIN || error == EWOULDBLOCK) &&
		    virtio_fs_backend_deadline_passed(&stream->send_deadline))
			error = ETIMEDOUT;
		return (error);
	}
	stream->send_done += (size_t)sent;
	if (stream->send_done < stream->send_len) {
		error = virtio_fs_backend_deadline_set(&stream->send_deadline);
		return (error != 0 ? error : EAGAIN);
	}
	free(stream->send_tail);
	stream->send_tail = NULL;
	stream->send_done = 0;
	stream->send_len = 0;
	return (0);
}

int
virtio_fs_backend_stream_send(struct virtio_fs_backend_stream *stream,
    int fd, const struct virtio_fs_backend_header *header, const void *payload)
{
	struct iovec vectors[2];
	struct msghdr message;
	uint8_t wire[VIRTIO_FS_BACKEND_HEADER_SIZE];
	uint8_t *tail;
	size_t skip, total;
	ssize_t sent;
	int error, i;

	if (stream == NULL || header == NULL ||
	    (payload == NULL && header->payload_len != 0))
		return (EINVAL);
	error = virtio_fs_backend_stream_flush(stream, fd);
	if (error != 0)
		return (error);
	error = virtio_fs_backend_header_encode(header, wire);
	if (error != 0)
		return (error);
	vectors[0].iov_base = wire;
	vectors[0].iov_len = sizeof(wire);
	vectors[1].iov_base = __DECONST(void *, payload);
	vectors[1].iov_len = header->payload_len;
	memset(&message, 0, sizeof(message));
	message.msg_iov = vectors;
	message.msg_iovlen = header->payload_len == 0 ? 1 : 2;
	total = sizeof(wire) + header->payload_len;
	/*
	 * local(4) SOCK_SEQPACKET shares the stream implementation: a record
	 * ends only where the sender passes MSG_EOR (without it consecutive
	 * frames coalesce), and a record larger than the peer's free receive
	 * space is accepted piecewise, so a nonblocking sendmsg() can return a
	 * short count.  Mark every frame as one record; once any part of it is
	 * queued the frame is committed, and its tail is kept for flush().
	 */
	do {
		sent = sendmsg(fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL |
		    MSG_EOR);
	} while (sent < 0 && errno == EINTR);
	if (sent < 0)
		return (errno);
	if ((size_t)sent == total)
		return (0);
	stream->send_len = total - (size_t)sent;
	stream->send_tail = malloc(stream->send_len);
	if (stream->send_tail == NULL) {
		stream->send_len = 0;
		return (ENOMEM);
	}
	tail = stream->send_tail;
	skip = (size_t)sent;
	for (i = 0; i < (int)message.msg_iovlen; i++) {
		if (skip >= vectors[i].iov_len) {
			skip -= vectors[i].iov_len;
			continue;
		}
		memcpy(tail, (const char *)vectors[i].iov_base + skip,
		    vectors[i].iov_len - skip);
		tail += vectors[i].iov_len - skip;
		skip = 0;
	}
	stream->send_done = 0;
	return (virtio_fs_backend_deadline_set(&stream->send_deadline));
}

int
virtio_fs_backend_stream_receive(struct virtio_fs_backend_stream *stream,
    int fd, struct virtio_fs_backend_header *header, void *payload,
    size_t payload_capacity, size_t *payload_len)
{
	union {
		struct cmsghdr alignment;
		unsigned char bytes[CMSG_SPACE(
		    sizeof(int) * VFSB_CONTROL_FDS)];
	} control_buffer;
	struct iovec source[2], vectors[2];
	struct msghdr message;
	ssize_t received;
	bool eor;
	int error;

	if (stream == NULL || header == NULL || payload_len == NULL ||
	    (payload == NULL && payload_capacity != 0) ||
	    payload_capacity > VIRTIO_FS_BACKEND_MAX_FRAME)
		return (EINVAL);
	/*
	 * This is a three-output transaction.  Reject aliases before recvmsg()
	 * consumes the record so a caller can correct the buffers and retry.
	 */
	if (virtio_state_ranges_overlap(header, sizeof(*header), payload,
	    payload_capacity) ||
	    virtio_state_ranges_overlap(header, sizeof(*header), payload_len,
	    sizeof(*payload_len)) ||
	    virtio_state_ranges_overlap(payload, payload_capacity, payload_len,
	    sizeof(*payload_len)))
		return (EINVAL);
	*payload_len = 0;
	source[0].iov_base = stream->receive_wire;
	source[0].iov_len = sizeof(stream->receive_wire);
	source[1].iov_base = payload;
	source[1].iov_len = payload_capacity;
	/*
	 * Every piece gets a control buffer: without one the kernel silently
	 * disposes of passed rights, and a frame carrying any is malformed.
	 */
	memset(&message, 0, sizeof(message));
	memset(&control_buffer, 0, sizeof(control_buffer));
	message.msg_control = control_buffer.bytes;
	message.msg_controllen = sizeof(control_buffer.bytes);
	if (stream->receive_done == 0) {
		message.msg_iov = source;
		message.msg_iovlen = payload_capacity == 0 ? 1 : 2;
	} else {
		/*
		 * Read exactly the rest of the header, then exactly the payload
		 * it announces, so a receive never consumes a following frame.
		 */
		message.msg_iov = vectors;
		message.msg_iovlen = virtio_fs_backend_tail(vectors, source,
		    nitems(source), stream->receive_done,
		    stream->receive_total != 0 ? stream->receive_total :
		    sizeof(stream->receive_wire));
	}
	do {
		received = recvmsg(fd, &message, MSG_DONTWAIT |
		    MSG_CMSG_CLOEXEC);
	} while (received < 0 && errno == EINTR);
	if (received < 0) {
		error = errno;
		if (error != EAGAIN && error != EWOULDBLOCK)
			goto fail;
		/* Only a peer that sent nothing in time has stalled. */
		if (stream->receive_done == 0 ||
		    !virtio_fs_backend_deadline_passed(
		    &stream->receive_deadline))
			return (EAGAIN);
		error = ETIMEDOUT;
		goto fail;
	}
	if (received == 0) {
		error = ECONNRESET;
		goto fail;
	}
	if (message.msg_controllen != 0)
		virtio_fs_backend_discard_rights(&message);
	if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
		error = EMSGSIZE;
		goto fail;
	}
	if (message.msg_controllen != 0) {
		error = EPROTO;
		goto fail;
	}
	stream->receive_done += (size_t)received;
	eor = (message.msg_flags & MSG_EOR) != 0;
	if (stream->receive_total == 0 &&
	    stream->receive_done >= sizeof(stream->receive_wire)) {
		error = virtio_fs_backend_header_decode(stream->receive_wire,
		    sizeof(stream->receive_wire), &stream->receive_header);
		if (error != 0)
			goto fail;
		if (stream->receive_header.payload_len > payload_capacity) {
			error = EMSGSIZE;
			goto fail;
		}
		stream->receive_total = sizeof(stream->receive_wire) +
		    stream->receive_header.payload_len;
	}
	/*
	 * A frame ends exactly at the peer's MSG_EOR.  A record that ends
	 * early, runs past the announced length, or reaches it without
	 * MSG_EOR has lost frame synchronization.
	 */
	if (stream->receive_total != 0 &&
	    (stream->receive_done > stream->receive_total ||
	    (stream->receive_done == stream->receive_total && !eor))) {
		error = EPROTO;
		goto fail;
	}
	if (eor) {
		if (stream->receive_done != stream->receive_total) {
			error = EPROTO;
			goto fail;
		}
		*header = stream->receive_header;
		*payload_len = stream->receive_header.payload_len;
		stream->receive_done = 0;
		stream->receive_total = 0;
		return (0);
	}
	error = virtio_fs_backend_deadline_set(&stream->receive_deadline);
	if (error != 0)
		goto fail;
	return (EAGAIN);
fail:
	stream->receive_done = 0;
	stream->receive_total = 0;
	return (error);
}

static int
virtio_fs_backend_wait(int fd, short events, const struct timespec *deadline)
{
	struct pollfd descriptor;
	struct timespec now;
	int remaining_ms, result;

	for (;;) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return (errno);
		if (timespeccmp(&now, deadline, >=))
			return (ETIMEDOUT);
		remaining_ms = (int)((deadline->tv_sec - now.tv_sec) * 1000 +
		    (deadline->tv_nsec - now.tv_nsec) / 1000000L) + 1;
		descriptor = (struct pollfd) {
			.fd = fd,
			.events = events,
		};
		result = poll(&descriptor, 1, remaining_ms);
		if (result > 0)
			return (0);
		if (result < 0 && errno != EINTR)
			return (errno);
	}
}

int
virtio_fs_backend_stream_drain(struct virtio_fs_backend_stream *stream, int fd)
{
	int error;

	error = 0;
	while (error == 0 && virtio_fs_backend_stream_sending(stream)) {
		error = virtio_fs_backend_wait(fd, POLLOUT,
		    &stream->send_deadline);
		if (error == 0)
			error = virtio_fs_backend_stream_flush(stream, fd);
		if (error == EAGAIN)
			error = 0;
	}
	return (error == ETIMEDOUT ? EIO : error);
}

int
virtio_fs_backend_send_frame(int fd,
    const struct virtio_fs_backend_header *header, const void *payload)
{
	struct virtio_fs_backend_stream stream;
	int error;

	virtio_fs_backend_stream_init(&stream);
	error = virtio_fs_backend_stream_send(&stream, fd, header, payload);
	if (error == 0)
		error = virtio_fs_backend_stream_drain(&stream, fd);
	virtio_fs_backend_stream_fini(&stream);
	return (error);
}

int
virtio_fs_backend_receive_frame(int fd,
    struct virtio_fs_backend_header *header, void *payload,
    size_t payload_capacity, size_t *payload_len)
{
	struct virtio_fs_backend_stream stream;
	int error;

	virtio_fs_backend_stream_init(&stream);
	for (;;) {
		error = virtio_fs_backend_stream_receive(&stream, fd, header,
		    payload, payload_capacity, payload_len);
		if (error != EAGAIN || stream.receive_done == 0)
			break;
		error = virtio_fs_backend_wait(fd, POLLIN,
		    &stream.receive_deadline);
		if (error != 0)
			break;
	}
	virtio_fs_backend_stream_fini(&stream);
	return (error == ETIMEDOUT ? EPROTO : error);
}

/*
 * The kernel accepts a local SOCK_SEQPACKET record piecewise when it exceeds
 * the sender's send buffer or the peer's free receive space (both default to
 * net.local.seqpacket.recvspace, 64 KiB: less than one 64 KiB FUSE_READ reply
 * plus headers).  The stream functions finish such records across readiness
 * callbacks, but every piece costs a wakeup.  Grow both
 * buffers toward one maximum-sized frame so ordinary traffic moves in one
 * piece.  This is best effort: kern.ipc.maxsockbuf may refuse the full size,
 * and the buffers are never shrunk.
 */
void
virtio_fs_backend_size_buffers(int fd, uint32_t maximum_message)
{
	socklen_t length;
	uint64_t target;
	int current, option, size;
	size_t i;
	static const int options[] = { SO_RCVBUF, SO_SNDBUF };

	if (fd < 0)
		return;
	target = (uint64_t)VIRTIO_FS_BACKEND_HEADER_SIZE + maximum_message;
	if (target > INT_MAX)
		target = INT_MAX;
	for (i = 0; i < nitems(options); i++) {
		option = options[i];
		length = sizeof(current);
		if (getsockopt(fd, SOL_SOCKET, option, &current, &length) != 0)
			continue;
		for (size = (int)target; size > current; size /= 2) {
			if (setsockopt(fd, SOL_SOCKET, option, &size,
			    sizeof(size)) == 0 || errno != ENOBUFS)
				break;
		}
	}
}
