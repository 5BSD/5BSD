/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_IO_H
#define DTRACED_IO_H
#include <sys/socket.h>
#include <errno.h>
#include <stddef.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

static inline int64_t
dtraced_io_milliseconds(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return (-1);
	if (now.tv_sec < 0 || now.tv_nsec < 0 ||
	    now.tv_nsec >= 1000000000L ||
	    (uint64_t)now.tv_sec >
	    (uint64_t)(INT64_MAX - now.tv_nsec / 1000000) / 1000) {
		errno = EOVERFLOW;
		return (-1);
	}
	return ((int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000);
}

static inline int64_t
dtraced_io_deadline_from(int64_t now, int64_t duration_ms)
{
	if (now < 0 || duration_ms <= 0) {
		errno = EINVAL;
		return (-1);
	}
	if (now > INT64_MAX - duration_ms) {
		errno = EOVERFLOW;
		return (-1);
	}
	return (now + duration_ms);
}

static inline int64_t
dtraced_io_deadline_after(int64_t duration_ms)
{
	if (duration_ms <= 0) {
		errno = EINVAL;
		return (-1);
	}
	int64_t now = dtraced_io_milliseconds();
	if (now < 0)
		return (-1);
	return (dtraced_io_deadline_from(now, duration_ms));
}

/* Recheck immediately before a wait: a preceding nonblocking call may have
 * consumed the remaining budget.  Check before subtracting to avoid signed
 * overflow for an invalid or already expired deadline. */
static inline int
dtraced_io_remaining_timeout(int64_t deadline, int *timeout)
{
	int64_t now, left;

	if (deadline < 0 || timeout == NULL) {
		errno = EINVAL;
		return (-1);
	}
	now = dtraced_io_milliseconds();
	if (now < 0)
		return (-1);
	if (deadline <= now) {
		errno = ETIMEDOUT;
		return (-1);
	}
	left = deadline - now;
	*timeout = left > INT32_MAX ? INT32_MAX : (int)left;
	return (0);
}

/* Finish a pending nonblocking connect without extending its deadline. */
static inline int
dtraced_io_complete_connect(int fd, int64_t deadline)
{
	struct pollfd event = { fd, POLLOUT, 0 };
	int error, status, timeout;
	socklen_t error_length;

	for (;;) {
		if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
			return (-1);
		status = poll(&event, 1, timeout);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (status == 0)
			continue;
		if (event.revents & POLLNVAL) {
			errno = EBADF;
			return (-1);
		}
		error_length = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error,
		    &error_length) != 0)
			return (-1);
		if (error == 0)
			return (0);
		if (error != EINPROGRESS && error != EALREADY) {
			errno = error;
			return (-1);
		}
	}
}

static inline int
dtraced_io_connect(int fd, const struct sockaddr *address, socklen_t length,
    int64_t deadline)
{
	int timeout;

	if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
		return (-1);
	if (connect(fd, address, length) == 0)
		return (0);
	if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR)
		return (-1);
	return (dtraced_io_complete_connect(fd, deadline));
}

/* The caller shares one absolute deadline across the complete frame. */
static inline int
dtraced_io_transfer(int fd, void *data, size_t length, bool writing, int64_t deadline,
    size_t *transferred)
{
	unsigned char *p = (unsigned char *)data;
	struct pollfd event = { fd, (short)(writing ? POLLOUT : POLLIN), 0 };
	ssize_t n;
	int status, timeout;

	*transferred = 0;
	while (*transferred < length) {
		if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
			return (-1);
		n = writing ? send(fd, p + *transferred, length - *transferred,
		    MSG_DONTWAIT | MSG_NOSIGNAL) : recv(fd, p + *transferred,
		    length - *transferred, MSG_DONTWAIT);
		if (n > 0) {
			*transferred += n;
			continue;
		}
		if (n == 0) {
			errno = writing ? EPIPE : ECONNRESET;
			return (-1);
		}
		if (errno == EINTR)
			continue;
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			return (-1);
		if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
			return (-1);
		status = poll(&event, 1, timeout);
		if (status < 0 && errno != EINTR)
			return (-1);
		if (status > 0 && (event.revents & POLLNVAL) != 0) {
			errno = EBADF;
			return (-1);
		}
	}
	return (0);
}

/* Protocol 28 scalar framing is eight bytes in little-endian order. */
static inline void
dtraced_wire_put_u64(unsigned char bytes[8], uint64_t value)
{
	for (unsigned i = 0; i != 8; ++i)
		bytes[i] = (unsigned char)(value >> (i * 8));
}

static inline uint64_t
dtraced_wire_get_u64(const unsigned char bytes[8])
{
	uint64_t value = 0;
	for (unsigned i = 0; i != 8; ++i)
		value |= (uint64_t)bytes[i] << (i * 8);
	return (value);
}

static inline int
dtraced_io_write_size(int fd, size_t value, int64_t deadline,
    size_t *transferred)
{
	unsigned char wire[8];
	dtraced_wire_put_u64(wire, value);
	return (dtraced_io_transfer(fd, wire, sizeof(wire), true,
	    deadline, transferred));
}

static inline int
dtraced_io_read_size(int fd, size_t *value, int64_t deadline,
    size_t *transferred)
{
	unsigned char wire[8];
	uint64_t decoded;

	if (dtraced_io_transfer(fd, wire, sizeof(wire), false,
	    deadline, transferred) != 0)
		return (-1);
	decoded = dtraced_wire_get_u64(wire);
	if (decoded > SIZE_MAX) {
		errno = EOVERFLOW;
		return (-1);
	}
	*value = (size_t)decoded;
	return (0);
}

/* A single byte carries one descriptor; the caller owns the received fd. */
static inline int
dtraced_io_send_fd(int sockfd, int passfd, int64_t deadline)
{
	unsigned char marker = 0xa5;
	unsigned char control[CMSG_SPACE(sizeof(int))] = {0};
	struct iovec iov = { &marker, sizeof(marker) };
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct pollfd event = { sockfd, POLLOUT, 0 };
	ssize_t n;
	int status, timeout;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &passfd, sizeof(passfd));
	for (;;) {
		if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
			return (-1);
		n = sendmsg(sockfd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n == 1)
			return (0);
		if (n == 0) { errno = EPIPE; return (-1); }
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
			return (-1);
		if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
			return (-1);
		status = poll(&event, 1, timeout);
		if (status < 0 && errno != EINTR)
			return (-1);
		if (status > 0 && (event.revents & POLLNVAL) != 0) {
			errno = EBADF;
			return (-1);
		}
	}
}

static inline int
dtraced_io_recv_fd(int sockfd, int64_t deadline)
{
	unsigned char marker = 0;
	unsigned char control[CMSG_SPACE(4 * sizeof(int))] = {0};
	struct iovec iov = { &marker, sizeof(marker) };
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct pollfd event = { sockfd, POLLIN, 0 };
	int received = -1, count, status, timeout;
	ssize_t n;

	for (;;) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);
		if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
			return (-1);
		n = recvmsg(sockfd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
		if (n > 0)
			break;
		if (n == 0) { errno = ECONNRESET; return (-1); }
		if (errno == EINTR)
			continue;
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			return (-1);
		if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
			return (-1);
		status = poll(&event, 1, timeout);
		if (status < 0 && errno != EINTR)
			return (-1);
		if (status > 0 && (event.revents & POLLNVAL) != 0) {
			errno = EBADF;
			return (-1);
		}
	}
	count = 0;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len < CMSG_LEN(0))
			continue;
		size_t nfd = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		for (size_t i = 0; i < nfd; i++) {
			int fd;
			memcpy(&fd, CMSG_DATA(cmsg) + i * sizeof(int), sizeof(fd));
			if (count++ == 0)
				received = fd;
			else
				close(fd);
		}
	}
	if (n != 1 || marker != 0xa5 || count != 1 ||
	    (msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
		if (received >= 0)
			close(received);
		errno = EPROTO;
		return (-1);
	}
	return (received);
}
#endif
