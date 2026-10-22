/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static int test_clock_gettime(clockid_t, struct timespec *);
static int test_poll(struct pollfd *, nfds_t, int);
static ssize_t test_sendmsg(int, const struct msghdr *, int);
static ssize_t test_recvmsg(int, struct msghdr *, int);
#define clock_gettime test_clock_gettime
#define poll test_poll
#define sendmsg test_sendmsg
#define recvmsg test_recvmsg
#include "dtraced_io.h"
#undef clock_gettime
#undef poll
#undef sendmsg
#undef recvmsg

static int fail_clock, huge_clock, scripted_clock, clock_calls, poll_calls;
static int invalid_poll, force_wouldblock;
static int
test_clock_gettime(clockid_t clock, struct timespec *time)
{
	if (scripted_clock) {
		time->tv_sec = 0;
		time->tv_nsec = clock_calls++ == 0 ? 100000000L : 102000000L;
		return (0);
	}
	if (fail_clock) {
		errno = EIO;
		return (-1);
	}
	if (huge_clock) {
		time->tv_sec = INT64_MAX / 1000 + (huge_clock == 2);
		time->tv_nsec = 0;
		return (0);
	}
	return (clock_gettime(clock, time));
}

static int
test_poll(struct pollfd *fds, nfds_t count, int timeout)
{
	if (invalid_poll) {
		assert(count == 1 && timeout > 0);
		poll_calls++;
		fds[0].revents = POLLNVAL;
		return (1);
	}
	if (scripted_clock) {
		poll_calls++;
		errno = EIO;
		return (-1);
	}
	return (poll(fds, count, timeout));
}

static ssize_t
test_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	if (force_wouldblock) {
		errno = EAGAIN;
		return (-1);
	}
	return (sendmsg(fd, msg, flags));
}

static ssize_t
test_recvmsg(int fd, struct msghdr *msg, int flags)
{
	if (force_wouldblock) {
		errno = EAGAIN;
		return (-1);
	}
	return (recvmsg(fd, msg, flags));
}

int
main(void)
{
	int pair[2], source, received;
	struct stat original, copied;
	unsigned char marker;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
	source = open("/dev/null", O_RDONLY | O_CLOEXEC);
	assert(source >= 0);
	assert(dtraced_io_send_fd(pair[0], source,
	    dtraced_io_milliseconds() + 1000) == 0);
	received = dtraced_io_recv_fd(pair[1],
	    dtraced_io_milliseconds() + 1000);
	assert(received >= 0);
	assert(fstat(source, &original) == 0 && fstat(received, &copied) == 0);
	assert(original.st_rdev == copied.st_rdev);
	assert((fcntl(received, F_GETFD) & FD_CLOEXEC) != 0);
	close(received);
	marker = 0xa5;
	assert(send(pair[0], &marker, 1, 0) == 1);
	assert(dtraced_io_recv_fd(pair[1],
	    dtraced_io_milliseconds() + 1000) == -1 && errno == EPROTO);
	unsigned char control[CMSG_SPACE(2 * sizeof(int))] = {0};
	struct iovec iov = { &marker, 1 };
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	int duplicate[2] = { source, source };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(duplicate));
	memcpy(CMSG_DATA(cmsg), duplicate, sizeof(duplicate));
	assert(sendmsg(pair[0], &msg, 0) == 1);
	assert(dtraced_io_recv_fd(pair[1],
	    dtraced_io_milliseconds() + 1000) == -1 && errno == EPROTO);
	assert(dtraced_io_recv_fd(pair[1],
	    dtraced_io_milliseconds() + 30) == -1 && errno == ETIMEDOUT);
	int64_t deadline = dtraced_io_milliseconds() + 1000;
	fail_clock = 1;
	assert(dtraced_io_send_fd(pair[0], source, deadline) == -1 &&
	    errno == EIO);
	assert(dtraced_io_recv_fd(pair[1], deadline) == -1 && errno == EIO);
	fail_clock = 0;
	assert(dtraced_io_deadline_after(0) == -1 && errno == EINVAL);
	fail_clock = 1;
	assert(dtraced_io_deadline_after(1000) == -1 && errno == EIO);
	fail_clock = 0;
	huge_clock = 1;
	assert(dtraced_io_deadline_after(10000) == -1 && errno == EOVERFLOW);
	huge_clock = 2;
	assert(dtraced_io_milliseconds() == -1 && errno == EOVERFLOW);
	huge_clock = 0;
	assert(dtraced_io_deadline_from(INT64_MAX - 99, 100) == -1 &&
	    errno == EOVERFLOW);
	assert(dtraced_io_deadline_from(100, 100) == 200);
	assert(dtraced_io_deadline_after(1000) > dtraced_io_milliseconds());
	int timeout;
	assert(dtraced_io_remaining_timeout(-1, &timeout) == -1 &&
	    errno == EINVAL);
	scripted_clock = 1;
	clock_calls = poll_calls = 0;
	size_t transferred = 99;
	assert(dtraced_io_transfer(pair[1], &marker, 1, false, 101,
	    &transferred) == -1 && errno == ETIMEDOUT);
	assert(transferred == 0 && clock_calls == 2 && poll_calls == 0);
	scripted_clock = 0;
	force_wouldblock = invalid_poll = 1;
	poll_calls = 0;
	assert(dtraced_io_send_fd(pair[0], source,
	    dtraced_io_deadline_after(1000)) == -1 && errno == EBADF);
	assert(poll_calls == 1);
	poll_calls = 0;
	assert(dtraced_io_recv_fd(pair[1],
	    dtraced_io_deadline_after(1000)) == -1 && errno == EBADF);
	assert(poll_calls == 1);
	force_wouldblock = invalid_poll = 0;
	close(source);
	close(pair[0]);
	close(pair[1]);
	return (0);
}
