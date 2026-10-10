/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

static unsigned polls;
static int mode;
static uint64_t now_ns;

static int
fake_connectat(int directory, int fd, const struct sockaddr *sa, socklen_t len)
{
	(void)sa;
	(void)len;
	ATF_CHECK_EQ(directory, fd);
	ATF_CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) != 0);
	errno = EINPROGRESS;
	return (-1);
}

static int
fake_clock(clockid_t clock, struct timespec *ts)
{
	ATF_CHECK_EQ(CLOCK_MONOTONIC, clock);
	ts->tv_sec = now_ns / 1000000000;
	ts->tv_nsec = now_ns % 1000000000;
	return (0);
}

static int
fake_poll(struct pollfd *fds, nfds_t count, int timeout)
{
	ATF_CHECK_EQ(1, count);
	ATF_CHECK_EQ(POLLOUT, fds[0].events);
	ATF_CHECK_EQ(polls == 0 ? 100 : 40, timeout);
	polls++;
	if (mode == 1) {
		errno = EIO;
		return (-1);
	}
	if (mode == 2) {
		fds[0].revents = POLLOUT;
		return (1);
	}
	if (polls == 1) {
		now_ns += 60000000;
		errno = EINTR;
		return (-1);
	}
	now_ns += 40000000;
	return (0);
}

#define connectat fake_connectat
#define clock_gettime fake_clock
#define poll fake_poll
#define NETWORKCMP_TESTING
#include "../networkcmp.c"

ATF_TC_WITHOUT_HEAD(connect_deadline);
ATF_TC_BODY(connect_deadline, tc)
{
	struct sockaddr_in sa = { .sin_len = sizeof(sa), .sin_family = AF_INET };
	int fd, flags, result, error;

	for (mode = 0; mode < 3; mode++) {
		for (int nonblock = 0; nonblock < 2; nonblock++) {
			fd = socket(AF_INET, SOCK_STREAM, 0);
			ATF_REQUIRE(fd >= 0);
			flags = fcntl(fd, F_GETFL);
			ATF_REQUIRE(flags != -1);
			if (nonblock)
				flags |= O_NONBLOCK;
			ATF_REQUIRE_EQ(0, fcntl(fd, F_SETFL, flags));
			polls = 0;
			now_ns = 1000000000;
			result = broker_perform_connect(NULL, fd,
			    (const struct sockaddr *)&sa, sizeof(sa), 100);
			error = errno;
			ATF_CHECK_EQ(mode == 2 ? 0 : -1, result);
			if (mode != 2)
				ATF_CHECK_EQ(mode == 0 ? ETIMEDOUT : EIO, error);
			ATF_CHECK_EQ(mode == 0 ? 2 : 1, polls);
			ATF_CHECK_EQ(flags, fcntl(fd, F_GETFL));
			close(fd);
		}
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, connect_deadline);
	return (atf_no_error());
}
