/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
/* Real libbluetooth command/receive code and real sockets; HCI-specific filter
 * options and selected I/O/clock faults are substituted. Packets follow Core Vol 4
 * Part E 5.4.4, 7.7.5, 7.7.8, 7.7.14 and 7.7.15. Event interleaving also
 * follows Fuchsia f15 transport/command_channel{,_unittest}.cc.
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static struct ng_btsocket_hci_raw_filter filter;
static unsigned int set_count, fail_set;
static int event_fd;
static unsigned int event_count;
static uint8_t events[1024][16];
static size_t event_lengths[1024];
static int retry_fd = -1, short_write_fd = -1, jump_clock;
static volatile sig_atomic_t alarm_count;

int __wrap_getsockopt(int, int, int, void *, socklen_t *);
int __wrap_setsockopt(int, int, int, const void *, socklen_t);
int __real_getsockopt(int, int, int, void *, socklen_t *);
int __real_setsockopt(int, int, int, const void *, socklen_t);
ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_read(int, void *, size_t);
ssize_t __real_writev(int, const struct iovec *, int);
ssize_t __wrap_writev(int, const struct iovec *, int);
time_t __real_time(time_t *);
time_t __wrap_time(time_t *);

ssize_t
__wrap_read(int fd, void *p, size_t size)
{
	if (fd == retry_fd) {
		/* Simulate a packet disappearing after readiness was reported. */
		ATF_REQUIRE(__real_read(fd, p, size) > 0);
		retry_fd = -1;
		errno = EAGAIN;
		return (-1);
	}
	return (__real_read(fd, p, size));
}

ssize_t
__wrap_writev(int fd, const struct iovec *iov, int count)
{
	if (fd == short_write_fd)
		return (1);
	return (__real_writev(fd, iov, count));
}

time_t
__wrap_time(time_t *result)
{
	time_t now = __real_time(NULL);
	if (jump_clock != 0)
		now += 3600 * jump_clock++;
	if (result != NULL)
		*result = now;
	return (now);
}

static void
on_alarm(int signo)
{
	(void)signo;
	alarm_count++;
}

static double
elapsed(const struct timespec *start)
{
	struct timespec now;
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &now));
	return (now.tv_sec - start->tv_sec +
	    (now.tv_nsec - start->tv_nsec) / 1000000000.0);
}

int
__wrap_getsockopt(int fd, int level, int opt, void *p, socklen_t *len)
{
	if (level != SOL_HCI_RAW || opt != SO_HCI_RAW_FILTER)
		return (__real_getsockopt(fd, level, opt, p, len));
	ATF_REQUIRE_EQ(sizeof(filter), *len);
	memcpy(p, &filter, sizeof(filter));
	return (0);
}

int
__wrap_setsockopt(int fd, int level, int opt, const void *p, socklen_t len)
{
	if (level != SOL_HCI_RAW || opt != SO_HCI_RAW_FILTER)
		return (__real_setsockopt(fd, level, opt, p, len));
	ATF_REQUIRE_EQ(sizeof(filter), len);
	if (++set_count == fail_set) {
		errno = EACCES;
		return (-1);
	}
	memcpy(&filter, p, sizeof(filter));
	return (0);
}

static void
record_event(int fd, const void *p, size_t n)
{
	ATF_REQUIRE_EQ(event_fd, fd);
	ATF_REQUIRE(event_count < nitems(events));
	ATF_REQUIRE(n <= sizeof(events[0]));
	memcpy(events[event_count], p, n);
	event_lengths[event_count++] = n;
}

static void
setup(int fds[2])
{
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, fds));
	memset(&filter, 0x55, sizeof(filter));
	set_count = fail_set = event_count = 0;
	event_fd = fds[0];
}

static void
packet(int fd, const void *p, size_t n)
{
	ATF_REQUIRE_EQ((ssize_t)n, send(fd, p, n, 0));
}

static int
reset(int fd, time_t timeout)
{
	uint8_t status = 0xff;
	struct bt_devreq r = { .opcode = 0x0c03, .rparam = &status,
	    .rlen = sizeof(status) };
	int rc = bt_devreq_events(fd, &r, timeout, record_event);
	if (rc == 0) {
		ATF_CHECK_EQ(1, r.rlen);
		ATF_CHECK_EQ(0, status);
	}
	return (rc);
}

static const uint8_t complete[] = { 4, 0x0e, 4, 1, 3, 0x0c, 0 };
static const uint8_t status_ok[] = { 4, 0x0f, 4, 0, 1, 3, 0x0c };
static const uint8_t disconnected[] = { 4, 5, 4, 0, 0x40, 0, 0x13 };
static const uint8_t encrypted[] = { 4, 8, 4, 0, 0x40, 0, 1 };

ATF_TC_WITHOUT_HEAD(interleaved_session);
ATF_TC_BODY(interleaved_session, tc)
{
	int fds[2];
	uint8_t cmd[16], later[16];
	struct ng_btsocket_hci_raw_filter before;
	setup(fds);
	before = filter;
	/* 256 command cycles, 512 ordered control events, and an event arriving
	 * just after each completion. No event may be duplicated or lost. */
	for (unsigned int i = 0; i < 256; i++) {
		packet(fds[1], status_ok, sizeof(status_ok));
		packet(fds[1], encrypted, sizeof(encrypted));
		packet(fds[1], disconnected, sizeof(disconnected));
		packet(fds[1], complete, sizeof(complete));
		packet(fds[1], encrypted, sizeof(encrypted));
		ATF_REQUIRE_EQ(0, reset(fds[0], 1));
		ATF_REQUIRE_EQ((i + 1) * 2, event_count);
		ATF_CHECK_EQ(0, memcmp(events[i * 2], encrypted, sizeof(encrypted)));
		ATF_CHECK_EQ(0, memcmp(events[i * 2 + 1], disconnected,
		    sizeof(disconnected)));
		ATF_CHECK_EQ(sizeof(encrypted), event_lengths[i * 2]);
		ATF_CHECK_EQ(sizeof(disconnected), event_lengths[i * 2 + 1]);
		ATF_REQUIRE_EQ(sizeof(encrypted), bt_devrecv(fds[0], later,
		    sizeof(later), 0));
		ATF_CHECK_EQ(0, memcmp(later, encrypted, sizeof(encrypted)));
		ATF_REQUIRE_EQ(4, recv(fds[1], cmd, sizeof(cmd), 0));
		ATF_CHECK_EQ(0, memcmp(cmd, "\x01\x03\x0c\x00", 4));
		ATF_CHECK_EQ(0, memcmp(&before, &filter, sizeof(filter)));
	}
	close(fds[0]); close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(truncated_command_headers);
ATF_TC_BODY(truncated_command_headers, tc)
{
	for (unsigned int kind = 0; kind < 2; kind++) {
		for (unsigned int n = 0; n < 3 + kind; n++) {
			int fds[2];
			uint8_t bad[7] = { 4, kind ? 0x0f : 0x0e, n,
			    1, 3, 0x0c, 0 };
			setup(fds);
			packet(fds[1], bad, 3 + n);
			packet(fds[1], complete, sizeof(complete));
			ATF_CHECK_EQ(-1, reset(fds[0], 1));
			ATF_CHECK_EQ(EIO, errno);
			ATF_CHECK_EQ(2, set_count);
			ATF_CHECK_EQ(0, event_count);
			close(fds[0]); close(fds[1]);
		}
	}
}

ATF_TC_WITHOUT_HEAD(error_and_recovery);
ATF_TC_BODY(error_and_recovery, tc)
{
	const uint8_t denied[] = { 4, 0x0f, 4, 0x0c, 1, 3, 0x0c };
	uint8_t cmd[16];
	int fds[2];
	setup(fds);
	for (unsigned int i = 0; i < 64; i++) {
		packet(fds[1], disconnected, sizeof(disconnected));
		packet(fds[1], denied, sizeof(denied));
		ATF_CHECK_EQ(-1, reset(fds[0], 1));
		ATF_CHECK_EQ(EIO, errno);
		ATF_REQUIRE_EQ(4, recv(fds[1], cmd, sizeof(cmd), 0));
		packet(fds[1], complete, sizeof(complete));
		ATF_CHECK_EQ(0, reset(fds[0], 1));
		ATF_REQUIRE_EQ(4, recv(fds[1], cmd, sizeof(cmd), 0));
		ATF_CHECK_EQ(i + 1, event_count);
	}
	close(fds[0]); close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(timeout_restores_filter);
ATF_TC_BODY(timeout_restores_filter, tc)
{
	int fds[2];
	struct ng_btsocket_hci_raw_filter before;
	setup(fds);
	before = filter;
	packet(fds[1], disconnected, sizeof(disconnected));
	ATF_CHECK_EQ(-1, reset(fds[0], 1));
	ATF_CHECK_EQ(ETIMEDOUT, errno);
	ATF_CHECK_EQ(1, event_count);
	ATF_CHECK_EQ(0, memcmp(&before, &filter, sizeof(filter)));
	close(fds[0]); close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(restore_failure_reported);
ATF_TC_BODY(restore_failure_reported, tc)
{
	int fds[2];
	setup(fds);
	fail_set = 2;
	packet(fds[1], complete, sizeof(complete));
	ATF_CHECK_EQ(-1, reset(fds[0], 1));
	ATF_CHECK_EQ(EACCES, errno);
	close(fds[0]); close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(receive_closed_transport);
ATF_TC_BODY(receive_closed_transport, tc)
{
	int fds[2];
	uint8_t buf[16] = { 4, 0x0e, 4, 1, 3, 0x0c, 0 };
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
	close(fds[1]);
	ATF_CHECK_EQ(-1, bt_devrecv(fds[0], buf, sizeof(buf), 1));
	ATF_CHECK_EQ(ECONNRESET, errno);
	close(fds[0]);
}

ATF_TC_WITHOUT_HEAD(receive_packet_length_matrix);
ATF_TC_BODY(receive_packet_length_matrix, tc)
{
	int fds[2];
	uint8_t input[260], output[260];
	setup(fds);
	/* Every event parameter length, with a short frame before a valid one.
	 * Exact framing rejects truncation and recovers on the next record. */
	for (unsigned int n = 0; n <= 255; n++) {
		memset(input, 0x6d, sizeof(input));
		input[0] = 4; input[1] = 0xff; input[2] = n;
		packet(fds[1], input, n + 2);
		ATF_CHECK_EQ(-1, bt_devrecv(fds[0], output, sizeof(output), 0));
		ATF_CHECK_EQ(EIO, errno);
		packet(fds[1], input, n + 3);
		ATF_REQUIRE_EQ(n + 3, bt_devrecv(fds[0], output, sizeof(output), 0));
		ATF_CHECK_EQ(0, memcmp(input, output, n + 3));
	}
	close(fds[0]); close(fds[1]);
}

ATF_TC(receive_signal_deadline);
ATF_TC_HEAD(receive_signal_deadline, tc)
{
	atf_tc_set_md_var(tc, "timeout", "5");
	/* Scheduling load must not dominate the one-second protocol deadline. */
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(receive_signal_deadline, tc)
{
	int fds[2], rc, error;
	uint8_t buf[16];
	struct timespec start;
	struct sigaction sa = { .sa_handler = on_alarm }, old;
	struct itimerval timer = { .it_interval = { .tv_usec = 20000 },
	    .it_value = { .tv_usec = 20000 } };
	setup(fds);
	sigemptyset(&sa.sa_mask);
	ATF_REQUIRE_EQ(0, sigaction(SIGALRM, &sa, &old));
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &start));
	ATF_REQUIRE_EQ(0, setitimer(ITIMER_REAL, &timer, NULL));
	rc = bt_devrecv(fds[0], buf, sizeof(buf), 1);
	error = errno;
	memset(&timer, 0, sizeof(timer));
	ATF_REQUIRE_EQ(0, setitimer(ITIMER_REAL, &timer, NULL));
	ATF_REQUIRE_EQ(0, sigaction(SIGALRM, &old, NULL));
	ATF_CHECK_EQ(-1, rc);
	ATF_CHECK_EQ(ETIMEDOUT, error);
	ATF_CHECK(alarm_count >= 10);
	ATF_CHECK(elapsed(&start) >= 0.9);
	ATF_CHECK(elapsed(&start) < 2.0);
	close(fds[0]); close(fds[1]);
}

ATF_TC(receive_retry_deadline);
ATF_TC_HEAD(receive_retry_deadline, tc)
{
	atf_tc_set_md_var(tc, "timeout", "5");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(receive_retry_deadline, tc)
{
	int fds[2], flags, error;
	uint8_t buf[16];
	struct timespec start;
	setup(fds);
	flags = fcntl(fds[0], F_GETFL);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE_EQ(0, fcntl(fds[0], F_SETFL, flags | O_NONBLOCK));
	packet(fds[1], complete, sizeof(complete));
	retry_fd = fds[0];
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &start));
	ATF_CHECK_EQ(-1, bt_devrecv(fds[0], buf, sizeof(buf), 1));
	error = errno;
	ATF_CHECK_EQ(ETIMEDOUT, error);
	ATF_CHECK(elapsed(&start) >= 0.9);
	ATF_CHECK(elapsed(&start) < 2.0);
	ATF_CHECK_EQ(flags | O_NONBLOCK, fcntl(fds[0], F_GETFL));
	packet(fds[1], complete, sizeof(complete));
	ATF_CHECK_EQ(sizeof(complete), bt_devrecv(fds[0], buf, sizeof(buf), 0));
	close(fds[0]); close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(command_wall_clock_jump);
ATF_TC_BODY(command_wall_clock_jump, tc)
{
	int fds[2];
	setup(fds);
	packet(fds[1], encrypted, sizeof(encrypted));
	packet(fds[1], complete, sizeof(complete));
	/* No system clock change: inject a one-hour jump into time(3). */
	jump_clock = 1;
	ATF_CHECK_EQ(0, reset(fds[0], 1));
	jump_clock = 0;
	ATF_CHECK_EQ(1, event_count);
	ATF_CHECK_EQ(2, set_count);
	close(fds[0]); close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(command_short_write);
ATF_TC_BODY(command_short_write, tc)
{
	int fds[2];
	struct ng_btsocket_hci_raw_filter before;
	setup(fds);
	before = filter;
	short_write_fd = fds[0];
	ATF_CHECK_EQ(-1, reset(fds[0], 0));
	ATF_CHECK_EQ(EIO, errno);
	ATF_CHECK_EQ(0, memcmp(&before, &filter, sizeof(filter)));
	short_write_fd = -1;
	packet(fds[1], complete, sizeof(complete));
	ATF_CHECK_EQ(0, reset(fds[0], 1));
	close(fds[0]); close(fds[1]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, interleaved_session);
	ATF_TP_ADD_TC(tp, truncated_command_headers);
	ATF_TP_ADD_TC(tp, error_and_recovery);
	ATF_TP_ADD_TC(tp, timeout_restores_filter);
	ATF_TP_ADD_TC(tp, restore_failure_reported);
	ATF_TP_ADD_TC(tp, receive_closed_transport);
	ATF_TP_ADD_TC(tp, receive_packet_length_matrix);
	ATF_TP_ADD_TC(tp, receive_signal_deadline);
	ATF_TP_ADD_TC(tp, receive_retry_deadline);
	ATF_TP_ADD_TC(tp, command_wall_clock_jump);
	ATF_TP_ADD_TC(tp, command_short_write);
	return (atf_no_error());
}
