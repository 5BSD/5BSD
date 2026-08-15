/*
 * Shared helpers for OES tests.
 */
#ifndef _OES_TEST_COMMON_H_
#define _OES_TEST_COMMON_H_

#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/oes/oes.h>

typedef union {
	oes_message_t	msg;
	uint8_t		raw[OES_MSG_MAX_SIZE];
} test_msg_buf;

/*
 * Test-failure accounting.  Previously TEST_FAIL()/ASSERT_MSG() only printed
 * "FAIL" and the process still exited 0, so a failing test was scored as a
 * pass by kyua/plain-test runners.  Now every failure is recorded here and an
 * atexit hook forces a non-zero exit status, making the harness sound.
 */
static int oes_test_failures;

static void
oes_test_report_failures(void)
{

	if (oes_test_failures != 0)
		_exit(1);
}

__attribute__((constructor))
static void
oes_test_install_reporter(void)
{

	(void)atexit(oes_test_report_failures);
}

#define TEST_BEGIN(_name) \
	printf("  Testing %s...\n", (_name))

#define TEST_SUITE_BEGIN(_name) \
	printf("Testing %s...\n", (_name))

#define TEST_SUITE_END(_name) \
	printf("%s: ok\n", (_name))

#define TEST_PASS() \
	printf("    PASS\n")

#define TEST_FAIL(_fmt, ...) do {					\
	printf("    FAIL: " _fmt "\n", ##__VA_ARGS__);			\
	oes_test_failures++;						\
} while (0)

#define TEST_SKIP(_fmt, ...) \
	printf("    SKIP: " _fmt "\n", ##__VA_ARGS__)

#define ASSERT_MSG(_cond, _fmt, ...) do {				\
	if (!(_cond)) {							\
		printf("    FAIL: " _fmt "\n", ##__VA_ARGS__);		\
		oes_test_failures++;					\
	}								\
} while (0)

static inline int
test_open_oes(void)
{

	return (open(OES_DEVICE_PATH, O_RDWR | O_NONBLOCK | O_CLOEXEC));
}

static inline int
test_set_mode(int fd, uint32_t mode)
{
	struct oes_mode_args args;

	memset(&args, 0, sizeof(args));
	args.ema_mode = mode;
	return (ioctl(fd, OES_IOC_SET_MODE, &args));
}

static inline int
test_subscribe(int fd, oes_event_type_t *events, size_t count, uint32_t flags)
{
	struct oes_subscribe_args args;

	memset(&args, 0, sizeof(args));
	args.esa_events = events;
	args.esa_count = count;
	args.esa_flags = flags;
	return (ioctl(fd, OES_IOC_SUBSCRIBE, &args));
}

static inline int
test_mute_self(int fd)
{
	struct oes_mute_args args;

	memset(&args, 0, sizeof(args));
	args.emu_flags = OES_MUTE_SELF;
	return (ioctl(fd, OES_IOC_MUTE_PROCESS, &args));
}

static inline int
test_unmute_self(int fd)
{
	struct oes_mute_args args;

	memset(&args, 0, sizeof(args));
	args.emu_flags = OES_MUTE_SELF;
	return (ioctl(fd, OES_IOC_UNMUTE_PROCESS, &args));
}

static inline int
test_wait_event(int fd, oes_message_t *msg, int timeout_ms)
{
	struct pollfd pfd;
	ssize_t n;

	if (msg == NULL) {
		errno = EINVAL;
		return (-1);
	}

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, timeout_ms) <= 0) {
		errno = EAGAIN;
		return (-1);
	}
	if ((pfd.revents & POLLIN) == 0) {
		errno = EAGAIN;
		return (-1);
	}

	n = read(fd, msg, OES_MSG_MAX_SIZE);
	if (n < (ssize_t)sizeof(*msg))
		return (-1);
	if (msg->em_size < sizeof(*msg) || msg->em_size > (uint32_t)n) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

static inline int
test_wait_event_type(int fd, oes_message_t *msg, oes_event_type_t event,
    int timeout_ms)
{
	int waited = 0;

	while (waited < timeout_ms) {
		int slice = timeout_ms - waited;

		if (slice > 100)
			slice = 100;
		if (test_wait_event(fd, msg, slice) == 0) {
			if (msg->em_event == event)
				return (0);
		}
		waited += slice;
	}

	errno = ETIMEDOUT;
	return (-1);
}

static inline int
test_wait_event_pid(int fd, pid_t pid, oes_event_type_t event, int timeout_ms,
    oes_message_t *out)
{
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		struct timespec now;
		long elapsed_ms;
		int remaining;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= timeout_ms)
			break;

		remaining = timeout_ms - (int)elapsed_ms;
		if (remaining > 100)
			remaining = 100;

		if (test_wait_event(fd, msg, remaining) != 0)
			continue;
		if (msg->em_process.ep_pid != pid)
			continue;
		if (msg->em_event != event)
			continue;
		if (out != NULL)
			*out = *msg;
		return (0);
	}

	return (ETIMEDOUT);
}

static inline void
test_drain_events(int fd)
{
	test_msg_buf buf;

	while (test_wait_event(fd, &buf.msg, 0) == 0)
		;
}

static inline void
test_batch_reset(void)
{
}

static inline int
test_create_temp_file(char *path, size_t pathlen)
{
	int fd;

	if (path == NULL || pathlen == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (strlcpy(path, "/tmp/oes-test.XXXXXX", pathlen) >= pathlen) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	fd = mkstemp(path);
	return (fd);
}

#endif /* !_OES_TEST_COMMON_H_ */
