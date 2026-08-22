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
#include <stdbool.h>
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

/* Stateful reader: NOTIFY reads may contain several packed messages. */
struct test_event_reader {
	test_msg_buf	ter_batch;
	size_t		ter_off;
	size_t		ter_len;
	int		ter_fd;
};

#define OES_TEST_DEFAULT_READERS	16

/*
 * Keep independent batch state for each descriptor.  Multi-client tests
 * commonly alternate reads between descriptors; a single shared reader
 * silently discarded the unread tail of the previous descriptor's batch.
 */
static struct test_event_reader
    oes_test_default_readers[OES_TEST_DEFAULT_READERS];
static bool oes_test_default_readers_initialized;

/*
 * Test-failure accounting.  Previously TEST_FAIL()/ASSERT_MSG() only printed
 * "FAIL" and the process still exited 0, so a failing test was scored as a
 * pass by kyua/plain-test runners.  Now every failure is recorded here and an
 * atexit hook forces a non-zero exit status, making the harness sound.
 */
static int oes_test_failures;

static inline void
test_default_readers_initialize(void)
{
	size_t i;

	if (oes_test_default_readers_initialized)
		return;
	for (i = 0; i < OES_TEST_DEFAULT_READERS; i++)
		oes_test_default_readers[i].ter_fd = -1;
	oes_test_default_readers_initialized = true;
}

static inline void
test_forget_event_reader(int fd)
{
	size_t i;

	test_default_readers_initialize();
	for (i = 0; i < OES_TEST_DEFAULT_READERS; i++) {
		if (oes_test_default_readers[i].ter_fd != fd)
			continue;
		memset(&oes_test_default_readers[i], 0,
		    sizeof(oes_test_default_readers[i]));
		oes_test_default_readers[i].ter_fd = -1;
	}
}

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
	int fd;

	fd = open(OES_DEVICE_PATH, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd >= 0)
		test_forget_event_reader(fd);
	return (fd);
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

static inline void
test_event_reader_init(struct test_event_reader *reader)
{

	memset(reader, 0, sizeof(*reader));
	reader->ter_fd = -1;
}

static inline int
test_event_reader_take(struct test_event_reader *reader, oes_message_t *msg)
{
	const oes_message_t *src;
	size_t remaining;

	if (reader->ter_off == reader->ter_len)
		return (EAGAIN);
	if (reader->ter_off > reader->ter_len ||
	    reader->ter_len - reader->ter_off < sizeof(*src))
		goto corrupt;

	remaining = reader->ter_len - reader->ter_off;
	src = (const oes_message_t *)(const void *)
	    (reader->ter_batch.raw + reader->ter_off);
	if (src->em_size < sizeof(*src) || src->em_size > remaining ||
	    (src->em_size & (OES_MSG_ALIGN - 1)) != 0 ||
	    !oes_message_is_compatible(src))
		goto corrupt;

	memcpy(msg, src, src->em_size);
	reader->ter_off += src->em_size;
	if (reader->ter_off == reader->ter_len) {
		reader->ter_off = 0;
		reader->ter_len = 0;
	}
	return (0);

corrupt:
	reader->ter_off = 0;
	reader->ter_len = 0;
	errno = EPROTO;
	return (EPROTO);
}

/*
 * Return one event while retaining the rest of a batched read.  msg must
 * point to OES_MSG_MAX_SIZE bytes, normally a test_msg_buf.
 */
static inline int
test_event_reader_next(struct test_event_reader *reader, int fd,
    oes_message_t *msg, int timeout_ms)
{
	struct pollfd pfd;
	ssize_t n;
	int error, nready;

	if (reader == NULL || msg == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (reader->ter_len != 0 && reader->ter_fd != -1 &&
	    reader->ter_fd != fd) {
		errno = EBUSY;
		return (-1);
	}
	if (reader->ter_len != 0) {
		error = test_event_reader_take(reader, msg);
		return (error == 0 ? 0 : -1);
	}
	reader->ter_fd = fd;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	do {
		nready = poll(&pfd, 1, timeout_ms);
	} while (nready < 0 && errno == EINTR);
	if (nready <= 0) {
		if (nready == 0)
			errno = EAGAIN;
		return (-1);
	}
	if ((pfd.revents & (POLLIN | POLLHUP)) == 0) {
		errno = EAGAIN;
		return (-1);
	}

	n = read(fd, reader->ter_batch.raw, sizeof(reader->ter_batch.raw));
	if (n < (ssize_t)sizeof(*msg)) {
		if (n >= 0)
			errno = EPROTO;
		return (-1);
	}
	reader->ter_off = 0;
	reader->ter_len = (size_t)n;
	if (test_event_reader_take(reader, msg) != 0)
		return (-1);

	return (0);
}

static inline int
test_wait_event(int fd, oes_message_t *msg, int timeout_ms)
{
	struct test_event_reader *free_reader;
	size_t i;

	test_default_readers_initialize();

	free_reader = NULL;
	for (i = 0; i < OES_TEST_DEFAULT_READERS; i++) {
		if (oes_test_default_readers[i].ter_fd == fd)
			return (test_event_reader_next(&oes_test_default_readers[i],
			    fd, msg, timeout_ms));
		if (free_reader == NULL &&
		    oes_test_default_readers[i].ter_fd == -1)
			free_reader = &oes_test_default_readers[i];
	}
	if (free_reader == NULL) {
		errno = ENFILE;
		return (-1);
	}
	free_reader->ter_fd = fd;
	return (test_event_reader_next(free_reader, fd, msg, timeout_ms));
}

static inline int
test_wait_event_type(int fd, oes_message_t *msg, oes_event_type_t event,
    int timeout_ms)
{
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		struct timespec now;
		long elapsed_ms;
		int slice;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= timeout_ms)
			break;
		slice = timeout_ms - (int)elapsed_ms;

		if (slice > 100)
			slice = 100;
		if (test_wait_event(fd, msg, slice) == 0) {
			if (msg->em_event == event)
				return (0);
		}
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
	size_t i;

	for (i = 0; i < OES_TEST_DEFAULT_READERS; i++)
		test_event_reader_init(&oes_test_default_readers[i]);
	oes_test_default_readers_initialized = true;
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
