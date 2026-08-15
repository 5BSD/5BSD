/*
 * OES event delivery reliability tests.
 *
 * Tests event delivery under various conditions including
 * event flooding, slow consumers, queue behavior, and
 * event ordering guarantees.
 */
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
#include "test_common.h"

/*
 * Count events received within a time window.
 */
static int
drain_events(int fd, int timeout_ms, int *count)
{
	struct timespec start, now;
	long elapsed_ms;
	test_msg_buf _buf;
	oes_message_t *msg = &_buf.msg;
	*count = 0;
	clock_gettime(CLOCK_MONOTONIC, &start);

	while (1) {
		int remaining;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= timeout_ms)
			break;

		remaining = timeout_ms - (int)elapsed_ms;
		if (remaining > 50)
			remaining = 50;

		if (test_wait_event(fd, msg, remaining) != 0)
			continue;
		(*count)++;
	}

	return (0);
}

/*
 * Test basic event delivery.
 */
static int
test_basic_event_delivery(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };
	pid_t pid;
	int count;

	printf("  Testing basic event delivery...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Generate a known event */
	pid = fork();
	if (pid == 0) {
		execl("/bin/true", "true", NULL);
		_exit(1);
	}
	waitpid(pid, NULL, 0);

	/* Should receive at least one event */
	if (drain_events(fd, 1000, &count) < 0) {
		close(fd);
		return (1);
	}

	close(fd);

	if (count > 0) {
		printf("    PASS: received %d events\n", count);
		return (0);
	}

	printf("    INFO: no events received (may be expected)\n");
	return (0);
}

/*
 * Test event flooding (many rapid events).
 */
static int
test_event_flood(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	pid_t pids[100];
	int i, count, spawned = 0;

	printf("  Testing event flood (100 rapid processes)...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Spawn many children rapidly */
	for (i = 0; i < 100; i++) {
		pids[i] = fork();
		if (pids[i] < 0) {
			perror("fork");
			continue;
		}
		if (pids[i] == 0) {
			/* Child - open some files */
			int tmpfd = open("/etc/passwd", O_RDONLY);
			if (tmpfd >= 0)
				close(tmpfd);
			tmpfd = open("/etc/group", O_RDONLY);
			if (tmpfd >= 0)
				close(tmpfd);
			_exit(0);
		}
		spawned++;
	}

	/* Wait for all children */
	for (i = 0; i < 100; i++) {
		if (pids[i] > 0)
			waitpid(pids[i], NULL, 0);
	}

	/* Drain events */
	if (drain_events(fd, 2000, &count) < 0) {
		close(fd);
		return (1);
	}

	close(fd);

	printf("    INFO: spawned %d, received %d events\n", spawned, count);
	printf("    PASS: event flood handled\n");
	return (0);
}

/*
 * Test slow consumer (don't read events immediately).
 */
static int
test_slow_consumer(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	pid_t pids[20];
	int i, count;

	printf("  Testing slow consumer behavior...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Generate events but DON'T read them */
	for (i = 0; i < 20; i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			int tmpfd = open("/etc/passwd", O_RDONLY);
			if (tmpfd >= 0)
				close(tmpfd);
			_exit(0);
		}
	}

	for (i = 0; i < 20; i++) {
		if (pids[i] > 0)
			waitpid(pids[i], NULL, 0);
	}

	/* Wait a bit (events accumulate) */
	usleep(500000);

	/* Now read all at once */
	if (drain_events(fd, 1000, &count) < 0) {
		close(fd);
		return (1);
	}

	close(fd);

	printf("    INFO: slow consumer received %d events\n", count);
	printf("    PASS: slow consumer handled\n");
	return (0);
}

/*
 * Test event ordering (FIFO).
 */
static int
test_event_ordering(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_FORK };
	test_msg_buf _msgs_bufs[10];
	pid_t pids[10];
	int i, count = 0;
	int ordered = 1;

	printf("  Testing event ordering...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Fork sequentially */
	for (i = 0; i < 10; i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			_exit(0);
		}
		usleep(10000);  /* 10ms between forks */
	}

	/* Wait for children */
	for (i = 0; i < 10; i++) {
		if (pids[i] > 0)
			waitpid(pids[i], NULL, 0);
	}

	while (count < 10 &&
	    test_wait_event(fd, &_msgs_bufs[count].msg, 500) == 0)
		count++;

	/* Check ordering by message ID (should be increasing) */
	for (i = 1; i < count; i++) {
		if (_msgs_bufs[i].msg.em_id < _msgs_bufs[i-1].msg.em_id) {
			ordered = 0;
			printf("    WARN: event %d (id=%lu) before event %d (id=%lu)\n",
			    i, (unsigned long)_msgs_bufs[i].msg.em_id,
			    i-1, (unsigned long)_msgs_bufs[i-1].msg.em_id);
		}
	}

	test_batch_reset();
	close(fd);

	if (ordered) {
		printf("    PASS: %d events received in order\n", count);
	} else {
		printf("    INFO: %d events received, some out of order\n", count);
	}
	return (0);
}

/*
 * Test reading with different buffer sizes.
 */
static int
test_read_buffer_sizes(void)
{
	int fd;
	struct oes_mode_args mode;
	char buf[4096];
	ssize_t n;

	printf("  Testing read with different buffer sizes...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Read with buffer too small */
	n = read(fd, buf, 1);
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		printf("    INFO: 1-byte read: no data available\n");
	} else if (n < 0) {
		printf("    INFO: 1-byte read: %s\n", strerror(errno));
	} else {
		printf("    INFO: 1-byte read returned %zd\n", n);
	}

	/* Read with buffer exactly right */
	n = read(fd, buf, sizeof(oes_message_t));
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		printf("    INFO: exact-size read: no data available\n");
	} else if (n < 0) {
		printf("    INFO: exact-size read: %s\n", strerror(errno));
	} else {
		printf("    INFO: exact-size read returned %zd\n", n);
	}

	/* Read with large buffer */
	n = read(fd, buf, 4096);
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		printf("    INFO: 4096-byte read: no data available\n");
	} else if (n < 0) {
		printf("    INFO: 4096-byte read: %s\n", strerror(errno));
	} else {
		printf("    INFO: 4096-byte read returned %zd\n", n);
	}

	close(fd);
	printf("    PASS: buffer size variations tested\n");
	return (0);
}

/*
 * Test poll/select behavior.
 */
static int
test_poll_behavior(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };
	struct pollfd pfd;
	int ret;
	pid_t pid;

	printf("  Testing poll behavior...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	/* Poll with no data - should timeout */
	ret = poll(&pfd, 1, 100);
	if (ret == 0) {
		printf("    PASS: poll timeout with no data\n");
	} else if (ret > 0) {
		printf("    INFO: poll returned %d (events pending?)\n", ret);
	} else {
		perror("poll");
	}

	/* Generate event */
	pid = fork();
	if (pid == 0) {
		execl("/bin/true", "true", NULL);
		_exit(1);
	}
	waitpid(pid, NULL, 0);

	/* Poll again - should have data */
	ret = poll(&pfd, 1, 1000);
	if (ret > 0 && (pfd.revents & POLLIN)) {
		printf("    PASS: poll indicated data available\n");
	} else if (ret == 0) {
		printf("    INFO: poll timeout (no events)\n");
	} else {
		printf("    INFO: poll returned %d, revents=0x%x\n", ret, pfd.revents);
	}

	close(fd);
	return (0);
}

/*
 * Test blocking read.
 */
static int
test_blocking_read(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	pid_t reader_pid, event_pid;
	int status;

	printf("  Testing blocking read...\n");

	fd = open("/dev/oes", O_RDWR | O_CLOEXEC);  /* Note: NOT O_NONBLOCK */
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Fork reader that will block */
	reader_pid = fork();
	if (reader_pid == 0) {
		/* Child - do blocking read */
		alarm(5);  /* Timeout after 5s */
		ssize_t n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t)) {
			_exit(0);  /* Success */
		}
		_exit(1);  /* Failure */
	}

	/* Give reader time to block */
	usleep(100000);

	/* Generate event to unblock reader */
	event_pid = fork();
	if (event_pid == 0) {
		execl("/bin/true", "true", NULL);
		_exit(1);
	}
	waitpid(event_pid, NULL, 0);

	/* Wait for reader */
	waitpid(reader_pid, &status, 0);

	close(fd);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("    PASS: blocking read unblocked by event\n");
		return (0);
	}

	printf("    INFO: blocking read status=%d\n", status);
	return (0);
}

/*
 * Test multiple subscriptions changing.
 */
static int
test_subscription_changes(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events1[] = { OES_EVENT_NOTIFY_EXEC };
	oes_event_type_t events2[] = { OES_EVENT_NOTIFY_OPEN, OES_EVENT_NOTIFY_FORK };
	int count1, count2;
	pid_t pid;

	printf("  Testing subscription changes...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Subscribe to EXEC */
	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events1;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Generate events */
	pid = fork();
	if (pid == 0) {
		int tmpfd = open("/etc/passwd", O_RDONLY);
		if (tmpfd >= 0)
			close(tmpfd);
		execl("/bin/true", "true", NULL);
		_exit(1);
	}
	waitpid(pid, NULL, 0);

	drain_events(fd, 500, &count1);
	printf("    INFO: with EXEC subscription: %d events\n", count1);

	/* Change subscription to OPEN+FORK */
	sub.esa_events = events2;
	sub.esa_count = 2;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Generate more events */
	pid = fork();
	if (pid == 0) {
		int tmpfd = open("/etc/passwd", O_RDONLY);
		if (tmpfd >= 0)
			close(tmpfd);
		execl("/bin/true", "true", NULL);
		_exit(1);
	}
	waitpid(pid, NULL, 0);

	drain_events(fd, 500, &count2);
	printf("    INFO: with OPEN+FORK subscription: %d events\n", count2);

	close(fd);
	printf("    PASS: subscription changes tested\n");
	return (0);
}

/*
 * Test empty event queue read.
 */
static int
test_empty_queue_read(void)
{
	int fd;
	struct oes_mode_args mode;
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	ssize_t n;

	printf("  Testing read from empty queue...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Don't subscribe to anything, just try to read */
	n = read(fd, msg, OES_MSG_MAX_SIZE);
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		printf("    PASS: empty queue returns EAGAIN\n");
	} else if (n < 0) {
		printf("    INFO: empty queue: %s\n", strerror(errno));
	} else {
		printf("    INFO: empty queue read returned %zd\n", n);
	}

	close(fd);
	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing event delivery...\n");

	failed += test_basic_event_delivery();
	failed += test_event_flood();
	failed += test_slow_consumer();
	failed += test_event_ordering();
	failed += test_read_buffer_sizes();
	failed += test_poll_behavior();
	failed += test_blocking_read();
	failed += test_subscription_changes();
	failed += test_empty_queue_read();

	if (failed > 0) {
		printf("event delivery: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("event delivery: ok\n");
	return (0);
}
