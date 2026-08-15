/*
 * OES stress and concurrency tests.
 *
 * Tests many concurrent clients, rapid subscribe/unsubscribe, event floods.
 */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

#define NUM_CLIENTS	20
#define NUM_ITERATIONS	100

static int
test_many_clients(void)
{
	int fds[NUM_CLIENTS];
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };
	int i;

	printf("  Testing %d concurrent clients...\n", NUM_CLIENTS);

	/* Open many clients */
	for (i = 0; i < NUM_CLIENTS; i++) {
		fds[i] = open("/dev/oes", O_RDWR | O_NONBLOCK);
		if (fds[i] < 0) {
			perror("open /dev/oes");
			while (--i >= 0)
				close(fds[i]);
			return (1);
		}
	}

	/* Configure all as NOTIFY */
	for (i = 0; i < NUM_CLIENTS; i++) {
		memset(&mode, 0, sizeof(mode));
		mode.ema_mode = OES_MODE_NOTIFY;
		if (ioctl(fds[i], OES_IOC_SET_MODE, &mode) < 0) {
			perror("OES_IOC_SET_MODE");
			for (int j = 0; j < NUM_CLIENTS; j++)
				close(fds[j]);
			return (1);
		}
	}

	/* Subscribe all */
	for (i = 0; i < NUM_CLIENTS; i++) {
		memset(&sub, 0, sizeof(sub));
		sub.esa_events = events;
		sub.esa_count = 1;
		sub.esa_flags = OES_SUB_REPLACE;
		if (ioctl(fds[i], OES_IOC_SUBSCRIBE, &sub) < 0) {
			perror("OES_IOC_SUBSCRIBE");
			for (int j = 0; j < NUM_CLIENTS; j++)
				close(fds[j]);
			return (1);
		}
	}

	/* Close all */
	for (i = 0; i < NUM_CLIENTS; i++)
		close(fds[i]);

	printf("    PASS: %d concurrent clients handled\n", NUM_CLIENTS);
	return (0);
}

static int
test_rapid_subscribe_unsubscribe(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events1[] = { OES_EVENT_NOTIFY_EXEC };
	oes_event_type_t events2[] = { OES_EVENT_NOTIFY_FORK, OES_EVENT_NOTIFY_EXIT };
	int i;

	printf("  Testing rapid subscribe/unsubscribe (%d iterations)...\n",
	    NUM_ITERATIONS);

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	for (i = 0; i < NUM_ITERATIONS; i++) {
		/* Subscribe to events1 */
		memset(&sub, 0, sizeof(sub));
		sub.esa_events = events1;
		sub.esa_count = 1;
		sub.esa_flags = OES_SUB_REPLACE;
		if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
			perror("OES_IOC_SUBSCRIBE (1)");
			close(fd);
			return (1);
		}

		/* Subscribe to events2 (replace) */
		sub.esa_events = events2;
		sub.esa_count = 2;
		if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
			perror("OES_IOC_SUBSCRIBE (2)");
			close(fd);
			return (1);
		}

		/* Add events1 (using ADD flag) */
		sub.esa_events = events1;
		sub.esa_count = 1;
		sub.esa_flags = OES_SUB_ADD;
		if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
			perror("OES_IOC_SUBSCRIBE (add)");
			close(fd);
			return (1);
		}

		/* Clear subscriptions by replacing with empty (events2 only) */
		sub.esa_events = events2;
		sub.esa_count = 2;
		sub.esa_flags = OES_SUB_REPLACE;
		if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
			perror("OES_IOC_SUBSCRIBE (clear)");
			close(fd);
			return (1);
		}
	}

	close(fd);
	printf("    PASS: rapid subscribe/unsubscribe completed\n");
	return (0);
}

static int
test_rapid_mute_unmute(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };
	int i;

	printf("  Testing rapid mute/unmute (%d iterations)...\n", NUM_ITERATIONS);

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	for (i = 0; i < NUM_ITERATIONS; i++) {
		/* Self-mute */
		memset(&mute, 0, sizeof(mute));
		mute.emu_flags = OES_MUTE_SELF;
		if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) < 0) {
			perror("OES_IOC_MUTE_PROCESS");
			close(fd);
			return (1);
		}

		/* Self-unmute */
		if (ioctl(fd, OES_IOC_UNMUTE_PROCESS, &mute) < 0) {
			perror("OES_IOC_UNMUTE_PROCESS");
			close(fd);
			return (1);
		}
	}

	close(fd);
	printf("    PASS: rapid mute/unmute completed\n");
	return (0);
}

static void *
client_thread(void *arg)
{
	int *result = arg;
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };
	int i;

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		*result = 1;
		return (NULL);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		close(fd);
		*result = 1;
		return (NULL);
	}

	/* Rapidly subscribe/read */
	for (i = 0; i < 50; i++) {
		test_msg_buf _msg_buf;
		oes_message_t *msg = &_msg_buf.msg;

		memset(&sub, 0, sizeof(sub));
		sub.esa_events = events;
		sub.esa_count = 1;
		sub.esa_flags = OES_SUB_REPLACE;
		(void)ioctl(fd, OES_IOC_SUBSCRIBE, &sub);

		/* Try to read (non-blocking) */
		(void)read(fd, msg, OES_MSG_MAX_SIZE);

		usleep(1000); /* 1ms */
	}

	close(fd);
	*result = 0;
	return (NULL);
}

static int
test_concurrent_threads(void)
{
	pthread_t threads[10];
	int results[10];
	int i, failed = 0;

	printf("  Testing 10 concurrent threads...\n");

	for (i = 0; i < 10; i++) {
		results[i] = -1;
		if (pthread_create(&threads[i], NULL, client_thread, &results[i]) != 0) {
			perror("pthread_create");
			return (1);
		}
	}

	for (i = 0; i < 10; i++) {
		pthread_join(threads[i], NULL);
		if (results[i] != 0)
			failed++;
	}

	if (failed > 0) {
		fprintf(stderr, "FAIL: %d threads failed\n", failed);
		return (1);
	}

	printf("    PASS: concurrent threads completed\n");
	return (0);
}

static int
test_fork_stress(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_FORK, OES_EVENT_NOTIFY_EXIT };
	int i;
	pid_t pids[20];

	printf("  Testing rapid fork/exit (20 children)...\n");

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
	sub.esa_count = 2;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Fork many children rapidly */
	for (i = 0; i < 20; i++) {
		pids[i] = fork();
		if (pids[i] < 0) {
			perror("fork");
			continue;
		}
		if (pids[i] == 0) {
			_exit(0);
		}
	}

	/* Wait for all */
	for (i = 0; i < 20; i++) {
		if (pids[i] > 0)
			waitpid(pids[i], NULL, 0);
	}

	/* Drain events */
	for (i = 0; i < 100; i++) {
		test_msg_buf _msg_buf;
		oes_message_t *msg = &_msg_buf.msg;
		ssize_t n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			break;
	}

	close(fd);
	printf("    PASS: fork stress completed\n");
	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing stress conditions...\n");

	failed += test_many_clients();
	failed += test_rapid_subscribe_unsubscribe();
	failed += test_rapid_mute_unmute();
	failed += test_concurrent_threads();
	failed += test_fork_stress();

	if (failed > 0) {
		printf("stress: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("stress: ok\n");
	return (0);
}
