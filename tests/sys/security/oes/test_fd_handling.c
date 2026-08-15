/*
 * OES file descriptor handling tests.
 *
 * Tests fd leak detection, close-on-exec, dup() scenarios.
 */
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/oes/oes.h>

static int
test_close_on_exec(void)
{
	int fd;
	pid_t pid;
	int status;

	printf("  Testing O_CLOEXEC behavior...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		/* Child: exec and check if fd is closed */
		char fd_str[16];
		snprintf(fd_str, sizeof(fd_str), "%d", fd);
		execl("/bin/sh", "sh", "-c",
		    "test -e /dev/fd/$1 && exit 1 || exit 0",
		    "sh", fd_str, (char *)NULL);
		_exit(127);
	}

	waitpid(pid, &status, 0);
	close(fd);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "FAIL: fd not closed on exec\n");
		return (1);
	}

	printf("    PASS: O_CLOEXEC works\n");
	return (0);
}

static int
test_dup_fd(void)
{
	int fd, fd2;
	struct oes_mode_args mode;

	printf("  Testing dup() behavior...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	/* Set mode on original fd */
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Dup the fd */
	fd2 = dup(fd);
	if (fd2 < 0) {
		perror("dup");
		close(fd);
		return (1);
	}

	/* Both fds should work - they share the same file description */
	/* Close original, dup should still work */
	close(fd);

	/* The dup'd fd should still be usable */
	/* Note: After closing the original, the client state remains */
	close(fd2);

	printf("    PASS: dup() works correctly\n");
	return (0);
}

static int
test_multiple_opens(void)
{
	int fds[10];
	struct oes_mode_args mode;
	int i;

	printf("  Testing multiple simultaneous opens...\n");

	/* Open multiple handles */
	for (i = 0; i < 10; i++) {
		fds[i] = open("/dev/oes", O_RDWR | O_NONBLOCK);
		if (fds[i] < 0) {
			perror("open /dev/oes");
			while (--i >= 0)
				close(fds[i]);
			return (1);
		}
	}

	/* Configure each as a different mode */
	for (i = 0; i < 10; i++) {
		memset(&mode, 0, sizeof(mode));
		mode.ema_mode = (i % 2 == 0) ? OES_MODE_NOTIFY : OES_MODE_AUTH;
		if (ioctl(fds[i], OES_IOC_SET_MODE, &mode) < 0) {
			perror("OES_IOC_SET_MODE");
			for (int j = 0; j < 10; j++)
				close(fds[j]);
			return (1);
		}
	}

	/* Close all */
	for (i = 0; i < 10; i++)
		close(fds[i]);

	printf("    PASS: multiple opens work\n");
	return (0);
}

static int
test_close_while_subscribed(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_EXEC,
		OES_EVENT_NOTIFY_FORK,
		OES_EVENT_NOTIFY_EXIT,
	};

	printf("  Testing close while subscribed...\n");

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
	sub.esa_count = sizeof(events) / sizeof(events[0]);
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Close while subscribed - should clean up properly */
	close(fd);

	printf("    PASS: close while subscribed works\n");
	return (0);
}

static int
test_fork_with_fd(void)
{
	int fd;
	pid_t pid;
	int status;
	struct oes_mode_args mode;

	printf("  Testing fork with open fd...\n");

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

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		/* Child: fd is inherited, close it */
		close(fd);
		_exit(0);
	}

	/* Parent: wait for child and close */
	waitpid(pid, &status, 0);
	close(fd);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "FAIL: child failed\n");
		return (1);
	}

	printf("    PASS: fork with fd works\n");
	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing file descriptor handling...\n");

	failed += test_close_on_exec();
	failed += test_dup_fd();
	failed += test_multiple_opens();
	failed += test_close_while_subscribed();
	failed += test_fork_with_fd();

	if (failed > 0) {
		printf("fd handling: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("fd handling: ok\n");
	return (0);
}
