/*
 * OES path/target path muting smoke test.
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

static int
respond_allow(int fd, const oes_message_t *msg)
{
	oes_response_t resp;

	if (msg->em_action != OES_ACTION_AUTH)
		return (0);

	memset(&resp, 0, sizeof(resp));
	resp.er_id = msg->em_id;
	resp.er_result = OES_AUTH_ALLOW;
	return (write(fd, &resp, sizeof(resp)) == sizeof(resp) ? 0 : -1);
}

static int
wait_for_exec(int fd, pid_t pid, const char *path, int timeout_ms,
    int expect_event)
{
	struct pollfd pfd;
	struct timespec start;

	pfd.fd = fd;
	pfd.events = POLLIN;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		struct timespec now;
		long elapsed_ms;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= timeout_ms)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			test_msg_buf _buf;
			oes_message_t *msg = &_buf.msg;
			ssize_t n = read(fd, msg, OES_MSG_MAX_SIZE);
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				perror("read");
				return (-1);
			}
			if (n < (ssize_t)sizeof(oes_message_t))
				continue;

			(void)respond_allow(fd, msg);

			if (msg->em_event != OES_EVENT_AUTH_EXEC ||
			    msg->em_process.ep_pid != pid)
				continue;

			fprintf(stderr, "exec event: got path '%s', want '%s'\n",
			    oes_msg_string(msg, msg->em_event_data.exec.executable.ef_path_off),
			    path ? path : "(null)");

			if (path != NULL &&
			    strcmp(oes_msg_string(msg, msg->em_event_data.exec.executable.ef_path_off), path) != 0)
				return (-1);

			return (expect_event ? 0 : 1);
		}
	}

	return (expect_event ? ETIMEDOUT : 0);
}

static int
wait_for_link(int fd, pid_t pid, const char *name, int timeout_ms,
    int expect_event)
{
	struct pollfd pfd;
	struct timespec start;

	pfd.fd = fd;
	pfd.events = POLLIN;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		struct timespec now;
		long elapsed_ms;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= timeout_ms)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			test_msg_buf _buf;
			oes_message_t *msg = &_buf.msg;
			ssize_t n = read(fd, msg, OES_MSG_MAX_SIZE);
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				perror("read");
				return (-1);
			}
			if (n < (ssize_t)sizeof(oes_message_t))
				continue;

			(void)respond_allow(fd, msg);

			if (msg->em_event != OES_EVENT_AUTH_LINK ||
			    msg->em_process.ep_pid != pid)
				continue;

			if (name != NULL &&
			    strcmp(oes_msg_string(msg, msg->em_event_data.link.name_off), name) != 0)
				return (-1);

			return (expect_event ? 0 : 1);
		}
	}

	return (expect_event ? ETIMEDOUT : 0);
}

static int
spawn_exec(const char *path)
{
	pid_t pid = fork();
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		execl(path, path, NULL);
		_exit(127);
	}
	return (pid);
}

static int
spawn_link(const char *src, const char *dst)
{
	pid_t pid = fork();
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		if (link(src, dst) != 0)
			_exit(1);
		_exit(0);
	}
	return (pid);
}

int
main(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = {
		OES_EVENT_AUTH_EXEC,
		OES_EVENT_AUTH_LINK,
	};
	struct oes_mute_path_args mpath;
	pid_t pid;
	int status;
	int rc;
	char srcpath[] = "/tmp/oes-pathmute.XXXXXX";
	char linkok[] = "/tmp/oes-link-ok";
	char linkmuted[] = "/tmp/oes-link-muted";
	int srcfd;

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
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

	memset(&mpath, 0, sizeof(mpath));
	strlcpy(mpath.emp_path, "/bin/echo", sizeof(mpath.emp_path));
	mpath.emp_type = OES_MUTE_PATH_LITERAL;
	if (ioctl(fd, OES_IOC_MUTE_PATH, &mpath) < 0) {
		perror("OES_IOC_MUTE_PATH");
		close(fd);
		return (1);
	}

	pid = spawn_exec("/bin/echo");
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}
	rc = wait_for_exec(fd, pid, "/bin/echo", 1000, 0);
	(void)waitpid(pid, &status, 0);
	if (rc != 0) {
		fprintf(stderr, "path mute failed (echo)\n");
		close(fd);
		return (1);
	}

	pid = spawn_exec("/usr/bin/true");
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}
	rc = wait_for_exec(fd, pid, "/usr/bin/true", 2000, 1);
	(void)waitpid(pid, &status, 0);
	if (rc != 0) {
		fprintf(stderr, "path mute failed (true)\n");
		close(fd);
		return (1);
	}

	if (ioctl(fd, OES_IOC_SET_MUTE_INVERT,
	    &(struct oes_mute_invert_args){
		.emi_type = OES_MUTE_INVERT_PATH,
		.emi_invert = 1,
	    }) < 0) {
		perror("OES_IOC_SET_MUTE_INVERT");
		close(fd);
		return (1);
	}

	pid = spawn_exec("/bin/echo");
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}
	rc = wait_for_exec(fd, pid, "/bin/echo", 2000, 1);
	(void)waitpid(pid, &status, 0);
	if (rc != 0) {
		fprintf(stderr, "path invert failed (echo)\n");
		close(fd);
		return (1);
	}

	pid = spawn_exec("/usr/bin/true");
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}
	rc = wait_for_exec(fd, pid, "/usr/bin/true", 1000, 0);
	(void)waitpid(pid, &status, 0);
	if (rc != 0) {
		fprintf(stderr, "path invert failed (true)\n");
		close(fd);
		return (1);
	}

	if (ioctl(fd, OES_IOC_SET_MUTE_INVERT,
	    &(struct oes_mute_invert_args){
		.emi_type = OES_MUTE_INVERT_PATH,
		.emi_invert = 0,
	    }) < 0) {
		perror("OES_IOC_SET_MUTE_INVERT");
		close(fd);
		return (1);
	}

	srcfd = mkstemp(srcpath);
	if (srcfd < 0) {
		perror("mkstemp");
		close(fd);
		return (1);
	}
	close(srcfd);
	unlink(linkok);
	unlink(linkmuted);

	pid = spawn_link(srcpath, linkok);
	if (pid < 0) {
		perror("fork");
		close(fd);
		unlink(srcpath);
		return (1);
	}
	rc = wait_for_link(fd, pid, "oes-link-ok", 2000, 1);
	(void)waitpid(pid, &status, 0);
	if (rc != 0) {
		fprintf(stderr, "link event missing\n");
		close(fd);
		unlink(srcpath);
		unlink(linkok);
		return (1);
	}
	unlink(linkok);

	memset(&mpath, 0, sizeof(mpath));
	strlcpy(mpath.emp_path, "oes-link-muted", sizeof(mpath.emp_path));
	mpath.emp_type = OES_MUTE_PATH_LITERAL;
	mpath.emp_flags = OES_MUTE_PATH_FLAG_TARGET;
	if (ioctl(fd, OES_IOC_MUTE_PATH, &mpath) < 0) {
		perror("OES_IOC_MUTE_PATH (target)");
		close(fd);
		unlink(srcpath);
		return (1);
	}

	pid = spawn_link(srcpath, linkmuted);
	if (pid < 0) {
		perror("fork");
		close(fd);
		unlink(srcpath);
		return (1);
	}
	rc = wait_for_link(fd, pid, "oes-link-muted", 1000, 0);
	(void)waitpid(pid, &status, 0);
	if (rc != 0) {
		fprintf(stderr, "target path mute failed\n");
		close(fd);
		unlink(srcpath);
		unlink(linkmuted);
		return (1);
	}
	unlink(linkmuted);

	unlink(srcpath);
	close(fd);
	printf("path muting: ok\n");
	return (0);
}
