/*
 * OES decision cache test.
 */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

static int
respond_allow(int fd, uint64_t msg_id)
{
	oes_response_t resp;

	memset(&resp, 0, sizeof(resp));
	resp.er_id = msg_id;
	resp.er_result = OES_AUTH_ALLOW;
	if (write(fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp))
		return (-1);
	return (0);
}

static int
wait_for_open_event(int fd, pid_t pid, int timeout_ms, oes_message_t *out)
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
			if (msg->em_action == OES_ACTION_AUTH &&
			    msg->em_event == OES_EVENT_AUTH_OPEN &&
			    msg->em_process.ep_pid == pid) {
				if (out != NULL)
					*out = *msg;
				return (0);
			}
			if (msg->em_action == OES_ACTION_AUTH)
				(void)respond_allow(fd, msg->em_id);
		}
	}

	return (ETIMEDOUT);
}

static int
wait_for_no_open_event(int fd, pid_t pid, int timeout_ms)
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
			if (msg->em_action == OES_ACTION_AUTH &&
			    msg->em_event == OES_EVENT_AUTH_OPEN &&
			    msg->em_process.ep_pid == pid) {
				(void)respond_allow(fd, msg->em_id);
				return (1);
			}
			if (msg->em_action == OES_ACTION_AUTH)
				(void)respond_allow(fd, msg->em_id);
		}
	}

	return (0);
}

static int
wait_for_child_errno(int fd, int timeout_ms, int *out_errno)
{
	struct pollfd pfd;
	struct timespec start;

	pfd.fd = fd;
	pfd.events = POLLIN;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		struct timespec now;
		long elapsed_ms;
		int err;
		ssize_t n;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= timeout_ms)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			n = read(fd, &err, sizeof(err));
			if (n == (ssize_t)sizeof(err)) {
				if (out_errno != NULL)
					*out_errno = err;
				return (0);
			}
		}
	}

	return (ETIMEDOUT);
}

static void
sleep_ms(int ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000L;
	(void)nanosleep(&ts, NULL);
}

int
main(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = {
		OES_EVENT_AUTH_OPEN,
	};
	int ctl_pipe[2];
	int res_pipe[2];
	pid_t child;
	int status;
	int child_err;
	char cmd;
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_cache_entry_t entry;
	oes_cache_key_t key;
	struct oes_stats stats;

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_timeout_ms = 500;
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

	if (pipe(ctl_pipe) != 0 || pipe(res_pipe) != 0) {
		perror("pipe");
		close(fd);
		return (1);
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (child == 0) {
		int child_fd;
		int err = 0;

		close(fd);
		close(ctl_pipe[1]);
		close(res_pipe[0]);
		for (;;) {
			if (read(ctl_pipe[0], &cmd, 1) != 1)
				break;
			if (cmd == 'q')
				break;
			if (cmd == 'o') {
				child_fd = open("/etc/hosts", O_RDONLY);
				if (child_fd < 0)
					err = errno;
				else {
					close(child_fd);
					err = 0;
				}
				(void)write(res_pipe[1], &err, sizeof(err));
			}
		}
		close(ctl_pipe[0]);
		close(res_pipe[1]);
		_exit(0);
	}

	close(ctl_pipe[0]);
	close(res_pipe[1]);

	/* Prime cache key from a real AUTH_OPEN event. */
	cmd = 'o';
	(void)write(ctl_pipe[1], &cmd, 1);
	if (wait_for_open_event(fd, child, 2000, msg) != 0) {
		fprintf(stderr, "expected AUTH_OPEN event\n");
		goto fail;
	}
	if (respond_allow(fd, msg->em_id) != 0) {
		perror("respond allow");
		goto fail;
	}
	if (wait_for_child_errno(res_pipe[0], 2000, &child_err) != 0 ||
	    child_err != 0) {
		fprintf(stderr, "child open failed unexpectedly\n");
		goto fail;
	}

	memset(&entry, 0, sizeof(entry));
	entry.ece_key.eck_event = OES_EVENT_AUTH_OPEN;
	entry.ece_key.eck_flags = OES_CACHE_KEY_PROCESS | OES_CACHE_KEY_FILE;
	entry.ece_key.eck_op_flags = (uint32_t)msg->em_event_data.open.flags;
	entry.ece_key.eck_process = msg->em_process.ep_token;
	entry.ece_key.eck_file = msg->em_event_data.open.file.ef_token;
	entry.ece_result = OES_AUTH_ALLOW;
	entry.ece_ttl_ms = 300;
	if (ioctl(fd, OES_IOC_CACHE_ADD, &entry) < 0) {
		perror("OES_IOC_CACHE_ADD allow");
		goto fail;
	}

	cmd = 'o';
	(void)write(ctl_pipe[1], &cmd, 1);
	if (wait_for_child_errno(res_pipe[0], 2000, &child_err) != 0 ||
	    child_err != 0) {
		fprintf(stderr, "cached allow did not permit open\n");
		goto fail;
	}
	if (wait_for_no_open_event(fd, child, 300) != 0) {
		fprintf(stderr, "cache hit still delivered event\n");
		goto fail;
	}

	memset(&stats, 0, sizeof(stats));
	if (ioctl(fd, OES_IOC_GET_STATS, &stats) < 0) {
		perror("OES_IOC_GET_STATS");
		goto fail;
	}
	if (stats.es_cache_hits < 1 || stats.es_cache_entries < 1) {
		fprintf(stderr,
		    "cache stats not updated (hits=%" PRIu64 " entries=%u)\n",
		    stats.es_cache_hits, stats.es_cache_entries);
		goto fail;
	}

	sleep_ms(400);

	cmd = 'o';
	(void)write(ctl_pipe[1], &cmd, 1);
	if (wait_for_open_event(fd, child, 2000, msg) != 0) {
		fprintf(stderr, "expected AUTH_OPEN after cache expiry\n");
		goto fail;
	}
	if (respond_allow(fd, msg->em_id) != 0) {
		perror("respond allow (post-expiry)");
		goto fail;
	}
	if (wait_for_child_errno(res_pipe[0], 2000, &child_err) != 0 ||
	    child_err != 0) {
		fprintf(stderr, "child open failed after cache expiry\n");
		goto fail;
	}

	memset(&entry, 0, sizeof(entry));
	entry.ece_key.eck_event = OES_EVENT_AUTH_OPEN;
	entry.ece_key.eck_flags = OES_CACHE_KEY_PROCESS | OES_CACHE_KEY_FILE;
	entry.ece_key.eck_op_flags = (uint32_t)msg->em_event_data.open.flags;
	entry.ece_key.eck_process = msg->em_process.ep_token;
	entry.ece_key.eck_file = msg->em_event_data.open.file.ef_token;
	entry.ece_result = OES_AUTH_DENY;
	entry.ece_ttl_ms = 500;
	if (ioctl(fd, OES_IOC_CACHE_ADD, &entry) < 0) {
		perror("OES_IOC_CACHE_ADD deny");
		goto fail;
	}

	cmd = 'o';
	(void)write(ctl_pipe[1], &cmd, 1);
	if (wait_for_child_errno(res_pipe[0], 2000, &child_err) != 0 ||
	    (child_err != EACCES && child_err != EPERM)) {
		fprintf(stderr, "cached deny did not block open\n");
		goto fail;
	}
	if (wait_for_no_open_event(fd, child, 300) != 0) {
		fprintf(stderr, "cache deny still delivered event\n");
		goto fail;
	}

	key = entry.ece_key;
	if (ioctl(fd, OES_IOC_CACHE_REMOVE, &key) < 0) {
		perror("OES_IOC_CACHE_REMOVE");
		goto fail;
	}

	cmd = 'o';
	(void)write(ctl_pipe[1], &cmd, 1);
	if (wait_for_open_event(fd, child, 2000, msg) != 0) {
		fprintf(stderr, "expected AUTH_OPEN after cache remove\n");
		goto fail;
	}
	if (respond_allow(fd, msg->em_id) != 0) {
		perror("respond allow (post-remove)");
		goto fail;
	}
	if (wait_for_child_errno(res_pipe[0], 2000, &child_err) != 0 ||
	    child_err != 0) {
		fprintf(stderr, "child open failed after cache remove\n");
		goto fail;
	}

	if (ioctl(fd, OES_IOC_CACHE_CLEAR) < 0) {
		perror("OES_IOC_CACHE_CLEAR");
		goto fail;
	}

	cmd = 'q';
	(void)write(ctl_pipe[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(ctl_pipe[1]);
	close(res_pipe[0]);
	close(fd);
	return (0);

fail:
	cmd = 'q';
	(void)write(ctl_pipe[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(ctl_pipe[1]);
	close(res_pipe[0]);
	close(fd);
	return (1);
}
