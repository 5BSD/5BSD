/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Helpers shared by the OES idle tests (test_idle_pins, test_idle_gate):
 * a worker process that performs one file operation per command and
 * reports its errno, AUTH clients, and the malloc-type and sysctl readers.
 */
#ifndef _OES_TEST_IDLE_COMMON_H_
#define _OES_TEST_IDLE_COMMON_H_

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <memstat.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

/* Worker commands; the worker answers each with an int errno (0 = ok). */
#define	IW_OPEN		'o'	/* open(path, O_RDONLY) and close */
#define	IW_WRITE	'w'	/* open(path, O_WRONLY), write 1 byte, close */
#define	IW_QUIT		'q'

struct idle_worker {
	pid_t	iw_pid;
	int	iw_cmd;		/* parent writes commands */
	int	iw_res;		/* parent reads errnos */
};

static inline long
idle_elapsed_ms(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return ((now.tv_sec - start->tv_sec) * 1000L +
	    (now.tv_nsec - start->tv_nsec) / 1000000L);
}

static void
idle_worker_loop(int cmd, int res, const char *path)
{
	char c;
	int err, fd;

	for (;;) {
		if (read(cmd, &c, 1) != 1 || c == IW_QUIT)
			_exit(0);
		err = 0;
		switch (c) {
		case IW_OPEN:
			fd = open(path, O_RDONLY);
			if (fd < 0)
				err = errno;
			else
				(void)close(fd);
			break;
		case IW_WRITE:
			fd = open(path, O_WRONLY);
			if (fd < 0)
				err = errno;
			else {
				if (write(fd, "x", 1) != 1)
					err = errno;
				(void)close(fd);
			}
			break;
		default:
			err = EINVAL;
			break;
		}
		if (write(res, &err, sizeof(err)) != sizeof(err))
			_exit(1);
	}
}

/* Fork a worker that operates on path; it inherits the caller's scope. */
static inline int
idle_worker_start(struct idle_worker *w, const char *path)
{
	int cmd[2], res[2];

	if (pipe(cmd) != 0 || pipe(res) != 0)
		return (-1);
	w->iw_pid = fork();
	if (w->iw_pid < 0)
		return (-1);
	if (w->iw_pid == 0) {
		int lo, hi;

		/* Keep no copy of an OES descriptor: close must end a client. */
		lo = MIN(cmd[0], res[1]);
		hi = MAX(cmd[0], res[1]);
		if (lo > 3)
			(void)close_range(3, lo - 1, 0);
		if (hi > lo + 1)
			(void)close_range(lo + 1, hi - 1, 0);
		(void)close_range(hi + 1, ~0U, 0);
		idle_worker_loop(cmd[0], res[1], path);
	}
	(void)close(cmd[0]);
	(void)close(res[1]);
	w->iw_cmd = cmd[1];
	w->iw_res = res[0];
	return (0);
}

static inline int
idle_worker_send(struct idle_worker *w, char c)
{

	return (write(w->iw_cmd, &c, 1) == 1 ? 0 : -1);
}

/* The worker's errno for its last command; -1 if none within timeout_ms. */
static inline int
idle_worker_result(struct idle_worker *w, int timeout_ms)
{
	struct pollfd pfd;
	int err;

	pfd.fd = w->iw_res;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, timeout_ms) != 1 ||
	    read(w->iw_res, &err, sizeof(err)) != sizeof(err))
		return (-1);
	return (err);
}

static inline void
idle_worker_stop(struct idle_worker *w)
{
	int status;

	if (w->iw_pid <= 0)
		return;
	(void)idle_worker_send(w, IW_QUIT);
	(void)close(w->iw_cmd);
	(void)close(w->iw_res);
	(void)waitpid(w->iw_pid, &status, 0);
	w->iw_pid = -1;
}

static inline int
idle_respond(int fd, uint64_t id, oes_auth_result_t result)
{
	oes_response_t resp;

	memset(&resp, 0, sizeof(resp));
	resp.er_id = id;
	resp.er_result = result;
	return (write(fd, &resp, sizeof(resp)) == (ssize_t)sizeof(resp) ?
	    0 : -1);
}

/*
 * A client restricted to the caller and its later descendants, in mode
 * mode, subscribed to events.  Workers forked afterwards are in scope.
 */
static inline int
idle_scoped_client(uint32_t mode, uint32_t deadline_ms,
    oes_event_type_t *events, size_t nevents)
{
	struct oes_mode_args ma;
	int fd;

	fd = test_open_oes();
	if (fd < 0)
		return (-1);
	memset(&ma, 0, sizeof(ma));
	ma.ema_mode = mode;
	ma.ema_default_deadline_ms = deadline_ms;
	if (test_set_descendants_scope(fd) != 0 ||
	    ioctl(fd, OES_IOC_SET_MODE, &ma) != 0 ||
	    (nevents != 0 &&
	    test_subscribe(fd, events, nevents, OES_SUB_REPLACE) != 0)) {
		(void)close(fd);
		return (-1);
	}
	return (fd);
}

/*
 * AUTH deadline given to clients whose waiters a test expects to be
 * released by something else (a response, an unsubscribe, a close): a
 * waiter that returns before it was released by that, not by the deadline,
 * which the test tells apart by checking the time taken against it.
 */
#define	IDLE_AUTH_DEADLINE_MS	30000

/*
 * Wait for event ev from pid about the file with inode ino (0: any file).
 * AUTH events of other kinds or processes are allowed so they never stall.
 * timeout_ms is INFTIM for an event that must come (the test's timeout
 * ends the wait), or 0 to look only at what is already queued.
 */
static inline int
idle_wait_event(int fd, pid_t pid, oes_event_type_t ev, ino_t ino,
    int timeout_ms, oes_message_t *out)
{
	test_msg_buf buf;
	const oes_file_t *f;

	for (;;) {
		if (test_wait_event(fd, &buf.msg, timeout_ms) != 0)
			return (ETIMEDOUT);
		f = NULL;
		switch (buf.msg.em_event) {
		case OES_EVENT_AUTH_OPEN:
		case OES_EVENT_NOTIFY_OPEN:
			f = &buf.msg.em_event_data.open.file;
			break;
		default:
			break;
		}
		if (buf.msg.em_event == ev &&
		    (pid == 0 || buf.msg.em_process.ep_pid == pid) &&
		    (ino == 0 || (f != NULL && f->ef_token.eft_id == ino))) {
			if (out != NULL)
				memcpy(out, &buf.msg, buf.msg.em_size);
			return (0);
		}
		if (buf.msg.em_action == OES_ACTION_AUTH)
			(void)idle_respond(fd, buf.msg.em_id, OES_AUTH_ALLOW);
	}
}

/* Number of malloc(9) calls of type "oes" so far. */
static inline uint64_t
idle_oes_mallocs(void)
{
	struct memory_type_list *mtlp;
	struct memory_type *mtp;
	uint64_t n;

	mtlp = memstat_mtl_alloc();
	if (mtlp == NULL)
		return (0);
	if (memstat_sysctl_malloc(mtlp, 0) < 0) {
		memstat_mtl_free(mtlp);
		return (0);
	}
	mtp = memstat_mtl_find(mtlp, ALLOCATOR_MALLOC, "oes");
	n = mtp != NULL ? memstat_get_numallocs(mtp) : 0;
	memstat_mtl_free(mtlp);
	return (n);
}

static inline int
idle_sysctl_int(const char *name)
{
	size_t len;
	int v;

	len = sizeof(v);
	if (sysctlbyname(name, &v, &len, NULL, 0) != 0)
		return (-1);
	return (v);
}

/* count fork()+_exit() pairs, each child reaped before the next. */
static inline int
idle_fork_exit(int count)
{
	pid_t pid;
	int i, status;

	for (i = 0; i < count; i++) {
		pid = fork();
		if (pid < 0)
			return (-1);
		if (pid == 0)
			_exit(0);
		if (waitpid(pid, &status, 0) != pid)
			return (-1);
	}
	return (0);
}

#endif /* !_OES_TEST_IDLE_COMMON_H_ */
