/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Pins of the identities OES gives pipes and credentials, which must hold
 * however the labels behind them are stored:
 *
 * I-1  a pipe's id is non-zero, the same in every event about that pipe
 *      (both ends, read and write, and across a subscription made after
 *      the pipe was created), and different for another pipe;
 * I-2  a process's exec id is non-zero, survives fork and a credential
 *      change (setuid to its own uid), and changes on exec, where the exec
 *      path changes too.
 */

#include <sys/param.h>

#include "test_idle_common.h"

/*
 * Collect up to n events of type ev, and up to n2 of type ev2 into out2,
 * from pid; returns how many of ev.
 */
static int
collect2(int fd, pid_t pid, oes_event_type_t ev, oes_message_t **out, int n,
    oes_event_type_t ev2, oes_message_t **out2, int n2, int *got2,
    int timeout_ms)
{
	struct timespec start;
	test_msg_buf buf;
	int got;

	got = 0;
	*got2 = 0;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while ((got < n || *got2 < n2) && idle_elapsed_ms(&start) < timeout_ms) {
		if (test_wait_event(fd, &buf.msg, 50) != 0)
			continue;
		if (buf.msg.em_process.ep_pid != pid)
			continue;
		if (buf.msg.em_event == ev && got < n) {
			out[got] = malloc(buf.msg.em_size);
			memcpy(out[got++], &buf.msg, buf.msg.em_size);
		} else if (buf.msg.em_event == ev2 && *got2 < n2) {
			out2[*got2] = malloc(buf.msg.em_size);
			memcpy(out2[(*got2)++], &buf.msg, buf.msg.em_size);
		}
	}
	return (got);
}

static int
collect(int fd, pid_t pid, oes_event_type_t ev, oes_message_t **out, int n,
    int timeout_ms)
{
	int none;

	return (collect2(fd, pid, ev, out, n, 0, NULL, 0, &none, timeout_ms));
}

static void
i1_pipe_ids(void)
{
	oes_event_type_t ev[] = { OES_EVENT_NOTIFY_PIPE_WRITE,
	    OES_EVENT_NOTIFY_PIPE_READ };
	oes_message_t *w[4], *r[4];
	int go[2], fd, nw, nr, i, status;
	pid_t pid;
	char c;

	TEST_BEGIN("I-1 pipe ids: non-zero, stable per pipe, distinct");
	if (pipe(go) != 0) {
		TEST_FAIL("pipe: %s", strerror(errno));
		return;
	}
	pid = fork();
	if (pid == 0) {
		int a[2], b[2];

		/* Both pipes exist before anybody subscribes. */
		if (pipe(a) != 0 || pipe(b) != 0)
			_exit(1);
		if (read(go[0], &c, 1) != 1)
			_exit(2);
		for (i = 0; i < 2; i++) {
			if (write(a[1], "a", 1) != 1 || read(a[0], &c, 1) != 1 ||
			    write(b[1], "b", 1) != 1 || read(b[0], &c, 1) != 1)
				_exit(3);
		}
		_exit(0);
	}
	fd = test_open_oes();
	if (fd < 0 || test_set_mode(fd, OES_MODE_NOTIFY) != 0 ||
	    test_subscribe(fd, ev, nitems(ev), OES_SUB_REPLACE) != 0) {
		TEST_FAIL("client: %s", strerror(errno));
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, &status, 0);
		return;
	}
	(void)write(go[1], "g", 1);
	ASSERT_MSG(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0, "child status %#x", status);
	nw = collect2(fd, pid, OES_EVENT_NOTIFY_PIPE_WRITE, w, 4,
	    OES_EVENT_NOTIFY_PIPE_READ, r, 4, &nr, 5000);
	ASSERT_MSG(nw == 4 && nr == 4, "%d write and %d read records", nw, nr);
	if (nw == 4 && nr == 4) {
		uint64_t a = w[0]->em_event_data.pipe.pipe_id;
		uint64_t b = w[1]->em_event_data.pipe.pipe_id;

		printf("    pipe ids %#jx %#jx\n", (uintmax_t)a, (uintmax_t)b);
		ASSERT_MSG(a != 0 && b != 0, "zero pipe id");
		ASSERT_MSG(a != b, "two pipes share id %#jx", (uintmax_t)a);
		/* Order per pipe: write a, read a, write b, read b, twice. */
		ASSERT_MSG(w[2]->em_event_data.pipe.pipe_id == a &&
		    w[3]->em_event_data.pipe.pipe_id == b &&
		    r[0]->em_event_data.pipe.pipe_id == a &&
		    r[1]->em_event_data.pipe.pipe_id == b &&
		    r[2]->em_event_data.pipe.pipe_id == a &&
		    r[3]->em_event_data.pipe.pipe_id == b,
		    "a pipe's id changed between events");
	}
	for (i = 0; i < nw; i++)
		free(w[i]);
	for (i = 0; i < nr; i++)
		free(r[i]);
	(void)close(fd);
	(void)close(go[0]);
	(void)close(go[1]);
}

static void
i2_exec_ids(const char *file)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_OPEN;
	oes_message_t *m[4];
	int go[2], fd, n, i, status;
	pid_t pid;
	char c;

	TEST_BEGIN("I-2 exec id: kept over fork and setuid, new on exec");
	if (pipe(go) != 0) {
		TEST_FAIL("pipe: %s", strerror(errno));
		return;
	}
	pid = fork();
	if (pid == 0) {
		int f;

		if (read(go[0], &c, 1) != 1)
			_exit(2);
		f = open(file, O_RDONLY);		/* record 0 */
		if (f >= 0)
			(void)close(f);
		if (setuid(getuid()) != 0)		/* a new credential */
			_exit(3);
		f = open(file, O_RDONLY);		/* record 1 */
		if (f >= 0)
			(void)close(f);
		if (fork() == 0) {			/* same exec, child */
			f = open(file, O_RDONLY);	/* record of another pid */
			_exit(0);
		}
		(void)wait(NULL);
		execl("/bin/cat", "cat", file, (char *)NULL);	/* record 2 */
		_exit(4);
	}
	fd = test_open_oes();
	if (fd < 0 || test_set_mode(fd, OES_MODE_NOTIFY) != 0 ||
	    test_subscribe(fd, &ev, 1, OES_SUB_REPLACE) != 0) {
		TEST_FAIL("client: %s", strerror(errno));
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, &status, 0);
		return;
	}
	(void)write(go[1], "g", 1);
	(void)waitpid(pid, &status, 0);
	/* cat opens libraries and the file: keep the last three of pid. */
	n = collect(fd, pid, ev, m, 4, 5000);
	ASSERT_MSG(n >= 3, "%d open records from the child", n);
	if (n >= 3) {
		uint64_t e0 = m[0]->em_process.ep_exec_id;
		uint64_t e1 = m[1]->em_process.ep_exec_id;
		uint64_t e2 = m[2]->em_process.ep_exec_id;

		printf("    exec ids %#jx %#jx %#jx\n", (uintmax_t)e0,
		    (uintmax_t)e1, (uintmax_t)e2);
		ASSERT_MSG(e0 != 0, "exec id 0 before exec");
		ASSERT_MSG(e1 == e0, "setuid changed the exec id");
		ASSERT_MSG(e2 != 0 && e2 != e0, "exec kept the exec id");
		ASSERT_MSG(strcmp(oes_msg_string(m[2],
		    m[2]->em_process.ep_path_off), "/bin/cat") == 0,
		    "exec path after exec: %s", oes_msg_string(m[2],
		    m[2]->em_process.ep_path_off));
	}
	for (i = 0; i < n; i++)
		free(m[i]);
	(void)close(fd);
	(void)close(go[0]);
	(void)close(go[1]);
}

int
main(void)
{
	char file[] = "./oes-identity.XXXXXX";
	int fd;

	TEST_SUITE_BEGIN("OES identity pins");
	fd = mkstemp(file);
	if (fd < 0) {
		TEST_FAIL("mkstemp: %s", strerror(errno));
		return (1);
	}
	(void)write(fd, "x\n", 2);
	(void)close(fd);
	i1_pipe_ids();
	i2_exec_ids(file);
	(void)unlink(file);
	TEST_SUITE_END("OES identity pins");
	return (0);
}
