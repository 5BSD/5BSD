/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable-guest signal capture identity and recycling regression. */
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>
#include "test_common.h"

#define ROUNDS 128
static pthread_barrier_t start;
struct worker { pid_t target; int signum, ack, failed; };

static void *
signal_worker(void *arg)
{
	struct worker *w = arg;
	char ack;
	int rc = pthread_barrier_wait(&start);

	if (rc != 0 && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
		w->failed = 1;
		return (NULL);
	}
	for (int i = 0; i < ROUNDS; i++) {
		if (kill(w->target, w->signum) != 0 || read(w->ack, &ack, 1) != 1 ||
		    ack != 'a') {
			w->failed = 1;
			break;
		}
	}
	return (NULL);
}

int
main(void)
{
	struct oes_mode_args mode = { .ema_mode = OES_MODE_NOTIFY };
	oes_event_type_t event = OES_EVENT_NOTIFY_SIGNAL;
	struct oes_subscribe_args sub = {
		.esa_events = &event, .esa_count = 1, .esa_flags = OES_SUB_REPLACE
	};
	struct sigaction ignore = { .sa_handler = SIG_IGN }, old[2], old_pipe;
	struct worker workers[2];
	struct test_event_reader reader;
	struct timespec begin, now;
	test_msg_buf buf;
	uint64_t tids[2] = {0, 0}, ids[2 * ROUNDS];
	unsigned seen[2] = {0, 0}, count = 0;
	int pipes[2][2] = {{-1, -1}, {-1, -1}}, signals[2] = {SIGUSR1, SIGUSR2};
	int fd = -1, status = 0, failed = 1, done = 0, installed = 0;
	int pipe_ignored = 0;
	pid_t child = -1, target = getpid();
	const char *guard = getenv("LINUXULATOR_DISPOSABLE");

	if (guard == NULL || strcmp(guard, "yes") != 0)
		return (125);
	sigemptyset(&ignore.sa_mask);
	if (sigaction(SIGPIPE, &ignore, &old_pipe) != 0)
		goto out;
	pipe_ignored = 1;
	for (int i = 0; i < 2; i++) {
		if (sigaction(signals[i], &ignore, &old[i]) != 0)
			goto out;
		installed++;
		if (pipe(pipes[i]) != 0)
			goto out;
		workers[i] = (struct worker){ target, signals[i], pipes[i][0], 0 };
	}
	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0 || ioctl(fd, OES_IOC_SET_MODE, &mode) != 0 ||
	    ioctl(fd, OES_IOC_SUBSCRIBE, &sub) != 0 ||
	    clock_gettime(CLOCK_MONOTONIC, &begin) != 0)
		goto out;
	child = fork();
	if (child < 0)
		goto out;
	if (child == 0) {
		pthread_t threads[2];
		close(fd);
		for (int i = 0; i < 2; i++)
			close(pipes[i][1]);
		if (pthread_barrier_init(&start, NULL, 2) != 0)
			_exit(2);
		for (int i = 0; i < 2; i++)
			if (pthread_create(&threads[i], NULL, signal_worker,
			    &workers[i]) != 0)
				_exit(2);
		for (int i = 0; i < 2; i++)
			if (pthread_join(threads[i], NULL) != 0)
				_exit(3);
		_exit(workers[0].failed || workers[1].failed ||
		    pthread_barrier_destroy(&start) != 0);
	}
	for (int i = 0; i < 2; i++) {
		close(pipes[i][0]);
		pipes[i][0] = -1;
	}
	test_event_reader_init(&reader);
	failed = 0;
	while ((!done || count < 2 * ROUNDS) && !failed) {
		oes_message_t *msg = &buf.msg;
		int rc = test_event_reader_next(&reader, fd, msg, 100);
		if (rc == 0) {
			int worker = msg->em_event_data.signal.signum == SIGUSR1 ? 0 : 1;
			if (msg->em_event != event || msg->em_process.ep_pid != child ||
			    msg->em_event_data.signal.target.ep_pid != target ||
			    msg->em_event_data.signal.signum != signals[worker] ||
			    (msg->em_thread.et_flags & OES_THREAD_META_PRESENT) == 0 ||
			    msg->em_thread.et_id == 0 || seen[worker] >= ROUNDS ||
			    (tids[worker] != 0 && tids[worker] != msg->em_thread.et_id) ||
			    tids[1 - worker] == msg->em_thread.et_id || msg->em_id == 0)
				failed = 1;
			for (unsigned i = 0; i < count; i++)
				if (ids[i] == msg->em_id)
					failed = 1;
			if (!failed) {
				tids[worker] = msg->em_thread.et_id;
				ids[count++] = msg->em_id;
				seen[worker]++;
				if (write(pipes[worker][1], "a", 1) != 1)
					failed = 1;
			}
		} else if (errno != EAGAIN)
			failed = 1;
		if (!done) {
			pid_t waited = waitpid(child, &status, WNOHANG);
			if (waited == child)
				done = 1;
			else if (waited < 0)
				failed = 1;
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
		    now.tv_sec - begin.tv_sec >= 60)
			failed = 1;
	}
	if (!done || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
	    seen[0] != ROUNDS || seen[1] != ROUNDS)
		failed = 1;
	printf("OES_SIGNAL_CONCURRENT first=%u second=%u expected=%d failed=%d\n",
	    seen[0], seen[1], ROUNDS, failed);
out:
	if (child > 0 && !done) {
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
	}
	if (fd >= 0)
		close(fd);
	for (int i = 0; i < 2; i++) {
		for (int j = 0; j < 2; j++)
			if (pipes[i][j] >= 0)
				close(pipes[i][j]);
		if (i < installed && sigaction(signals[i], &old[i], NULL) != 0)
			failed = 1;
	}
	if (pipe_ignored && sigaction(SIGPIPE, &old_pipe, NULL) != 0)
		failed = 1;
	return (failed);
}
