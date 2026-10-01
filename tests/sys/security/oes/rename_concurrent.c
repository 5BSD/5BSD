/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable-guest regression for per-thread rename authorization metadata. */
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include "test_common.h"

#define ROUNDS 100
static pthread_barrier_t start;

struct worker {
	char left[32], right[32];
	int failed;
};

static void *
rename_worker(void *arg)
{
	struct worker *w = arg;
	int rc = pthread_barrier_wait(&start);

	if (rc != 0 && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
		w->failed = 1;
		return (NULL);
	}

	for (int i = 0; i < ROUNDS; i++) {
		if (rename(w->left, w->right) != 0 ||
		    rename(w->right, w->left) != 0) {
			w->failed = 1;
			break;
		}
	}
	return (NULL);
}

int
main(void)
{
	struct worker workers[2] = {
		{ .left = "worker0-left", .right = "worker0-right" },
		{ .left = "worker1-left", .right = "worker1-right" }
	};
	struct oes_mode_args mode = { .ema_mode = OES_MODE_AUTH };
	oes_event_type_t event = OES_EVENT_AUTH_RENAME;
	struct oes_subscribe_args sub = {
		.esa_events = &event, .esa_count = 1, .esa_flags = OES_SUB_REPLACE
	};
	struct test_event_reader reader;
	struct stat original[2], final;
	struct timespec begin, now;
	test_msg_buf buf;
	char dir[] = "oes-concurrent.XXXXXX";
	const char *guard = getenv("LINUXULATOR_DISPOSABLE");
	unsigned seen[2] = {0, 0};
	uint64_t tids[2] = {0, 0};
	int fd = -1, file, status = 0, failed = 1, done = 0;
	pid_t child = -1;

	if (guard == NULL || strcmp(guard, "yes") != 0)
		return (125);
	if (mkdtemp(dir) == NULL)
		return (1);
	if (chdir(dir) != 0) {
		rmdir(dir);
		return (1);
	}
	for (int i = 0; i < 2; i++) {
		file = open(workers[i].left, O_CREAT | O_EXCL | O_RDWR, 0600);
		if (file < 0)
			goto out;
		int rc = fstat(file, &original[i]);
		close(file);
		if (rc != 0)
			goto out;
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
		if (pthread_barrier_init(&start, NULL, 2) != 0)
			_exit(2);
		for (int i = 0; i < 2; i++)
			if (pthread_create(&threads[i], NULL, rename_worker,
			    &workers[i]) != 0)
				_exit(2);
		for (int i = 0; i < 2; i++)
			if (pthread_join(threads[i], NULL) != 0)
				_exit(3);
		_exit(workers[0].failed || workers[1].failed ||
		    pthread_barrier_destroy(&start) != 0);
	}
	test_event_reader_init(&reader);
	failed = 0;
	while (!done && !failed) {
		oes_message_t *msg = &buf.msg;
		int rc = test_event_reader_next(&reader, fd, msg, 100);
		if (rc == 0) {
			oes_event_rename_t *rename = &msg->em_event_data.rename;
			const char *dst = oes_msg_string(msg, rename->dst_name_off);
			oes_response_t response = { .er_id = msg->em_id };
			int matched = -1;
			if (msg->em_event == OES_EVENT_AUTH_RENAME &&
			    msg->em_process.ep_pid == child && dst != NULL &&
			    (msg->em_thread.et_flags & OES_THREAD_META_PRESENT) != 0 &&
			    msg->em_thread.et_id != 0) {
				for (int i = 0; i < 2; i++)
					if (rename->src_file.ef_ino == original[i].st_ino &&
					    (strcmp(dst, workers[i].left) == 0 ||
					    strcmp(dst, workers[i].right) == 0))
						matched = i;
			}
			if (matched >= 0) {
				if ((tids[matched] != 0 &&
				    tids[matched] != msg->em_thread.et_id) ||
				    tids[1 - matched] == msg->em_thread.et_id)
					matched = -1;
				else
					tids[matched] = msg->em_thread.et_id;
			}
			response.er_result = matched < 0 ? OES_AUTH_DENY : OES_AUTH_ALLOW;
			if (matched < 0)
				failed = 1;
			else
				seen[matched]++;
			if (write(fd, &response, sizeof(response)) != sizeof(response))
				failed = 1;
		} else if (errno != EAGAIN)
			failed = 1;
		pid_t waited = waitpid(child, &status, WNOHANG);
		if (waited == child)
			done = 1;
		else if (waited < 0 || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
		    now.tv_sec - begin.tv_sec >= 60)
			failed = 1;
	}
	if (!done || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		failed = 1;
	for (int i = 0; i < 2; i++) {
		/* Retries may authorize again; every requested move must be observed. */
		if (seen[i] < 2 * ROUNDS || stat(workers[i].left, &final) != 0 ||
		    final.st_ino != original[i].st_ino ||
		    lstat(workers[i].right, &final) == 0 || errno != ENOENT)
			failed = 1;
		printf("OES_CONCURRENT worker=%d auth=%u minimum=%d\n",
		    i, seen[i], 2 * ROUNDS);
	}
out:
	if (child > 0 && !done) {
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
	}
	if (fd >= 0)
		close(fd);
	for (int i = 0; i < 2; i++) {
		unlink(workers[i].left);
		unlink(workers[i].right);
	}
	if (chdir("..") != 0 || rmdir(dir) != 0)
		failed = 1;
	return (failed);
}
