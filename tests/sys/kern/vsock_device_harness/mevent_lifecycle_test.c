/*
 * Lifecycle tests for bhyve's event callback ownership boundary.
 */
#include <sys/types.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <atf-c.h>

#define	BHYVE_EXIT_ERROR	1
#include "mevent_dut.c"

struct callback_state {
	pthread_mutex_t mtx;
	pthread_cond_t cv;
	unsigned int calls;
	unsigned int cleanup_calls;
	int reentrant_fd;
	int cleanup_error;
};

static void
record_callback(int fd, enum ev_type type __unused, void *arg)
{
	struct callback_state *state;
	uint8_t byte;

	state = arg;
	(void)read(fd, &byte, sizeof(byte));
	pthread_mutex_lock(&state->mtx);
	state->calls++;
	pthread_cond_broadcast(&state->cv);
	pthread_mutex_unlock(&state->mtx);
}

static void
record_cleanup(void *arg)
{
	struct callback_state *state;
	struct mevent *event;
	int fd;

	state = arg;
	pthread_mutex_lock(&state->mtx);
	state->cleanup_calls++;
	fd = state->reentrant_fd;
	state->reentrant_fd = -1;
	pthread_mutex_unlock(&state->mtx);
	if (fd < 0)
		return;

	/*
	 * The cleanup hook must not execute under mevent's queue lock: callers
	 * may need to retire related events while releasing their parameter.
	 */
	event = mevent_add(fd, EVF_READ, record_callback, state);
	pthread_mutex_lock(&state->mtx);
	if (event == NULL)
		state->cleanup_error = 1;
	else if (mevent_delete(event) != 0)
		state->cleanup_error = 1;
	pthread_mutex_unlock(&state->mtx);
}

static void *
dispatch_thread(void *arg __unused)
{

	mevent_dispatch();
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(delete_before_dispatch_removes_kernel_registration);
ATF_TC_BODY(delete_before_dispatch_removes_kernel_registration, tc)
{
	struct callback_state deleted, sentinel, startup;
	struct mevent *deleted_event, *sentinel_event, *startup_event;
	pthread_t thread;
	uint8_t byte;
	int deleted_pipe[2], sentinel_pipe[2], startup_pipe[2], reentrant_pipe[2];

	memset(&deleted, 0, sizeof(deleted));
	memset(&sentinel, 0, sizeof(sentinel));
	memset(&startup, 0, sizeof(startup));
	deleted.reentrant_fd = -1;
	sentinel.reentrant_fd = -1;
	startup.reentrant_fd = -1;
	ATF_REQUIRE_EQ(pthread_mutex_init(&deleted.mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&deleted.cv, NULL), 0);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sentinel.mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sentinel.cv, NULL), 0);
	ATF_REQUIRE_EQ(pthread_mutex_init(&startup.mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&startup.cv, NULL), 0);
	ATF_REQUIRE_EQ(pipe(deleted_pipe), 0);
	ATF_REQUIRE_EQ(pipe(sentinel_pipe), 0);
	ATF_REQUIRE_EQ(pipe(startup_pipe), 0);
	ATF_REQUIRE_EQ(pipe(reentrant_pipe), 0);
	deleted.reentrant_fd = reentrant_pipe[0];

	deleted_event = mevent_add_cleanup(deleted_pipe[0], EVF_READ,
	    record_callback, &deleted, record_cleanup);
	ATF_REQUIRE(deleted_event != NULL);
	ATF_REQUIRE_EQ(mevent_delete_sync(deleted_event), 0);
	pthread_mutex_lock(&deleted.mtx);
	ATF_CHECK_EQ(deleted.cleanup_calls, 1);
	ATF_CHECK_EQ(deleted.cleanup_error, 0);
	pthread_mutex_unlock(&deleted.mtx);

	sentinel_event = mevent_add_cleanup(sentinel_pipe[0], EVF_READ,
	    record_callback, &sentinel, record_cleanup);
	ATF_REQUIRE(sentinel_event != NULL);
	startup_event = mevent_add(startup_pipe[0], EVF_READ,
	    record_callback, &startup);
	ATF_REQUIRE(startup_event != NULL);
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, dispatch_thread, NULL), 0);
	/*
	 * Exercise deletion at the dispatch readiness boundary.  Depending on
	 * scheduling this uses either the direct pre-dispatch path or the
	 * acknowledged event-thread path; both must make the callback dead
	 * before returning.
	 */
	ATF_REQUIRE_EQ(mevent_delete_sync(startup_event), 0);

	byte = 1;
	ATF_REQUIRE_EQ(write(deleted_pipe[1], &byte, sizeof(byte)),
	    (ssize_t)sizeof(byte));
	ATF_REQUIRE_EQ(write(startup_pipe[1], &byte, sizeof(byte)),
	    (ssize_t)sizeof(byte));
	ATF_REQUIRE_EQ(write(sentinel_pipe[1], &byte, sizeof(byte)),
	    (ssize_t)sizeof(byte));
	pthread_mutex_lock(&sentinel.mtx);
	while (sentinel.calls == 0)
		pthread_cond_wait(&sentinel.cv, &sentinel.mtx);
	pthread_mutex_unlock(&sentinel.mtx);

	pthread_mutex_lock(&deleted.mtx);
	ATF_CHECK_EQ(deleted.calls, 0);
	pthread_mutex_unlock(&deleted.mtx);
	pthread_mutex_lock(&startup.mtx);
	ATF_CHECK_EQ(startup.calls, 0);
	pthread_mutex_unlock(&startup.mtx);
	ATF_REQUIRE_EQ(mevent_delete_sync(sentinel_event), 0);
	pthread_mutex_lock(&sentinel.mtx);
	ATF_CHECK_EQ(sentinel.cleanup_calls, 1);
	pthread_mutex_unlock(&sentinel.mtx);

	close(deleted_pipe[0]);
	close(deleted_pipe[1]);
	close(sentinel_pipe[0]);
	close(sentinel_pipe[1]);
	close(startup_pipe[0]);
	close(startup_pipe[1]);
	close(reentrant_pipe[0]);
	close(reentrant_pipe[1]);
	/*
	 * mevent_dispatch() is the process-wide event loop and intentionally
	 * does not return.  ATF runs this case in its own process.
	 */
}

ATF_TC_WITHOUT_HEAD(delete_close_sync_retires_callback_before_fd_close);
ATF_TC_BODY(delete_close_sync_retires_callback_before_fd_close, tc)
{
	struct callback_state state;
	struct mevent *event;
	uint8_t byte;
	void (*old_sigpipe)(int);
	int pipefd[2];

	memset(&state, 0, sizeof(state));
	state.reentrant_fd = -1;
	ATF_REQUIRE_EQ(pthread_mutex_init(&state.mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&state.cv, NULL), 0);
	ATF_REQUIRE_EQ(pipe(pipefd), 0);
	event = mevent_add(pipefd[0], EVF_READ, record_callback, &state);
	ATF_REQUIRE(event != NULL);

	/*
	 * A synchronous close-delete is the lifecycle operation used when the
	 * callback argument is about to be reclaimed.  Before dispatch starts it
	 * must still retire the registration and close the exact event fd.
	 */
	ATF_REQUIRE_EQ(mevent_delete_close_sync(event), 0);
	old_sigpipe = signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(old_sigpipe != SIG_ERR);
	byte = 1;
	errno = 0;
	ATF_CHECK_EQ(write(pipefd[1], &byte, sizeof(byte)), -1);
	ATF_CHECK_EQ(errno, EPIPE);
	close(pipefd[1]);
	ATF_CHECK_EQ(signal(SIGPIPE, old_sigpipe), SIG_IGN);
	ATF_CHECK_EQ(pthread_cond_destroy(&state.cv), 0);
	ATF_CHECK_EQ(pthread_mutex_destroy(&state.mtx), 0);
}

ATF_TC_WITHOUT_HEAD(change_batch_larger_than_kevent_buffer_is_chunked);
ATF_TC_BODY(change_batch_larger_than_kevent_buffer_is_chunked, tc)
{
	struct callback_state state;
	struct kevent changes[MEVENT_MAX];
	struct mevent *events[MEVENT_MAX + 1];
	int pipefd[MEVENT_MAX + 1][2];
	size_t i;

	memset(&state, 0, sizeof(state));
	state.reentrant_fd = -1;
	for (i = 0; i < sizeof(events) / sizeof(events[0]); i++) {
		ATF_REQUIRE_EQ(pipe(pipefd[i]), 0);
		events[i] = mevent_add(pipefd[i][0], EVF_READ,
		    record_callback, &state);
		ATF_REQUIRE(events[i] != NULL);
		ATF_REQUIRE_EQ(mevent_disable(events[i]), 0);
	}

	ATF_CHECK_EQ(mevent_build(changes), MEVENT_MAX);
	ATF_CHECK_EQ(mevent_build(changes), 1);
	ATF_CHECK_EQ(mevent_build(changes), 0);

	for (i = 0; i < sizeof(events) / sizeof(events[0]); i++) {
		ATF_REQUIRE_EQ(mevent_delete_sync(events[i]), 0);
		close(pipefd[i][0]);
		close(pipefd[i][1]);
	}
}

ATF_TC_WITHOUT_HEAD(dispatch_wakeup_pipe_is_nonblocking);
ATF_TC_BODY(dispatch_wakeup_pipe_is_nonblocking, tc)
{
	pthread_t thread;
	bool ready;
	unsigned int i;
	int readfd, writefd;

	(void)tc;
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, dispatch_thread, NULL), 0);
	ready = false;
	for (i = 0; i < 1000; i++) {
		mevent_qlock();
		ready = mevent_dispatching;
		readfd = mevent_pipefd[0];
		writefd = mevent_pipefd[1];
		mevent_qunlock();
		if (ready)
			break;
		usleep(1000);
	}
	ATF_REQUIRE(ready);
	ATF_REQUIRE(readfd >= 0);
	ATF_REQUIRE(writefd >= 0);
	ATF_CHECK((fcntl(readfd, F_GETFL) & O_NONBLOCK) != 0);
	ATF_CHECK((fcntl(writefd, F_GETFL) & O_NONBLOCK) != 0);
	ATF_CHECK((fcntl(readfd, F_GETFD) & FD_CLOEXEC) != 0);
	ATF_CHECK((fcntl(writefd, F_GETFD) & FD_CLOEXEC) != 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp,
	    delete_before_dispatch_removes_kernel_registration);
	ATF_TP_ADD_TC(tp,
	    delete_close_sync_retires_callback_before_fd_close);
	ATF_TP_ADD_TC(tp,
	    change_batch_larger_than_kevent_buffer_is_chunked);
	ATF_TP_ADD_TC(tp, dispatch_wakeup_pipe_is_nonblocking);
	return (atf_no_error());
}
