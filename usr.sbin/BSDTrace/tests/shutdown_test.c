/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

static unsigned clocks, event_calls, terms, kills, waits;
static int mode, kill_failure, wait_failure, exit_wait, exit_error;
static void *exit_worker;
static int
fake_clock(clockid_t id, struct timespec *time)
{
	ATF_CHECK_EQ(CLOCK_MONOTONIC, id);
	clocks++;
	if ((mode == 0 && clocks == 1) || (mode == 1 && clocks == 2))
		return (errno = EIO, -1);
	time->tv_sec = clocks == 1 ? 10 : 12;
	time->tv_nsec = 0;
	return (0);
}
static int
fake_kill(int fd, int sig)
{
	ATF_CHECK(fd >= 0);
	if (sig == SIGTERM)
		terms++;
	else if (sig == SIGKILL)
		kills++;
	else
		atf_tc_fail("unexpected signal");
	return (sig == SIGKILL && kill_failure ? (errno = EPERM, -1) : 0);
}
static int
fake_wait(int fd, int *status, int options, struct rusage *usage, siginfo_t *info)
{
	(void)fd;
	(void)usage;
	(void)info;
	if (exit_wait) {
		ATF_CHECK_EQ(WEXITED | WNOHANG, options);
		if (++waits == 1)
			return (errno = EINTR, -1);
		*status = 0;
		return (exit_error ? (errno = exit_error, -1) : 0);
	}
	ATF_CHECK_EQ(WEXITED | ((kill_failure ||
	    (wait_failure && waits != 0)) ? WNOHANG : 0), options);
	waits++;
	if (kill_failure || wait_failure)
		return (errno = EIO, -1);
	if (waits == 1)
		return (errno = EINTR, -1);
	*status = 0;
	return (0);
}
static int
fake_event(int kq, const struct kevent *changes, int nchanges,
    struct kevent *events_out, int count, const struct timespec *timeout)
{
	(void)kq;
	(void)changes;
	(void)events_out;
	ATF_CHECK_EQ(0, nchanges);
	ATF_CHECK_EQ(1, count);
	ATF_CHECK_EQ(3, timeout->tv_sec);
	ATF_CHECK_EQ(0, timeout->tv_nsec);
	event_calls++;
	if (exit_worker != NULL) {
		events_out->filter = EVFILT_PROCDESC;
		events_out->udata = exit_worker;
		exit_worker = NULL;
		return (1);
	}
	return (0);
}
#define clock_gettime fake_clock
#define pdkill fake_kill
#define pdwait fake_wait
#define kevent(...) fake_event(__VA_ARGS__)
int bsdtrace_main(void);
#define main bsdtrace_main
#include "../tracecmp.c"
#undef main

ATF_TC_WITHOUT_HEAD(shutdown_clock_failure);
ATF_TC_BODY(shutdown_clock_failure, tc)
{
	struct trace_worker *head, *node;
	size_t count;
	int fds[4];

	for (mode = 0; mode < 3; mode++) {
		clocks = event_calls = terms = kills = waits = 0;
		head = NULL;
		count = 2;
		for (size_t i = 0; i < 2; i++) {
			node = calloc(1, sizeof(*node));
			ATF_REQUIRE(node != NULL);
			node->pd = fds[2 * i] = open("/dev/null", O_RDONLY);
			node->liveness = fds[2 * i + 1] = open("/dev/null", O_RDONLY);
			ATF_REQUIRE(node->liveness >= 0);
			ATF_REQUIRE(node->pd >= 0);
			node->next = head;
			head = node;
		}
		ATF_CHECK_EQ(0, workers_shutdown(-1, &head, &count));
		ATF_CHECK_EQ(NULL, head);
		ATF_CHECK_EQ(0, count);
		ATF_CHECK_EQ(mode == 0 ? 1 : 2, clocks);
		ATF_CHECK_EQ(mode == 2 ? 1 : 0, event_calls);
		ATF_CHECK_EQ(2, terms);
		ATF_CHECK_EQ(2, kills);
		ATF_CHECK_EQ(3, waits);
		for (size_t i = 0; i < 4; i++)
			ATF_CHECK_ERRNO(EBADF, fcntl(fds[i], F_GETFD) == -1);
	}
}
ATF_TC_WITHOUT_HEAD(shutdown_reports_cleanup_failure);
ATF_TC_BODY(shutdown_reports_cleanup_failure, tc)
{
	struct trace_worker *head, *node;
	size_t count;
	int fds[4];

	for (int failure = 0; failure < 2; failure++) {
		mode = 2;
		kill_failure = failure == 0;
		wait_failure = failure == 1;
		clocks = event_calls = terms = kills = waits = 0;
		head = NULL;
		count = 2;
		for (size_t i = 0; i < 2; i++) {
			node = calloc(1, sizeof(*node));
			ATF_REQUIRE(node != NULL);
			node->pd = fds[2 * i] = open("/dev/null", O_RDONLY);
			node->liveness = fds[2 * i + 1] = open("/dev/null", O_RDONLY);
			ATF_REQUIRE(node->liveness >= 0);
			ATF_REQUIRE(node->pd >= 0);
			node->next = head;
			head = node;
		}
		ATF_CHECK_ERRNO(kill_failure ? EPERM : EIO,
		    workers_shutdown(-1, &head, &count) == -1);
		ATF_CHECK_EQ(NULL, head);
		ATF_CHECK_EQ(0, count);
		ATF_CHECK_EQ(2, kills);
		ATF_CHECK_EQ(2, waits);
		for (size_t i = 0; i < 4; i++)
			ATF_CHECK_ERRNO(EBADF, fcntl(fds[i], F_GETFD) == -1);
	}
}

ATF_TC_WITHOUT_HEAD(exit_event_reap_errors);
ATF_TC_BODY(exit_event_reap_errors, tc)
{
	struct trace_worker *head;
	size_t count;
	int errors[] = { 0, EIO, ECHILD };
	int pd;

	for (size_t i = 0; i < nitems(errors); i++) {
		head = calloc(1, sizeof(*head));
		ATF_REQUIRE(head != NULL);
		head->pd = pd = open("/dev/null", O_RDONLY);
		ATF_REQUIRE(pd >= 0);
		head->liveness = -1;
		count = 1;
		mode = 2;
		exit_wait = 1;
		exit_error = errors[i];
		exit_worker = head;
		clocks = event_calls = terms = kills = waits = 0;
		if (exit_error == EIO)
			ATF_CHECK_ERRNO(EIO, workers_shutdown(-1, &head, &count) == -1);
		else
			ATF_CHECK_EQ(0, workers_shutdown(-1, &head, &count));
		ATF_CHECK_EQ(NULL, head);
		ATF_CHECK_EQ(0, count);
		ATF_CHECK_EQ(1, terms);
		ATF_CHECK_EQ(0, kills);
		ATF_CHECK_EQ(2, waits);
		ATF_CHECK_ERRNO(EBADF, fcntl(pd, F_GETFD) == -1);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, shutdown_clock_failure);
	ATF_TP_ADD_TC(tp, exit_event_reap_errors);
	ATF_TP_ADD_TC(tp, shutdown_reports_cleanup_failure);
	return (atf_no_error());
}
