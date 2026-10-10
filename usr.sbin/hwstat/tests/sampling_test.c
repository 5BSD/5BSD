/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <sys/param.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include "hwstat.h"

static int fake_signal_wait(const sigset_t *, siginfo_t *, const struct timespec *);
static pid_t fake_fork(void);
static pid_t fake_waitpid(pid_t, int *, int);
static int fake_clock(clockid_t, struct timespec *);
static int fake_sleep(clockid_t, int, const struct timespec *, struct timespec *);
static struct rapl *fake_open(void);
static void fake_close(struct rapl *);
static int fake_poll(struct rapl *);
static int fake_sample(struct rapl *, struct rapl_sample *, double *);
static double fake_interval(const struct rapl *);
int hwstat_program_main(int, char **);

#define main hwstat_program_main
#define sigtimedwait fake_signal_wait
#define fork fake_fork
#define waitpid fake_waitpid
#define clock_gettime fake_clock
#define clock_nanosleep fake_sleep
#define rapl_open fake_open
#define rapl_close fake_close
#define rapl_poll fake_poll
#define rapl_sample(...) fake_sample(__VA_ARGS__)
#define rapl_poll_interval fake_interval
#include "../main.c"
#undef main

static int polls, failure_poll, failure_final, waits, child_exit, interrupted;
static double clock_now;
static int fork_error, signal_wait_error, interrupt_signals;
static double poll_times[4];
static int token;

static struct rapl *
fake_open(void)
{

	return ((struct rapl *)(void *)&token);
}

static void
fake_close(struct rapl *r)
{

	ATF_REQUIRE(r == fake_open());
}

static pid_t
fake_fork(void)
{

	if (fork_error) {
		errno = EAGAIN;
		return (-1);
	}
	return (123);
}

static pid_t
fake_waitpid(pid_t pid, int *status, int options)
{

	ATF_REQUIRE_EQ(pid, 123);
	if (interrupted) {
		interrupted = 0;
		errno = EINTR;
		return (-1);
	}
	if (interrupt_signals && options == WNOHANG && clock_now < 2.25)
		return (0);
	if (++waits < 3 && options == WNOHANG && !interrupt_signals)
		return (0);
	*status = child_exit << 8;
	return (pid);
}

static int
fake_clock(clockid_t id, struct timespec *ts)
{

	ATF_REQUIRE_EQ(id, CLOCK_MONOTONIC);
	ts->tv_sec = (time_t)clock_now;
	ts->tv_nsec = (long)((clock_now - (double)ts->tv_sec) * 1e9);
	return (0);
}

static int
fake_sleep(clockid_t id, int flags, const struct timespec *ts,
    struct timespec *remaining)
{

	ATF_REQUIRE_EQ(id, CLOCK_MONOTONIC);
	ATF_REQUIRE_EQ(flags, TIMER_ABSTIME);
	ATF_REQUIRE(remaining == NULL);
	clock_now = (double)ts->tv_sec + (double)ts->tv_nsec / 1e9;
	return (0);
}

static double
fake_interval(const struct rapl *r)
{

	ATF_REQUIRE(r == fake_open());
	return (1);
}

static int
fake_signal_wait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout)
{

	ATF_REQUIRE(sigismember(set, SIGCHLD));
	ATF_REQUIRE(info == NULL);
	if (interrupt_signals) {
		clock_now += 0.25;
		errno = EINTR;
		return (-1);
	}
	if (signal_wait_error) {
		errno = EINVAL;
		return (-1);
	}
	clock_now += (double)timeout->tv_sec + (double)timeout->tv_nsec / 1e9;
	errno = EAGAIN;
	return (-1);
}

static int
fake_poll(struct rapl *r)
{

	ATF_REQUIRE(r == fake_open());
	if (polls < (int)nitems(poll_times))
		poll_times[polls] = clock_now;
	if (++polls == failure_poll) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

static int
fake_sample(struct rapl *r, struct rapl_sample *samples, double *elapsed)
{

	ATF_REQUIRE(r == fake_open());
	if (failure_final) {
		errno = EIO;
		return (-1);
	}
	samples[0] = (struct rapl_sample){RAPL_PACKAGE, 50, 100};
	*elapsed = 0.5;
	return (1);
}

static void
exec_case(int fail_poll, int fail_final, int child_status, int expected)
{
	char *args[] = { __DECONST(char *, "exec"), __DECONST(char *, "--format"),
	    __DECONST(char *, "json"), __DECONST(char *, "--"),
	    __DECONST(char *, "fixture"), NULL };

	FILE *capture;
	char output[16384];
	size_t length;
	int saved, result;

	capture = tmpfile();
	ATF_REQUIRE(capture != NULL);
	fflush(stdout);
	saved = dup(STDOUT_FILENO);
	ATF_REQUIRE(saved >= 0);
	ATF_REQUIRE(dup2(fileno(capture), STDOUT_FILENO) >= 0);
	failure_poll = fail_poll;
	failure_final = fail_final;
	child_exit = child_status;
	result = cmd_hw_exec(5, args);
	fflush(stdout);
	ATF_REQUIRE(dup2(saved, STDOUT_FILENO) >= 0);
	close(saved);
	rewind(capture);
	length = fread(output, 1, sizeof(output) - 1, capture);
	output[length] = '\0';
	fclose(capture);
	ATF_CHECK_EQ(result, expected);
	if (fail_poll || fail_final || fork_error || signal_wait_error) {
		ATF_CHECK(strstr(output, "\"energy_status\":\"read_error\"") != NULL);
		ATF_CHECK(strstr(output, "\"domains\"") == NULL);
	} else {
		ATF_CHECK(strstr(output, "\"energy_status\":\"available\"") != NULL);
		ATF_CHECK(strstr(output, "\"domains\"") != NULL);
	}
}

ATF_TC_WITHOUT_HEAD(exec_initial_failure);
ATF_TC_BODY(exec_initial_failure, tc)
{

	exec_case(1, 0, 0, 1);
	ATF_CHECK_EQ(waits, 1); /* child still reaped */
}

ATF_TC_WITHOUT_HEAD(exec_midrun_failure);
ATF_TC_BODY(exec_midrun_failure, tc)
{

	exec_case(2, 0, 0, 1);
	ATF_CHECK_EQ(polls, 2);
}

ATF_TC_WITHOUT_HEAD(exec_final_failure);
ATF_TC_BODY(exec_final_failure, tc)
{

	exec_case(0, 1, 0, 1);
}

ATF_TC_WITHOUT_HEAD(exec_preserves_child_failure);
ATF_TC_BODY(exec_preserves_child_failure, tc)
{

	exec_case(0, 1, 42, 42);
}

ATF_TC_WITHOUT_HEAD(exec_interrupted_wait);
ATF_TC_BODY(exec_interrupted_wait, tc)
{

	interrupted = 1;
	exec_case(0, 0, 0, 0);
	ATF_CHECK_EQ(waits, 3);
}

ATF_TC_WITHOUT_HEAD(watch_polls_between_outputs);
ATF_TC_BODY(watch_polls_between_outputs, tc)
{
	char *args[] = { __DECONST(char *, "watch"), __DECONST(char *, "--format"),
	    __DECONST(char *, "json"), __DECONST(char *, "--interval"),
	    __DECONST(char *, "1500"), __DECONST(char *, "--duration"),
	    __DECONST(char *, "1500"), NULL };

	ATF_CHECK_EQ(cmd_hw_watch(7, args), 0);
	ATF_CHECK_EQ(polls, 1500); /* initial + 1499 intermediate polls */
	ATF_CHECK_EQ(clock_now, 1500);
}

ATF_TC_WITHOUT_HEAD(exec_fork_failure_restores_signals);
ATF_TC_BODY(exec_fork_failure_restores_signals, tc)
{
	sigset_t before, after;
	struct sigaction action_before, action_after;
	int sig;

	ATF_REQUIRE_EQ(sigprocmask(SIG_BLOCK, NULL, &before), 0);
	ATF_REQUIRE_EQ(sigaction(SIGCHLD, NULL, &action_before), 0);
	fork_error = 1;
	exec_case(0, 0, 0, 127);
	ATF_CHECK_EQ(waits, 0);
	ATF_REQUIRE_EQ(sigprocmask(SIG_BLOCK, NULL, &after), 0);
	ATF_REQUIRE_EQ(sigaction(SIGCHLD, NULL, &action_after), 0);
	for (sig = 1; sig < NSIG; sig++)
		ATF_CHECK_EQ(sigismember(&before, sig), sigismember(&after, sig));
	ATF_CHECK(action_before.sa_handler == action_after.sa_handler);
}

ATF_TC_WITHOUT_HEAD(exec_signal_wait_failure_reaps_child);
ATF_TC_BODY(exec_signal_wait_failure_reaps_child, tc)
{

	signal_wait_error = 1;
	exec_case(0, 0, 0, 1);
	ATF_CHECK_EQ(waits, 2);
}

ATF_TC_WITHOUT_HEAD(watch_read_failures);
ATF_TC_BODY(watch_read_failures, tc)
{
	char *args[] = { __DECONST(char *, "watch"), __DECONST(char *, "--format"),
	    __DECONST(char *, "json"), __DECONST(char *, "--interval"),
	    __DECONST(char *, "10"), __DECONST(char *, "--duration"),
	    __DECONST(char *, "10"), NULL };
	int i;

	for (i = 0; i < 3; i++) {
		failure_poll = i == 2 ? 0 : i + 1;
		failure_final = i == 2;
		polls = 0;
		clock_now = 0;
		optreset = optind = 1;
		ATF_CHECK_EQ(cmd_hw_watch(7, args), 1);
	}
}

ATF_TC_WITHOUT_HEAD(exec_signals_preserve_poll_deadline);
ATF_TC_BODY(exec_signals_preserve_poll_deadline, tc)
{

	/* Repeated EINTR every 250 ms must not postpone the 1 s polls. */
	interrupt_signals = 1;
	exec_case(0, 0, 0, 0);
	ATF_CHECK_EQ(polls, 3);
	ATF_CHECK_EQ(poll_times[0], 0);
	ATF_CHECK_EQ(poll_times[1], 1);
	ATF_CHECK_EQ(poll_times[2], 2);
	ATF_CHECK_EQ(clock_now, 2.25);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, exec_signals_preserve_poll_deadline);
	ATF_TP_ADD_TC(tp, exec_fork_failure_restores_signals);
	ATF_TP_ADD_TC(tp, exec_signal_wait_failure_reaps_child);
	ATF_TP_ADD_TC(tp, watch_read_failures);
	ATF_TP_ADD_TC(tp, exec_initial_failure);
	ATF_TP_ADD_TC(tp, exec_midrun_failure);
	ATF_TP_ADD_TC(tp, exec_final_failure);
	ATF_TP_ADD_TC(tp, exec_preserves_child_failure);
	ATF_TP_ADD_TC(tp, exec_interrupted_wait);
	ATF_TP_ADD_TC(tp, watch_polls_between_outputs);
	return (atf_no_error());
}
