/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "hwstat.h"

static int energy_poll(struct rapl *);
static int energy_sample(struct rapl *, struct rapl_sample *, double *);
static double energy_interval(const struct rapl *);
int hwstat_program_main(int, char **);
static int checked_execvp(const char *, char *const *);
static int expected_mask = -1, expected_ignore;

#define execvp checked_execvp
#define main hwstat_program_main
#define rapl_poll energy_poll
#define rapl_sample(...) energy_sample(__VA_ARGS__)
#define rapl_poll_interval energy_interval
#include "../main.c"
#undef main
#undef execvp

/* Inspect the child immediately before exec resets caught dispositions. */
static int
checked_execvp(const char *file, char *const *args)
{
	sigset_t mask;
	struct sigaction action;

	if (expected_mask >= 0) {
		if (sigprocmask(SIG_BLOCK, NULL, &mask) != 0 ||
		    sigaction(SIGCHLD, NULL, &action) != 0 ||
		    sigismember(&mask, SIGCHLD) != expected_mask ||
		    (action.sa_handler == SIG_IGN) != expected_ignore) {
			errno = EINVAL;
			return (-1);
		}
	}
	return (execvp(file, args));
}

static int token, polls;
static pid_t extra_child;
static volatile sig_atomic_t user_signals;
static double started, poll_interval = 1;

static int
energy_poll(struct rapl *r)
{

	ATF_REQUIRE(r == (struct rapl *)(void *)&token);
	if (polls++ == 0)
		started = monotime();
	return (0);
}

static double
energy_interval(const struct rapl *r)
{

	ATF_REQUIRE(r == (struct rapl *)(void *)&token);
	return (poll_interval);
}

static int
energy_sample(struct rapl *r, struct rapl_sample *sample, double *elapsed)
{

	ATF_REQUIRE(r == (struct rapl *)(void *)&token);
	*elapsed = monotime() - started;
	*sample = (struct rapl_sample){ RAPL_PACKAGE, 100 * *elapsed, 100 };
	return (1);
}

static double
measure(char **args, int expected, int energy)
{
	struct rapl_sample samples[RAPL_NDOMAINS];
	sigset_t before, after;
	struct sigaction action_before, action_after;
	int failed, count, result, sig, status;

	polls = 0;
	ATF_REQUIRE_EQ(sigprocmask(SIG_BLOCK, NULL, &before), 0);
	ATF_REQUIRE_EQ(sigaction(SIGCHLD, NULL, &action_before), 0);
	result = run_child(args, energy ? (struct rapl *)(void *)&token : NULL,
	    &failed, samples, &count);
	ATF_REQUIRE_MSG(result == expected, "child returned %d, expected %d", result, expected);
	ATF_CHECK_EQ(failed, 0);
	ATF_REQUIRE_EQ(sigaction(SIGCHLD, NULL, &action_after), 0);
	ATF_CHECK(action_before.sa_handler == action_after.sa_handler);
	ATF_CHECK_EQ(action_before.sa_flags, action_after.sa_flags);
	ATF_REQUIRE_EQ(sigprocmask(SIG_BLOCK, NULL, &after), 0);
	for (sig = 1; sig < NSIG; sig++) {
		ATF_CHECK_EQ(sigismember(&before, sig), sigismember(&after, sig));
		ATF_CHECK_EQ(sigismember(&action_before.sa_mask, sig),
		    sigismember(&action_after.sa_mask, sig));
	}
	if (extra_child > 0) {
		ATF_REQUIRE_EQ(waitpid(extra_child, &status, 0), extra_child);
		extra_child = 0;
	}
	ATF_CHECK_EQ(waitpid(-1, &status, WNOHANG), -1);
	ATF_CHECK_EQ(errno, ECHILD); /* measured child was reaped */
	ATF_REQUIRE_EQ(count, energy ? 1 : 0);
	return (energy ? samples[0].joules / 100 : 0);
}

ATF_TC_WITHOUT_HEAD(short_real_child);
ATF_TC_BODY(short_real_child, tc)
{
	char *args[] = { __DECONST(char *, "/bin/sleep"),
	    __DECONST(char *, "0.01"), NULL };
	double best = 10, elapsed;
	int i;

	/* Use the best of five to tolerate unrelated scheduling stalls. */
	for (i = 0; i < 5; i++) {
		elapsed = measure(args, 0, 1);
		if (elapsed < best)
			best = elapsed;
	}
	printf("Shortest 10 ms command measurement: %.6f s\n", best);
	ATF_CHECK_MSG(best < 0.20, "exit detection delayed by polling: %.6f", best);
}

ATF_TC_WITHOUT_HEAD(real_child_spans_polls);
ATF_TC_BODY(real_child_spans_polls, tc)
{
	char *args[] = { __DECONST(char *, "/bin/sleep"),
	    __DECONST(char *, "0.35"), NULL };

	poll_interval = 0.05;
	ATF_CHECK(measure(args, 0, 1) >= 0.35);
	ATF_CHECK(polls >= 5);
}

ATF_TC_WITHOUT_HEAD(real_child_exits_immediately);
ATF_TC_BODY(real_child_exits_immediately, tc)
{
	char *args[] = { __DECONST(char *, "/usr/bin/true"), NULL };
	int i;

	for (i = 0; i < 20; i++)
		(void)measure(args, 0, 1);
}

ATF_TC_WITHOUT_HEAD(real_child_failure_and_signal);
ATF_TC_BODY(real_child_failure_and_signal, tc)
{
	char *failure[] = { __DECONST(char *, "/bin/sh"),
	    __DECONST(char *, "-c"), __DECONST(char *, "exit 42"), NULL };
	char *killed[] = { __DECONST(char *, "/bin/sh"),
	    __DECONST(char *, "-c"), __DECONST(char *, "kill -TERM $$"), NULL };
	char *missing[] = { __DECONST(char *, "/nonexistent/hwstat-test"), NULL };

	(void)measure(failure, 42, 1);
	(void)measure(killed, 128 + SIGTERM, 1);
	(void)measure(missing, 127, 1);
	(void)measure(failure, 42, 0);
}

ATF_TC_WITHOUT_HEAD(existing_signal_mask);
ATF_TC_BODY(existing_signal_mask, tc)
{
	char *args[] = { __DECONST(char *, "/usr/bin/true"), NULL };
	sigset_t blocked, saved;

	sigemptyset(&blocked);
	sigaddset(&blocked, SIGCHLD);
	sigaddset(&blocked, SIGUSR1);
	ATF_REQUIRE_EQ(sigprocmask(SIG_BLOCK, &blocked, &saved), 0);
	(void)measure(args, 0, 1);
	ATF_REQUIRE_EQ(sigprocmask(SIG_SETMASK, &saved, NULL), 0);
}

static void
user_signal(int sig __unused)
{

	user_signals++;
}

ATF_TC_WITHOUT_HEAD(unrelated_signals_and_child);
ATF_TC_BODY(unrelated_signals_and_child, tc)
{
	char *args[] = { __DECONST(char *, "/bin/sleep"),
	    __DECONST(char *, "0.2"), NULL };
	struct sigaction action = {0}, saved;
	pid_t parent;
	int i;

	poll_interval = 0.05;
	action.sa_handler = user_signal;
	sigemptyset(&action.sa_mask);
	ATF_REQUIRE_EQ(sigaction(SIGUSR1, &action, &saved), 0);
	parent = getpid();
	extra_child = fork();
	ATF_REQUIRE(extra_child >= 0);
	if (extra_child == 0) {
		for (i = 0; i < 4; i++) {
			usleep(20000);
			(void)kill(parent, SIGUSR1);
		}
		_exit(0); /* SIGCHLD for a different child must not end measurement. */
	}
	ATF_CHECK(measure(args, 0, 1) >= 0.2);
	ATF_CHECK(user_signals > 0);
	/* Deadline preservation is checked with a controlled clock separately. */
	ATF_REQUIRE_EQ(sigaction(SIGUSR1, &saved, NULL), 0);
}

ATF_TC_WITHOUT_HEAD(child_inherits_original_signal_state);
ATF_TC_BODY(child_inherits_original_signal_state, tc)
{
	char path[1024], masked[2], ignored[2];
	char *args[] = { path, __DECONST(char *, "--mask-probe"), masked, ignored, NULL };
	struct sigaction action = {0}, saved_action;
	sigset_t mask, saved;
	int m, ign;

	snprintf(path, sizeof(path), "%s/exec_timing_test",
	    atf_tc_get_config_var(tc, "srcdir"));
	ATF_REQUIRE_EQ(sigprocmask(SIG_BLOCK, NULL, &saved), 0);
	ATF_REQUIRE_EQ(sigaction(SIGCHLD, NULL, &saved_action), 0);
	for (m = 0; m < 2; m++) {
		for (ign = 0; ign < 2; ign++) {
			mask = saved;
			if (m)
				sigaddset(&mask, SIGCHLD);
			else
				sigdelset(&mask, SIGCHLD);
			ATF_REQUIRE_EQ(sigprocmask(SIG_SETMASK, &mask, NULL), 0);
			action.sa_handler = ign ? SIG_IGN : SIG_DFL;
			sigemptyset(&action.sa_mask);
			ATF_REQUIRE_EQ(sigaction(SIGCHLD, &action, NULL), 0);
			snprintf(masked, sizeof(masked), "%d", m);
			expected_mask = m;
			expected_ignore = ign;
			/* execsigs() resets even ignored SIGCHLD to SIG_DFL. */
			strlcpy(ignored, "0", sizeof(ignored));
			printf("Probe masked=%d ignored=%d\n", m, ign);
			(void)measure(args, 0, 1);
		}
	}
	ATF_REQUIRE_EQ(sigaction(SIGCHLD, &saved_action, NULL), 0);
	ATF_REQUIRE_EQ(sigprocmask(SIG_SETMASK, &saved, NULL), 0);
}

int atf_driver_main(int, char **);
#define main atf_driver_main
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, unrelated_signals_and_child);
	ATF_TP_ADD_TC(tp, child_inherits_original_signal_state);
	ATF_TP_ADD_TC(tp, short_real_child);
	ATF_TP_ADD_TC(tp, real_child_spans_polls);
	ATF_TP_ADD_TC(tp, real_child_exits_immediately);
	ATF_TP_ADD_TC(tp, real_child_failure_and_signal);
	ATF_TP_ADD_TC(tp, existing_signal_mask);
	return (atf_no_error());
}

#undef main

/* Exec this test binary without the ATF harness to inspect inherited state. */
int
main(int argc, char **argv)
{
	sigset_t mask;
	struct sigaction action;

	if (argc == 4 && strcmp(argv[1], "--mask-probe") == 0) {
		if (sigprocmask(SIG_BLOCK, NULL, &mask) != 0 ||
		    sigaction(SIGCHLD, NULL, &action) != 0)
			return (2);
		fprintf(stderr, "Inherited masked=%d ignored=%d; expected %s %s\n",
		    sigismember(&mask, SIGCHLD), action.sa_handler == SIG_IGN,
		    argv[2], argv[3]);
		return (sigismember(&mask, SIGCHLD) != atoi(argv[2]) ||
		    (action.sa_handler == SIG_IGN) != atoi(argv[3]));
	}
	return (atf_driver_main(argc, argv));
}
