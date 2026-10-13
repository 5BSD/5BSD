/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise the real wait helper without starting cron or launching jobs. */
#define DEBUGGING 0
#include "cron.h"
#include "cron_trace.h"
#include "cron-wait-under-test.h"
#include <assert.h>

static volatile sig_atomic_t interrupted;

static void
interrupt_wait(int signo __unused)
{
	interrupted = 1;
}

int
main(void)
{
	struct sigaction action = { .sa_handler = interrupt_wait };
	struct itimerval timer = { .it_value = { .tv_usec = 50000 } };
	struct timespec delay = { .tv_nsec = 300000000 };
	pid_t child;
	int status;

	child = fork();
	assert(child >= 0);
	if (child == 0)
		_exit(7);
	status = wait_on_child(child, "exit status test");
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);

	child = fork();
	assert(child >= 0);
	if (child == 0) {
		raise(SIGTERM);
		_exit(99);
	}
	status = wait_on_child(child, "signal status test");
	assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);

	sigemptyset(&action.sa_mask);
	assert(sigaction(SIGALRM, &action, NULL) == 0);
	child = fork();
	assert(child >= 0);
	if (child == 0) {
		nanosleep(&delay, NULL);
		_exit(9);
	}
	assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
	status = wait_on_child(child, "interrupted wait test");
	assert(interrupted && WIFEXITED(status) && WEXITSTATUS(status) == 9);
	puts("cron exit, signal and interrupted waits PASS");
	return (0);
}
