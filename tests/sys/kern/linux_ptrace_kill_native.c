/* SPDX-License-Identifier: BSD-2-Clause */
/* Verify that native ptrace retains its stopped-SIGKILL behavior. */
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <signal.h>
#include <unistd.h>
int
main(void)
{
	pid_t p;
	int st;
	p = fork();
	if (p < 0)
		return 1;
	if (!p) {
		if (ptrace(PT_TRACE_ME, 0, 0, 0))
			_exit(90);
		raise(SIGSTOP);
		_exit(91);
	}
	if (waitpid(p, &st, 0) != p || !WIFSTOPPED(st))
		return 2;
	if (kill(p, SIGKILL))
		return 3;
	usleep(20000);
	if (waitpid(p, &st, WNOHANG) != 0)
		return 4;
	if (ptrace(PT_KILL, p, 0, 0))
		return 5;
	if (waitpid(p, &st, 0) != p || !WIFSIGNALED(st) ||
	    WTERMSIG(st) != SIGKILL)
		return 6;
	return 0;
}
