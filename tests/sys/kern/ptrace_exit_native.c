/* SPDX-License-Identifier: BSD-2-Clause */
/* Native opt-in process exit-stop regression; disposable VM only. */
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <machine/reg.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#ifndef PTRACE_EXIT
#define PTRACE_EXIT 0x0040
#endif
int
main(void)
{
	for (int enabled = 0; enabled < 2; enabled++) {
		pid_t pid = fork();
		int status, mask = enabled ? PTRACE_EXIT : 0;
		if (pid < 0) return 1;
		if (!pid) {
			if (ptrace(PT_TRACE_ME, 0, NULL, 0)) _exit(90);
			raise(SIGSTOP);
			_exit(23);
		}
		if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status) ||
		    ptrace(PT_SET_EVENT_MASK, pid, (caddr_t)&mask, sizeof(mask)) ||
		    ptrace(PT_CONTINUE, pid, (caddr_t)1, 0)) return 2;
		if (waitpid(pid, &status, 0) != pid) return 3;
		if (enabled) {
			struct ptrace_lwpinfo info;
			struct reg regs;
			if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP ||
			    ptrace(PT_LWPINFO, pid, (caddr_t)&info, sizeof(info)) ||
			    !(info.pl_flags & PL_FLAG_EXITED) ||
			    ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0) ||
			    ptrace(PT_CONTINUE, pid, (caddr_t)1, 0)) return 4;
			if (waitpid(pid, &status, 0) != pid) return 5;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 23) return 6;
	}
	puts("PTRACE_EXIT_NATIVE_PASS");
	return 0;
}
