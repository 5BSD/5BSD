/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Disposable amd64 BSD guest only. Build twice: the freestanding Linux probe
 * with -DLINUX_PROBE, and the static native parent without that define.
 * A traced breakpoint reports the syscall result without needing another
 * Linux syscall in capability mode. The native parent always reaps its child.
 */
#ifdef LINUX_PROBE
#ifndef QUOTA_SYSCALL
#define QUOTA_SYSCALL 443
#endif
#define QUOTA_STR_(x) #x
#define QUOTA_STR(x) QUOTA_STR_(x)
__asm__(".text\n.globl _start\n_start:\n"
    "mov $" QUOTA_STR(QUOTA_SYSCALL) ",%eax\nmov $-1,%edi\nsyscall\nint3\nud2\n");
#else
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <machine/reg.h>
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct reg regs;
	pid_t pid, waited;
	int fd, status, rc;
	bool reaped = false;

	if (argc != 2)
		errx(1, "usage: quota_capmode /absolute/path/to/linux_probe");
	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		err(1, "open probe");
	pid = fork();
	if (pid < 0)
		err(1, "fork");
	if (pid == 0) {
		char *args[] = { argv[1], NULL };
		char *env[] = { NULL };

		if (ptrace(PT_TRACE_ME, 0, NULL, 0) != 0 || cap_enter() != 0)
			_exit(2);
		fexecve(fd, args, env);
		_exit(3);
	}
	close(fd);
	rc = 1;
	waited = waitpid(pid, &status, 0);
	reaped = waited == pid && (WIFEXITED(status) || WIFSIGNALED(status));
	if (waited != pid || !WIFSTOPPED(status) ||
	    WSTOPSIG(status) != SIGTRAP)
		goto out;
	if (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) != 0)
		goto out;
	waited = waitpid(pid, &status, 0);
	reaped = waited == pid && (WIFEXITED(status) || WIFSIGNALED(status));
	if (waited != pid || !WIFSTOPPED(status) ||
	    WSTOPSIG(status) != SIGTRAP ||
	    ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0) != 0)
		goto out;
	/* Native ECAPMODE is translated to Linux EPERM (1). */
	rc = (long)regs.r_rax == -1 ? 0 : 4;
	printf("QUOTA_CAPMODE result=%ld rc=%d\n", (long)regs.r_rax, rc);
out:
	if (reaped)
		return (rc);
	/* Terminate the tracee even if a ptrace operation failed. */
	if (ptrace(PT_KILL, pid, NULL, 0) != 0)
		(void)kill(pid, SIGKILL);
	(void)waitpid(pid, &status, 0);
	return (rc);
}
#endif
