/* SPDX-License-Identifier: BSD-2-Clause */
/* Native ptrace regression, disposable amd64 VM only. */
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <machine/reg.h>

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
int
main(void)
{
	struct fpreg a, b;
	pid_t p;
	int st, rc = 1;
	p = fork();
	if (p < 0)
		return 2;
	if (p == 0) {
		if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0)
			_exit(3);
		raise(SIGSTOP);
		_exit(0);
	}
	if (waitpid(p, &st, 0) != p || !WIFSTOPPED(st))
		goto out;
	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	if (ptrace(PT_GETFPREGS, p, (void *)&a, 0) != 0)
		goto out;
	if (ptrace(PT_SETFPREGS, p, (void *)&a, 0) != 0)
		goto out;
	if (ptrace(PT_GETFPREGS, p, (void *)&b, 0) != 0 ||
	    memcmp(&a, &b, sizeof(a)) != 0)
		goto out;
	errno = 0;
	if (ptrace(129, p, (void *)1, 0) != -1 || errno != EINVAL)
		goto out;
	if (ptrace(PT_CONTINUE, p, (void *)1, 0) != 0)
		goto out;
	if (waitpid(p, &st, 0) != p || st != 0)
		return 4;
	return 0;
out:
	ptrace(PT_KILL, p, 0, 0);
	kill(p, SIGKILL);
	waitpid(p, &st, 0);
	return rc;
}
