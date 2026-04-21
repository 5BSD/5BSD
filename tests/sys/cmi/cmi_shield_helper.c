/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Helper for shield tests.  Exec'd to get a different nonce, then
 * attempts an operation on a target pid.  Exits 0 if the operation
 * was denied (EACCES/ESRCH), 1 if it succeeded (shield didn't work),
 * 2 on usage error.
 *
 * Usage: cmi_shield_helper <op> <pid>
 *   ops: ptrace, signal, sigkill, sigcont, wait, visibility
 */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <sys/ioctl.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cmi_ioctl.h"
#include "cmi_capprotect_proto.h"

static int
try_ptrace(pid_t pid)
{
	int status;

	if (ptrace(PT_ATTACH, pid, NULL, 0) == 0) {
		waitpid(pid, &status, WUNTRACED);
		ptrace(PT_DETACH, pid, NULL, 0);
		return (1);	/* succeeded — shield didn't block */
	}
	if (errno == EACCES)
		return (0);	/* denied — shield works */
	return (2);		/* unexpected error */
}

static int
try_signal(pid_t pid)
{

	if (kill(pid, SIGUSR1) == 0)
		return (1);
	if (errno == EACCES)
		return (0);
	return (2);
}

/* Check signal permission without delivering (signum=0). */
static int
try_signal0(pid_t pid)
{

	if (kill(pid, 0) == 0)
		return (1);
	if (errno == EACCES)
		return (0);
	return (2);
}

static int
try_sigkill(pid_t pid)
{

	if (kill(pid, SIGKILL) == 0)
		return (1);
	if (errno == EACCES)
		return (0);
	return (2);
}

static int
try_sigcont(pid_t pid)
{

	if (kill(pid, SIGCONT) == 0)
		return (1);
	if (errno == EACCES)
		return (0);
	return (2);
}

static int
try_wait(pid_t pid)
{
	int status;

	/*
	 * waitpid on a non-child returns ECHILD normally.
	 * If MAC denies it, we get EACCES.
	 */
	if (waitpid(pid, &status, WNOHANG) == -1) {
		if (errno == EACCES)
			return (0);	/* denied — shield works */
		if (errno == ECHILD)
			return (1);	/* allowed (no such child, but not blocked) */
	}
	return (1);	/* succeeded or unexpected */
}

static int
try_visibility(pid_t pid)
{
	int mib[4];
	struct kinfo_proc kp;
	size_t len;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;
	len = sizeof(kp);

	if (sysctl(mib, 4, &kp, &len, NULL, 0) == 0 && len > 0)
		return (1);	/* visible — shield didn't hide */
	if (errno == ESRCH || len == 0)
		return (0);	/* hidden — shield works */
	return (2);
}

/*
 * authorize_ptrace: activate a token fd, then try ptrace.
 * Usage: cmi_shield_helper authorize_ptrace <token_fd> <pid>
 * Returns 0 if ptrace succeeds after authorize (access granted),
 * 1 if ptrace still fails (access not granted), 2 on error.
 */
static int
try_authorize_ptrace(int token_fd, pid_t pid)
{
	struct cmi_call_args ca;
	struct cp_request req;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (ioctl(token_fd, CMI_CALL, &ca) != 0)
		return (2);	/* authorize failed */

	if (ptrace(PT_ATTACH, pid, NULL, 0) == 0) {
		waitpid(pid, &status, WUNTRACED);
		ptrace(PT_DETACH, pid, NULL, 0);
		return (0);	/* access granted */
	}
	return (1);		/* still denied */
}

int
main(int argc, char **argv)
{
	pid_t pid;

	if (argc == 4 && strcmp(argv[1], "authorize_ptrace") == 0) {
		int token_fd = (int)strtol(argv[2], NULL, 10);
		pid = (pid_t)strtol(argv[3], NULL, 10);
		if (token_fd < 0 || pid <= 0)
			return (2);
		return (try_authorize_ptrace(token_fd, pid));
	}

	if (argc != 3)
		return (2);

	pid = (pid_t)strtol(argv[2], NULL, 10);
	if (pid <= 0)
		return (2);

	if (strcmp(argv[1], "ptrace") == 0)
		return (try_ptrace(pid));
	if (strcmp(argv[1], "signal") == 0)
		return (try_signal(pid));
	if (strcmp(argv[1], "signal0") == 0)
		return (try_signal0(pid));
	if (strcmp(argv[1], "sigkill") == 0)
		return (try_sigkill(pid));
	if (strcmp(argv[1], "sigcont") == 0)
		return (try_sigcont(pid));
	if (strcmp(argv[1], "wait") == 0)
		return (try_wait(pid));
	if (strcmp(argv[1], "visibility") == 0)
		return (try_visibility(pid));

	return (2);
}
