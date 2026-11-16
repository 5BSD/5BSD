/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Helper for shield tests.  Exec'd to get a different nonce, then
 * attempts an operation on a target pid.  Exit status:
 *
 *   0  the operation was refused the way a capprotect shield refuses it:
 *      EACCES (mac_capability_capprotect's verdict).  ktrace(2) reports
 *      every ktrcanset() refusal as EPERM, so for "ktrace" EPERM (or a
 *      silently skipped target) is the refusal;
 *   1  the operation was allowed (the shield did not block it);
 *   2  usage error, or an unexpected answer such as EPERM from the
 *      p_noambient or ordinary p_candebug/p_cansignal checks, or ESRCH;
 *   3  the target is not a live process (absent or a zombie), so nothing
 *      was proved about its shield.
 *
 * The "visibility" probe is the exception: hiding answers ESRCH, so it
 * counts ESRCH as the refusal.
 *
 * Usage: mac_capability_shield_helper <op> <pid>
 *   ops: ptrace, signal, signal0, sigkill, sigcont, sched, wait,
 *        visibility, ktrace, suspend
 */

#include <sys/types.h>
#include <sys/ktrace.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <sys/ioctl.h>
#include <sys/resource.h>

#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_capprotect_proto.h"
#include "mac_capability_identity_proto.h"

static int
report_self_nonce(int outfd)
{
	struct mac_capability_call_args call;
	struct mac_capability_connect_args connect_args;
	struct identity_request req;
	struct identity_reply reply;
	int ctl, fd, saved;

	ctl = open("/dev/mac_capability", O_RDWR);
	if (ctl < 0)
		return (2);
	memset(&connect_args, 0, sizeof(connect_args));
	strlcpy(connect_args.name, "identity", sizeof(connect_args.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &connect_args) != 0) {
		saved = errno;
		close(ctl);
		errno = saved;
		return (2);
	}
	close(ctl);
	fd = connect_args.fd;

	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;
	memset(&reply, 0, sizeof(reply));
	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply = &reply;
	call.reply_len = sizeof(reply);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &call) != 0 ||
	    reply.status != IDENTITY_STATUS_OK || reply.nonce == 0) {
		close(fd);
		return (2);
	}
	close(fd);
	return (write(outfd, &reply.nonce, sizeof(reply.nonce)) ==
	    (ssize_t)sizeof(reply.nonce) ? 0 : 2);
}

/*
 * The target must be a live process before a refusal can mean anything: a
 * zombie or a reaped PID also refuses ptrace and signals (ESRCH).  The
 * sysctl is not subject to the shield (CP_SF_VISIBLE is not enforced).
 */
static bool
target_live(pid_t pid)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;
	len = sizeof(kp);
	if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len != sizeof(kp))
		return (false);
	return (kp.ki_pid == pid && kp.ki_stat != SZOMB);
}

/* Map a refused call's errno: only the shield's EACCES proves the shield. */
static int
refusal(int error)
{

	return (error == EACCES ? 0 : 2);
}

static int
try_ptrace(pid_t pid)
{
	int status;

	if (ptrace(PT_ATTACH, pid, NULL, 0) == 0) {
		waitpid(pid, &status, WUNTRACED);
		ptrace(PT_DETACH, pid, NULL, 0);
		return (1);	/* succeeded — shield didn't block */
	}
	return (refusal(errno));
}

static int
try_kill(pid_t pid, int signum)
{

	if (kill(pid, signum) == 0)
		return (1);
	return (refusal(errno));
}

static int
try_signal(pid_t pid)
{

	return (try_kill(pid, SIGUSR1));
}

/* Check signal permission without delivering (signum=0). */
static int
try_signal0(pid_t pid)
{

	return (try_kill(pid, 0));
}

static int
try_sigkill(pid_t pid)
{

	return (try_kill(pid, SIGKILL));
}

static int
try_sigcont(pid_t pid)
{

	return (try_kill(pid, SIGCONT));
}

static int
try_sched(pid_t pid)
{
	int prio;

	/*
	 * getpriority goes through p_cansee, not p_cansched.
	 * Use setpriority which goes through p_cansched → MAC hook.
	 * First read the current priority, then set it to the same
	 * value (no actual change, but exercises the permission check).
	 */
	errno = 0;
	prio = getpriority(PRIO_PROCESS, pid);
	if (prio == -1 && errno != 0)
		return (2);	/* p_cansee is not gated by CP_SF_SCHED */

	if (setpriority(PRIO_PROCESS, pid, prio) == 0)
		return (1);	/* allowed — shield didn't block */
	return (refusal(errno));
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

static int
try_ktrace(pid_t pid)
{
	struct kinfo_proc kp;
	int mib[4];
	size_t len;

	/*
	 * ktrace(2) answers EPERM for a target that fails ktrcanset(), which
	 * includes mac_proc_check_ktrace() (capprotect's CP_SF_KTRACE) and the
	 * ordinary p_candebug() refusal alike; the caller pairs this probe
	 * with an unshielded control.  On success, confirm the trace flag was
	 * actually set on the target.
	 */
	char tmpf[] = "/tmp/mac_capability_ktrace.XXXXXX";
	int fd, ret;

	fd = mkstemp(tmpf);
	if (fd < 0)
		return (2);

	ret = ktrace(tmpf, KTROP_SET, KTRFAC_SYSCALL, pid);
	unlink(tmpf);
	close(fd);

	if (ret != 0) {
		/* ktrace(2) answers every ktrcanset() refusal with EPERM. */
		if (errno == EPERM)
			return (0);	/* denied */
		return (2);
	}

	/*
	 * ktrace returned 0, but that doesn't mean it worked.
	 * Check if the target's trace flag was actually set.
	 */
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;
	len = sizeof(kp);
	if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0)
		return (2);	/* CP_SF_VISIBLE is not enforced: unexpected */

	if (kp.ki_traceflag & KTRFAC_SYSCALL) {
		/* Tracing was set — shield didn't block. Clean up. */
		ktrace(tmpf, KTROP_CLEAR, KTRFAC_SYSCALL, pid);
		return (1);
	}

	return (2);	/* ktrace succeeded but set nothing: unexpected */
}

static int
try_suspend(pid_t pid)
{

	if (kill(pid, SIGSTOP) == 0) {
		/* Succeeded — resume and report shield didn't block. */
		kill(pid, SIGCONT);
		return (1);
	}
	return (refusal(errno));
}

/*
 * authorize_ptrace: activate a token fd, then try ptrace.
 * Usage: mac_capability_shield_helper authorize_ptrace <token_fd> <pid>
 * Returns 0 if ptrace succeeds after authorize (access granted),
 * 1 if ptrace still fails (access not granted), 2 on error.
 */
static int
try_authorize_ptrace(int token_fd, pid_t pid)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (ioctl(token_fd, MAC_CAPABILITY_CALL, &ca) != 0)
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
	int outfd;

	if (argc == 3 && strcmp(argv[1], "self_nonce") == 0) {
		outfd = (int)strtol(argv[2], NULL, 10);
		if (outfd < 0)
			return (2);
		return (report_self_nonce(outfd));
	}

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

	/* Hiding is the expected refusal of "visibility": probe it as is. */
	if (strcmp(argv[1], "visibility") == 0)
		return (try_visibility(pid));
	if (!target_live(pid))
		return (3);

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
	if (strcmp(argv[1], "sched") == 0)
		return (try_sched(pid));
	if (strcmp(argv[1], "wait") == 0)
		return (try_wait(pid));
	if (strcmp(argv[1], "ktrace") == 0)
		return (try_ktrace(pid));
	if (strcmp(argv[1], "suspend") == 0)
		return (try_suspend(pid));

	return (2);
}
