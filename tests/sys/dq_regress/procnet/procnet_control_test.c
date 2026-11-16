/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Process creation, signalling, waiting and exit as a process that is NOT
 * attached to a dq(4) controller sees them.
 *
 * The supervisor-control series lets a supervisor stop, signal, kill and
 * wait for the processes attached to its queue, and to do so it touches
 * fork, exit, wait and signal delivery.  A process nothing is attached to
 * must not be able to tell: this program runs one fixed workload through
 * those paths and compares every return value, errno and wait status with
 * a table.  The table is the behaviour of the kernel before the series
 * (commit a9935859e88), recorded by running this program on it, and of
 * the project base before DescriptorQueue, where it gives the same
 * answers.
 *
 * The Linux-ABI half is linux_procctl_test.sh.
 */

#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <pthread.h>
#include <pthread_np.h>

#include "procnet_common.h"

/* One row of the table: a name, the value seen and the value expected. */
#define	ROW(name, got, want) do {					\
	long _g = (long)(got), _w = (long)(want);			\
	ATF_CHECK_MSG(_g == _w, "%s: got %ld (%#lx), expected %ld (%#lx)", \
	    (name), _g, (unsigned long)_g, _w, (unsigned long)_w);	\
} while (0)

/* errno of an expression expected to fail with -1; -1 if it did not. */
#define	FAILS(expr)	(errno = 0, (expr) == -1 ? errno : -1)

/* A pid that names no process: above kern.pid_max's ceiling (99999). */
#define	NOPID	((pid_t)0x3ffffffe)

static volatile sig_atomic_t got_usr1;

static void
on_usr1(int sig __unused)
{

	got_usr1 = 1;
}

/* A child that sleeps until a signal; exits 6 if it was a caught SIGUSR1. */
static pid_t
sleeper(int *pdp)
{
	struct sigaction sa;
	sigset_t empty, usr1;
	pid_t pid;

	/*
	 * The handler and a blocked SIGUSR1 are in place before the fork,
	 * so the parent may signal the child as soon as it has the pid.
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_usr1;
	sigemptyset(&sa.sa_mask);
	ATF_REQUIRE(sigaction(SIGUSR1, &sa, NULL) == 0);
	sigemptyset(&usr1);
	sigaddset(&usr1, SIGUSR1);
	ATF_REQUIRE(sigprocmask(SIG_BLOCK, &usr1, NULL) == 0);
	pid = pdp != NULL ? pdfork(pdp, 0) : fork();
	ATF_REQUIRE_MSG(pid != -1, "fork: %s", strerror(errno));
	if (pid == 0) {
		sigemptyset(&empty);
		while (got_usr1 == 0)
			sigsuspend(&empty);
		_exit(6);
	}
	return (pid);
}

static void *
thread_value(void *arg)
{

	return ((void *)((uintptr_t)arg + 1));
}

static void *
thread_exits_process(void *arg __unused)
{

	_exit(9);
}

static void *
thread_sleeps(void *arg __unused)
{

	for (;;)
		pause();
}

ATF_TC_WITHOUT_HEAD(proc_invariance);
ATF_TC_BODY(proc_invariance, tc)
{
	char *const noargv[] = { __DECONST(char *, "x"), NULL };
	char *const noenv[] = { NULL };
	sigset_t block, old;
	siginfo_t si;
	pthread_t th;
	void *thr;
	pid_t pid, wpid;
	int fd, pd, status;

	/*
	 * SIGCHLD is blocked and never taken, so that nothing below is
	 * interrupted; the SIGCHLD accounting is pinned in
	 * tests/sys/kern/procdesc.c.
	 */
	sigemptyset(&block);
	sigaddset(&block, SIGCHLD);
	ATF_REQUIRE(sigprocmask(SIG_BLOCK, &block, &old) == 0);

	/* --- wait with nothing to wait for --- */
	ROW("wait4(-1) no children", FAILS(wait4(-1, &status, 0, NULL)),
	    ECHILD);
	ROW("waitpid(1)", FAILS(waitpid(1, &status, WNOHANG)), ECHILD);
	ROW("waitpid(NOPID)", FAILS(waitpid(NOPID, &status, WNOHANG)),
	    ECHILD);
	/* An idtype nobody knows matches no child; it is not EINVAL. */
	ROW("wait6 bad idtype", FAILS(wait6(9999, 0, &status, WEXITED, NULL,
	    NULL)), ECHILD);
	ROW("wait6 no options", FAILS(wait6(P_ALL, 0, &status, 0, NULL,
	    NULL)), EINVAL);
	/* 0x40000000 and 0x80000000 are WLINUXALL and WLINUXCLONE. */
	ROW("waitpid bad options", FAILS(waitpid(-1, &status, 0x00100000)),
	    EINVAL);
	ROW("waitpid(WLINUXALL)", FAILS(waitpid(-1, &status, 0x40000000)),
	    ECHILD);

	/* --- fork, exit, waitpid --- */
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		_exit(3);
	status = -1;
	ROW("fork: waitpid", waitpid(pid, &status, 0), pid);
	ROW("fork: status", status, W_EXITCODE(3, 0));
	ROW("fork: second waitpid", FAILS(waitpid(pid, &status, 0)), ECHILD);
	ROW("fork: kill reaped", FAILS(kill(pid, 0)), ESRCH);

	/* The exit status is the low byte. */
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		_exit(0x1234);
	ROW("exit(0x1234): waitpid", waitpid(pid, &status, 0), pid);
	ROW("exit(0x1234): status", status, W_EXITCODE(0x34, 0));

	/* --- vfork --- */
	pid = vfork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		_exit(4);
	ROW("vfork: waitpid", waitpid(pid, &status, 0), pid);
	ROW("vfork: status", status, W_EXITCODE(4, 0));

	/* --- rfork: a shared and a copied descriptor table --- */
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	pid = rfork(RFPROC | RFFDG);
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		_exit(close(fd) == 0 ? 5 : PN_X_WRONG);
	ROW("rfork(RFPROC|RFFDG): waitpid", waitpid(pid, &status, 0), pid);
	ROW("rfork(RFPROC|RFFDG): status", status, W_EXITCODE(5, 0));
	ROW("rfork(RFPROC|RFFDG): parent's fd", fcntl(fd, F_GETFD), 0);
	pid = rfork(RFPROC);
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		_exit(close(fd) == 0 ? 5 : PN_X_WRONG);
	ROW("rfork(RFPROC): waitpid", waitpid(pid, &status, 0), pid);
	ROW("rfork(RFPROC): status", status, W_EXITCODE(5, 0));
	ROW("rfork(RFPROC): parent's fd", FAILS(fcntl(fd, F_GETFD)), EBADF);
	/* Without RFPROC rfork changes the caller; nothing asked is nothing. */
	ROW("rfork(0)", rfork(0), 0);
	ROW("rfork(RFFDG|RFCFDG)", FAILS(rfork(RFPROC | RFFDG | RFCFDG)),
	    EINVAL);

	/* --- execve --- */
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		execl("/bin/sh", "sh", "-c", "exit 7", (char *)NULL);
		_exit(PN_X_SETUP);
	}
	ROW("execve: waitpid", waitpid(pid, &status, 0), pid);
	ROW("execve: status", status, W_EXITCODE(7, 0));
	ROW("execve ENOENT", FAILS(execve("/nonexistent/x", noargv, noenv)),
	    ENOENT);
	ROW("execve of a directory", FAILS(execve("/bin", noargv, noenv)),
	    EACCES);
	ROW("execve without x", FAILS(execve("/etc/passwd", noargv, noenv)),
	    EACCES);
	ROW("execve bad path pointer", FAILS(execve((const char *)-1, noargv,
	    noenv)), EFAULT);

	/* --- kill --- */
	pid = sleeper(NULL);
	ROW("kill(child, 0)", kill(pid, 0), 0);
	ROW("kill bad signal", FAILS(kill(pid, _SIG_MAXSIG + 1)), EINVAL);
	ROW("kill negative signal", FAILS(kill(pid, -1)), EINVAL);
	ROW("kill(NOPID)", FAILS(kill(NOPID, 0)), ESRCH);
	ROW("wait4(-1, WNOHANG) live child", wait4(-1, &status, WNOHANG,
	    NULL), 0);
	ROW("kill(child, SIGUSR1)", kill(pid, SIGUSR1), 0);
	/* wait6 with WNOWAIT looks, and leaves the zombie. */
	memset(&si, 0, sizeof(si));
	status = -1;
	ROW("wait6(WNOWAIT)", wait6(P_PID, pid, &status, WEXITED | WNOWAIT,
	    NULL, &si), pid);
	ROW("wait6(WNOWAIT): status", status, W_EXITCODE(6, 0));
	ROW("wait6(WNOWAIT): si_signo", si.si_signo, SIGCHLD);
	ROW("wait6(WNOWAIT): si_code", si.si_code, CLD_EXITED);
	ROW("wait6(WNOWAIT): si_status", si.si_status, 6);
	ROW("wait6(WNOWAIT): si_pid", si.si_pid, pid);
	/* A zombie can be signalled; nothing happens. */
	ROW("kill(zombie, SIGKILL)", kill(pid, SIGKILL), 0);
	status = -1;
	ROW("wait6 reaps", wait6(P_PID, pid, &status, WEXITED, NULL, NULL),
	    pid);
	ROW("wait6 reaps: status", status, W_EXITCODE(6, 0));

	pid = sleeper(NULL);
	ROW("kill(child, SIGTERM)", kill(pid, SIGTERM), 0);
	ROW("SIGTERM: waitpid", waitpid(pid, &status, 0), pid);
	ROW("SIGTERM: status", status, W_EXITCODE(0, SIGTERM));

	/* A stop and a continue are reported once each. */
	pid = sleeper(NULL);
	ROW("kill(child, SIGSTOP)", kill(pid, SIGSTOP), 0);
	status = -1;
	ROW("waitpid(WUNTRACED)", waitpid(pid, &status, WUNTRACED), pid);
	ROW("stop status", status, W_STOPCODE(SIGSTOP));
	ROW("waitpid(WUNTRACED) again", waitpid(pid, &status,
	    WUNTRACED | WNOHANG), 0);
	ROW("kill(child, SIGCONT)", kill(pid, SIGCONT), 0);
	status = -1;
	ROW("waitpid(WCONTINUED)", waitpid(pid, &status, WCONTINUED), pid);
	ROW("continue status", status, 0x13);
	ROW("waitpid(WCONTINUED) again", waitpid(pid, &status,
	    WCONTINUED | WNOHANG), 0);
	ROW("kill(child, SIGKILL)", kill(pid, SIGKILL), 0);
	ROW("SIGKILL: waitpid", waitpid(pid, &status, 0), pid);
	ROW("SIGKILL: status", status, W_EXITCODE(0, SIGKILL));

	/* --- pdfork, pdkill, pdwait --- */
	pd = -1;
	pid = sleeper(&pd);
	wpid = -1;
	ROW("pdgetpid", pdgetpid(pd, &wpid), 0);
	ROW("pdgetpid: pid", wpid, pid);
	ROW("pdkill(pd, 0)", pdkill(pd, 0), 0);
	ROW("pdkill bad signal", FAILS(pdkill(pd, _SIG_MAXSIG + 1)), EINVAL);
	ROW("pdkill(-1)", FAILS(pdkill(-1, SIGTERM)), EBADF);
	ROW("pdkill(not a process descriptor)", FAILS(pdkill(STDIN_FILENO,
	    SIGTERM)), EBADF);
	ROW("pdwait(-1)", FAILS(pdwait(-1, &status, WEXITED, NULL, NULL)),
	    EBADF);
	ROW("pdwait(not a process descriptor)", FAILS(pdwait(STDIN_FILENO,
	    &status, WEXITED, NULL, NULL)), EINVAL);
	ROW("pdwait no options", FAILS(pdwait(pd, &status, 0, NULL, NULL)),
	    EINVAL);
	ROW("pdwait(WNOHANG) live", FAILS(pdwait(pd, &status,
	    WEXITED | WNOHANG, NULL, NULL)), EWOULDBLOCK);
	ROW("pdgetpid(not a process descriptor)", FAILS(pdgetpid(STDIN_FILENO,
	    &wpid)), EBADF);
	ROW("pdkill(pd, SIGTERM)", pdkill(pd, SIGTERM), 0);
	status = -1;
	memset(&si, 0, sizeof(si));
	ROW("pdwait", pdwait(pd, &status, WEXITED, NULL, &si), 0);
	ROW("pdwait: status", status, W_EXITCODE(0, SIGTERM));
	ROW("pdwait: si_code", si.si_code, CLD_KILLED);
	ROW("pdwait: si_status", si.si_status, SIGTERM);
	ROW("pdwait: si_pid", si.si_pid, pid);
	/* pdwait does not consume the parent's own wait. */
	status = -1;
	ROW("pdwait again", pdwait(pd, &status, WEXITED, NULL, NULL), 0);
	ROW("pdwait again: status", status, W_EXITCODE(0, SIGTERM));
	ROW("pdkill(exited)", pdkill(pd, SIGTERM), 0);
	status = -1;
	ROW("waitpid after pdwait", waitpid(pid, &status, 0), pid);
	ROW("waitpid after pdwait: status", status, W_EXITCODE(0, SIGTERM));
	/*
	 * The descriptor keeps the zombie after the parent's wait: pdkill
	 * still finds it, and pdwait still reports it.
	 */
	ROW("pdkill(reaped by waitpid)", pdkill(pd, SIGTERM), 0);
	status = -1;
	ROW("pdwait after waitpid", pdwait(pd, &status, WEXITED, NULL, NULL),
	    0);
	ROW("pdwait after waitpid: status", status, W_EXITCODE(0, SIGTERM));
	ROW("waitpid again", FAILS(waitpid(pid, &status, 0)), ECHILD);
	ROW("close(pd)", close(pd), 0);
	ROW("pdfork bad flags", FAILS(pdfork(&pd, 0x40000000)), EINVAL);

	/* --- threads --- */
	thr = NULL;
	ROW("pthread_create", pthread_create(&th, NULL, thread_value,
	    (void *)(uintptr_t)41), 0);
	ROW("pthread_join", pthread_join(th, &thr), 0);
	ROW("thread value", (uintptr_t)thr, 42);

	/* _exit(2) from a thread that is not the first ends the process. */
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (pthread_create(&th, NULL, thread_exits_process, NULL) != 0)
			_exit(PN_X_SETUP);
		for (;;)
			pause();
	}
	ROW("_exit from a thread: waitpid", waitpid(pid, &status, 0), pid);
	ROW("_exit from a thread: status", status, W_EXITCODE(9, 0));

	/* A signal ends a process whose other thread sleeps. */
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (pthread_create(&th, NULL, thread_sleeps, NULL) != 0)
			_exit(PN_X_SETUP);
		raise(SIGTERM);
		_exit(PN_X_WRONG);
	}
	ROW("threaded SIGTERM: waitpid", waitpid(pid, &status, 0), pid);
	ROW("threaded SIGTERM: status", status, W_EXITCODE(0, SIGTERM));

	/* fork from a threaded process: the child has the forking thread. */
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (pthread_create(&th, NULL, thread_sleeps, NULL) != 0)
			_exit(PN_X_SETUP);
		wpid = fork();
		if (wpid == -1)
			_exit(PN_X_SETUP);
		if (wpid == 0)
			_exit(pthread_main_np() == 1 ? 8 : PN_X_WRONG);
		if (waitpid(wpid, &status, 0) != wpid || !WIFEXITED(status))
			_exit(PN_X_WRONG);
		_exit(WEXITSTATUS(status));
	}
	ROW("fork with threads: waitpid", waitpid(pid, &status, 0), pid);
	ROW("fork with threads: status", status, W_EXITCODE(8, 0));

	ROW("wait4(-1) at the end", FAILS(wait4(-1, &status, WNOHANG, NULL)),
	    ECHILD);
	ATF_REQUIRE(sigprocmask(SIG_SETMASK, &old, NULL) == 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, proc_invariance);
	return (atf_no_error());
}
