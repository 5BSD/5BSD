/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ConnectWise
 * Copyright (c) 2026 Mark Johnston <markj@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/procctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/procdesc.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <machine/atomic.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>
#include <kvm.h>

#include "freebsd_test_suite/macros.h"

/* Tests for procdesc(4) that aren't specific to any one syscall */

/*
 * Block until a thread in the specified process is sleeping in the specified
 * wait message.
 */
static void
wait_for_naptime(pid_t pid, const char *wmesg)
{
	kvm_t *kd;
	int count;

	kd = kvm_openfiles(NULL, "/dev/null", NULL, O_RDONLY, NULL);
	ATF_REQUIRE(kd != NULL);
	for (;;) {
		struct kinfo_proc *kip;
		int i;

		usleep(1000);
		kip = kvm_getprocs(kd, KERN_PROC_PID | KERN_PROC_INC_THREAD,
		    pid, &count);
		ATF_REQUIRE(kip != NULL);
		for (i = 0; i < count; i++) {
			ATF_REQUIRE(kip[i].ki_stat != SZOMB);
			if (kip[i].ki_stat == SSLEEP &&
			    strcmp(kip[i].ki_wmesg, wmesg) == 0)
				break;
		}
		if (i < count)
			break;
	}

	kvm_close(kd);
}

/*
 * Even after waiting on a process descriptor with waitpid(2), the kernel will
 * not recycle the pid until after the process descriptor is closed.  That is
 * important to prevent users from trying to wait() twice, the second time
 * using a dangling pid.
 *
 * Whether this same anti-recycling behavior is used with pdwait() is
 * unimportant, because pdwait _always_ uses a process descriptor.
 */
ATF_TC_WITHOUT_HEAD(pid_recycle);
ATF_TC_BODY(pid_recycle, tc)
{
	size_t len;
	int i, pd, pid_max;
	pid_t dangle_pid;

	len = sizeof(pid_max);
	ATF_REQUIRE_EQ_MSG(0,
	    sysctlbyname("kern.pid_max", &pid_max, &len, NULL, 0),
	    "sysctlbyname: %s", strerror(errno));

	/* Create a process descriptor */
	dangle_pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	ATF_REQUIRE_MSG(dangle_pid >= 0, "pdfork: %s", strerror(errno));
	if (dangle_pid == 0) {
		// In child
		_exit(0);
	}
	/*
	 * Reap the child, but don't close the pd, creating a dangling pid.
	 * Notably, it isn't a Zombie, because the process is reaped.
	 */
	ATF_REQUIRE_EQ(dangle_pid, waitpid(dangle_pid, NULL, WEXITED));

	/*
	 * Now create and kill pid_max additional children.  Test to see if pid
	 * gets reused.  If not, that means the kernel is correctly reserving
	 * the dangling pid from reuse.
	 */
	for (i = 0; i < pid_max; i++) {
		pid_t pid;

		pid = vfork();
		ATF_REQUIRE_MSG(pid >= 0, "vfork: %s", strerror(errno));
		if (pid == 0)
			_exit(0);
		ATF_REQUIRE_MSG(pid != dangle_pid,
		    "pid got recycled after %d forks", i);
		ATF_REQUIRE_EQ(pid, waitpid(pid, NULL, WEXITED));
	}
	close(pd);
}

static void *
poll_procdesc(void *arg)
{
	struct pollfd pfd;

	pfd.fd = *(int *)arg;
	pfd.events = POLLHUP;
	(void)poll(&pfd, 1, 5000);
	return ((void *)(uintptr_t)pfd.revents);
}

/*
 * Regression test to exercise the case where a procdesc is closed while a
 * thread is poll()ing it.
 */
ATF_TC_WITHOUT_HEAD(poll_close_race);
ATF_TC_BODY(poll_close_race, tc)
{
	pthread_t thr;
	pid_t pid;
	uintptr_t revents;
	int error, pd;

	pid = pdfork(&pd, PD_DAEMON);
	ATF_REQUIRE_MSG(pid >= 0, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		pause();
		_exit(0);
	}

	error = pthread_create(&thr, NULL, poll_procdesc, &pd);
	ATF_REQUIRE_MSG(error == 0, "pthread_create: %s", strerror(error));

	wait_for_naptime(getpid(), "select");

	ATF_REQUIRE_MSG(close(pd) == 0, "close: %s", strerror(errno));

	error = pthread_join(thr, (void *)&revents);
	ATF_REQUIRE_MSG(error == 0, "pthread_join: %s", strerror(error));
	ATF_REQUIRE_EQ(revents, POLLNVAL);
}

/*
 * Verify that poll(2) of a procdesc returns POLLHUP when the process exits.
 */
ATF_TC_WITHOUT_HEAD(poll_exit_wakeup);
ATF_TC_BODY(poll_exit_wakeup, tc)
{
	pthread_t thr;
	uintptr_t revents;
	pid_t pid;
	int error, pd;

	pid = pdfork(&pd, PD_DAEMON);
	ATF_REQUIRE_MSG(pid >= 0, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		pause();
		_exit(0);
	}

	error = pthread_create(&thr, NULL, poll_procdesc, &pd);
	ATF_REQUIRE_MSG(error == 0, "pthread_create: %s", strerror(error));

	wait_for_naptime(getpid(), "select");

	ATF_REQUIRE_MSG(pdkill(pd, SIGKILL) == 0,
	    "pdkill: %s", strerror(errno));

	error = pthread_join(thr, (void *)&revents);
	ATF_REQUIRE_MSG(error == 0, "pthread_join: %s", strerror(error));
	ATF_REQUIRE_EQ(revents, POLLHUP);

	ATF_REQUIRE_MSG(close(pd) == 0, "close: %s", strerror(errno));
}

/* Tests for pdopenpid(2) */

/*
 * Basic: open a process descriptor for a child, verify pdgetpid() returns the
 * right pid.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_basic);
ATF_TC_BODY(pdopenpid_basic, tc)
{
	pid_t child, queried;
	int fd;

	child = fork();
	ATF_REQUIRE_MSG(child >= 0, "fork: %s", strerror(errno));
	if (child == 0) {
		for (;;)
			pause();
		_exit(0);
	}

	fd = pdopenpid(child, 0);
	ATF_REQUIRE_MSG(fd >= 0, "pdopenpid: %s", strerror(errno));

	ATF_REQUIRE_MSG(pdgetpid(fd, &queried) == 0,
	    "pdgetpid: %s", strerror(errno));
	ATF_REQUIRE_EQ(child, queried);

	ATF_REQUIRE_MSG(pdkill(fd, SIGKILL) == 0,
	    "pdkill: %s", strerror(errno));
	ATF_REQUIRE_EQ(child, waitpid(child, NULL, 0));
	ATF_REQUIRE(close(fd) == 0);
}

/*
 * pdopenpid with PD_CLOEXEC should set the close-on-exec flag.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_cloexec);
ATF_TC_BODY(pdopenpid_cloexec, tc)
{
	pid_t child;
	int fd, flags;

	child = fork();
	ATF_REQUIRE_MSG(child >= 0, "fork: %s", strerror(errno));
	if (child == 0) {
		for (;;)
			pause();
		_exit(0);
	}

	fd = pdopenpid(child, PD_CLOEXEC);
	ATF_REQUIRE_MSG(fd >= 0, "pdopenpid: %s", strerror(errno));

	flags = fcntl(fd, F_GETFD);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE(flags & FD_CLOEXEC);

	ATF_REQUIRE_MSG(pdkill(fd, SIGKILL) == 0,
	    "pdkill: %s", strerror(errno));
	ATF_REQUIRE_EQ(child, waitpid(child, NULL, 0));
	ATF_REQUIRE(close(fd) == 0);
}

/*
 * Invalid flags should return EINVAL.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_einval);
ATF_TC_BODY(pdopenpid_einval, tc)
{
	ATF_REQUIRE_ERRNO(EINVAL, pdopenpid(getpid(), 0xdeadbeef) < 0);
	ATF_REQUIRE_ERRNO(EINVAL, pdopenpid(getpid(), ~PD_ALLOWED_AT_FORK) < 0);
}

/*
 * Validate handling of EMFILE.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_emfile);
ATF_TC_BODY(pdopenpid_emfile, tc)
{
	pid_t child;
	struct rlimit rl;
	int fd;

	child = fork();
	ATF_REQUIRE_MSG(child >= 0, "fork: %s", strerror(errno));
	if (child == 0) {
		for (;;)
			pause();
		_exit(0);
	}

	/*
	 * Determine the lowest unused fd, then set the fd limit to that
	 * value so that no new fds can be allocated.
	 */
	fd = dup(STDIN_FILENO);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(close(fd) == 0);

	ATF_REQUIRE_EQ(getrlimit(RLIMIT_NOFILE, &rl), 0);
	rl.rlim_cur = fd;
	ATF_REQUIRE_EQ(setrlimit(RLIMIT_NOFILE, &rl), 0);

	ATF_REQUIRE_ERRNO(EMFILE, pdopenpid(child, 0) < 0);

	/*
	 * The child should not have been killed or reparented as a side
	 * effect of the failed syscall.
	 */
	ATF_REQUIRE_MSG(kill(child, 0) == 0,
	    "child was killed: %s", strerror(errno));
	ATF_REQUIRE_MSG(waitpid(child, NULL, WNOHANG) == 0,
	    "child was reparented");

	ATF_REQUIRE_MSG(kill(child, SIGKILL) == 0,
	    "kill: %s", strerror(errno));
	ATF_REQUIRE_EQ(child, waitpid(child, NULL, 0));
}

/*
 * Opening a nonexistent pid should return ESRCH.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_esrch);
ATF_TC_BODY(pdopenpid_esrch, tc)
{
	ATF_REQUIRE_ERRNO(ESRCH, pdopenpid(123456789, 0) < 0);
}

/*
 * pdopenpid works for children in capability mode.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_child);
ATF_TC_BODY(pdopenpid_child, tc)
{
	pid_t child, parent;

	ATF_REQUIRE_FEATURE("security_capability_mode");

	parent = getpid();
	child = fork();
	ATF_REQUIRE_MSG(child >= 0, "fork: %s", strerror(errno));
	if (child == 0) {
		while (getppid() == parent)
			sleep(1);
		_exit(0);
	}

	ATF_REQUIRE_MSG(cap_enter() == 0, "cap_enter: %s", strerror(errno));
	ATF_REQUIRE_MSG(pdopenpid(child, 0) >= 0, "pdopenpid: %s",
	    strerror(errno));
}

/*
 * pdopenpid should fail in capability mode.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_capmode);
ATF_TC_BODY(pdopenpid_capmode, tc)
{
	pid_t child;
	volatile pid_t grandchild;

	ATF_REQUIRE_FEATURE("security_capability_mode");

	child = vfork();
	ATF_REQUIRE_MSG(child >= 0, "fork: %s", strerror(errno));
	if (child == 0) {
		grandchild = fork();
		ATF_REQUIRE_MSG(grandchild >= 0, "fork: %s", strerror(errno));
		if (grandchild == 0) {
			for (;;)
				sleep(1);
		} else {
			_exit(0);
		}
	}

	ATF_REQUIRE_MSG(cap_enter() == 0, "cap_enter: %s", strerror(errno));
	ATF_REQUIRE_ERRNO(ECAPMODE, pdopenpid(grandchild, 0) < 0);
	kill(grandchild, SIGKILL);
}

/*
 * Open a process descriptor for a child that already has one from pdfork().
 * Both fds should refer to the same process.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_pdfork_then_open);
ATF_TC_BODY(pdopenpid_pdfork_then_open, tc)
{
	pid_t child, pid1, pid2;
	int fd1, fd2;

	child = pdfork(&fd1, PD_DAEMON);
	ATF_REQUIRE_MSG(child >= 0, "pdfork: %s", strerror(errno));
	if (child == 0) {
		for (;;)
			pause();
		_exit(0);
	}

	fd2 = pdopenpid(child, 0);
	ATF_REQUIRE_MSG(fd2 >= 0, "pdopenpid: %s", strerror(errno));

	ATF_REQUIRE(pdgetpid(fd1, &pid1) == 0);
	ATF_REQUIRE(pdgetpid(fd2, &pid2) == 0);
	ATF_REQUIRE_EQ(pid1, pid2);
	ATF_REQUIRE_EQ(child, pid1);

	/* Kill via the second fd, wait via the first. */
	ATF_REQUIRE_MSG(pdkill(fd2, SIGKILL) == 0,
	    "pdkill: %s", strerror(errno));
	ATF_REQUIRE_MSG(pdwait(fd1, NULL, WEXITED, NULL, NULL) == 0,
	    "pdwait: %s", strerror(errno));

	ATF_REQUIRE(close(fd1) == 0);
	ATF_REQUIRE(close(fd2) == 0);
}

/*
 * Open a process descriptor for a child created with fork(), which has no
 * pre-existing procdesc.  Then use pdkill() and pdwait() on it.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_fork_then_open);
ATF_TC_BODY(pdopenpid_fork_then_open, tc)
{
	pid_t child;
	int fd, status;

	child = fork();
	ATF_REQUIRE_MSG(child >= 0, "fork: %s", strerror(errno));
	if (child == 0) {
		for (;;)
			pause();
		_exit(0);
	}

	fd = pdopenpid(child, 0);
	ATF_REQUIRE_MSG(fd >= 0, "pdopenpid: %s", strerror(errno));

	ATF_REQUIRE_MSG(pdkill(fd, SIGKILL) == 0,
	    "pdkill: %s", strerror(errno));
	ATF_REQUIRE_MSG(pdwait(fd, &status, WEXITED, NULL, NULL) == 0,
	    "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFSIGNALED(status));
	ATF_REQUIRE_EQ(WTERMSIG(status), SIGKILL);

	ATF_REQUIRE(close(fd) == 0);
}

/*
 * Closing one fd should not kill the process when another fd still references
 * the same procdesc.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_close_one_of_two);
ATF_TC_BODY(pdopenpid_close_one_of_two, tc)
{
	pid_t child, queried;
	int fd1, fd2, status;

	child = pdfork(&fd1, PD_DAEMON);
	ATF_REQUIRE_MSG(child >= 0, "pdfork: %s", strerror(errno));
	if (child == 0) {
		for (;;)
			pause();
		_exit(0);
	}

	fd2 = pdopenpid(child, 0);
	ATF_REQUIRE_MSG(fd2 >= 0, "pdopenpid: %s", strerror(errno));

	/* Close the first fd; the process should remain alive. */
	ATF_REQUIRE(close(fd1) == 0);

	/*
	 * Verify the process is still reachable via the second fd and still
	 * alive.
	 */
	ATF_REQUIRE_EQ(0, pdgetpid(fd2, &queried));
	ATF_REQUIRE_EQ(child, queried);
	ATF_REQUIRE_MSG(pdkill(fd2, 0) == 0,
	    "pdkill(0) after closing first fd: %s", strerror(errno));

	/* Now kill and reap via the second fd. */
	ATF_REQUIRE_MSG(pdkill(fd2, SIGKILL) == 0,
	    "pdkill: %s", strerror(errno));
	ATF_REQUIRE_MSG(pdwait(fd2, &status, WEXITED, NULL, NULL) == 0,
	    "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFSIGNALED(status));
	ATF_REQUIRE_EQ(WTERMSIG(status), SIGKILL);

	ATF_REQUIRE(close(fd2) == 0);
}

/*
 * Two calls to pdopenpid for the same process (no pdfork) should both work.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_open_twice);
ATF_TC_BODY(pdopenpid_open_twice, tc)
{
	pid_t child, pid1, pid2;
	int fd1, fd2;

	child = fork();
	ATF_REQUIRE_MSG(child >= 0, "fork: %s", strerror(errno));
	if (child == 0) {
		for (;;)
			pause();
		_exit(0);
	}

	fd1 = pdopenpid(child, 0);
	ATF_REQUIRE_MSG(fd1 >= 0, "pdopenpid(1): %s", strerror(errno));

	fd2 = pdopenpid(child, 0);
	ATF_REQUIRE_MSG(fd2 >= 0, "pdopenpid(2): %s", strerror(errno));

	ATF_REQUIRE_EQ(0, pdgetpid(fd1, &pid1));
	ATF_REQUIRE_EQ(0, pdgetpid(fd2, &pid2));
	ATF_REQUIRE_EQ(pid1, pid2);

	/* Close the first, process should survive. */
	ATF_REQUIRE(close(fd1) == 0);
	ATF_REQUIRE_MSG(pdkill(fd2, 0) == 0,
	    "pdkill(0) after closing first fd: %s", strerror(errno));

	ATF_REQUIRE_MSG(pdkill(fd2, SIGKILL) == 0,
	    "pdkill: %s", strerror(errno));
	ATF_REQUIRE_MSG(pdwait(fd2, NULL, WEXITED, NULL, NULL) == 0,
	    "pdwait: %s", strerror(errno));
	ATF_REQUIRE(close(fd2) == 0);
}

/*
 * When a process with two procdesc fds exits, only one pdwait should succeed
 * in collecting the exit status.  The other should get ESRCH.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_pdwait_only_one);
ATF_TC_BODY(pdopenpid_pdwait_only_one, tc)
{
	pid_t child;
	int fd1, fd2, pip[2], status;

	ATF_REQUIRE_EQ(pipe(pip), 0);

	child = pdfork(&fd1, PD_DAEMON);
	ATF_REQUIRE_MSG(child >= 0, "pdfork: %s", strerror(errno));
	if (child == 0) {
		char c;

		close(pip[1]);
		/* Block until the parent has opened the second fd. */
		(void)read(pip[0], &c, 1);
		_exit(42);
	}
	ATF_REQUIRE(close(pip[0]) == 0);

	/* Open the second fd while the child is still alive. */
	fd2 = pdopenpid(child, 0);
	ATF_REQUIRE_MSG(fd2 >= 0, "pdopenpid: %s", strerror(errno));

	/* Release the child so that it exits. */
	ATF_REQUIRE(close(pip[1]) == 0);

	/* Collect via the first fd. */
	ATF_REQUIRE_MSG(pdwait(fd1, &status, WEXITED, NULL, NULL) == 0,
	    "pdwait(fd1): %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 42);

	/* The second fd should be able to collect as well. */
	ATF_REQUIRE_MSG(pdwait(fd2, &status, WEXITED, NULL, NULL) == 0,
	    "pdwait(fd2): %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 42);

	ATF_REQUIRE(close(fd1) == 0);
	ATF_REQUIRE(close(fd2) == 0);
}

/*
 * Opening a process descriptor for ourselves should work.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_self);
ATF_TC_BODY(pdopenpid_self, tc)
{
	pid_t child, queried;
	int childfd, fd, status;

	/*
	 * Closing self-referencing procdesc would steal the exit
	 * status from the parent.  Keep one more procdesc for the
	 * child in the parent so that we can query the state.
	 *
	 * For the same reason we must use fork() and test in the
	 * child, otherwise kyua does not get the SIGCHILD nor the
	 * exit status.
	 */
	child = pdfork(&childfd, 0);
	if (child == 0) {
		fd = pdopenpid(getpid(), PD_DAEMON);
		if (fd < 0)
			_exit(21);
		if (pdgetpid(fd, &queried) == -1)
			_exit(22);
		if (getpid() != queried)
			_exit(23);
		if (close(fd) != 0)
			_exit(24);
		_exit(0);
	}

	ATF_REQUIRE(pdgetpid(childfd, &queried) == 0);
	ATF_REQUIRE_EQ(queried, child);
	ATF_REQUIRE(pdwait(childfd, &status, WEXITED, NULL, NULL) == 0);

	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	ATF_REQUIRE(close(childfd) == 0);
}

/*
 * pdopenpid for a process that is exiting (P_WEXIT set) should fail with EBUSY.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_exiting);
ATF_TC_BODY(pdopenpid_exiting, tc)
{
	pid_t child;
	int fd, pip[2], status;

	ATF_REQUIRE_EQ(pipe(pip), 0);

	child = fork();
	ATF_REQUIRE_MSG(child >= 0, "fork: %s", strerror(errno));
	if (child == 0) {
		char c;

		close(pip[1]);
		(void)read(pip[0], &c, 1);
		_exit(0);
	}
	ATF_REQUIRE(close(pip[0]) == 0);

	/* Tell the child to exit. */
	ATF_REQUIRE(close(pip[1]) == 0);

	/* Might still race. */
	usleep(1000);
	fd = pdopenpid(child, 0);
	if (fd >= 0) {
		ATF_REQUIRE(close(fd) == 0);
	} else {
		ATF_REQUIRE_MSG(errno == EBUSY,
		    "unexpected errno %d (%s)", errno, strerror(errno));
	}

	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
}

/*
 * Make sure that opening a process descriptor doesn't cause a wakeup in the
 * target process.
 */
ATF_TC_WITHOUT_HEAD(pdopenpid_no_wakeup);
ATF_TC_BODY(pdopenpid_no_wakeup, tc)
{
	pid_t child;
	int fd, pip[2];

	ATF_REQUIRE(pipe(pip) == 0);

	child = fork();
	ATF_REQUIRE_MSG(child >= 0, "fork: %s", strerror(errno));
	if (child == 0) {
		char buf[1];

		close(pip[1]);
		(void)read(pip[0], buf, 1);
		_exit(0);
	}
	close(pip[0]);

	wait_for_naptime(child, "piperd");

	fd = pdopenpid(child, 0);
	ATF_REQUIRE_MSG(fd >= 0, "pdopenpid: %s", strerror(errno));

	/*
	 * If pdopenpid() caused a wakeup, read() returned and the child exited.
	 */
	wait_for_naptime(child, "piperd");

	ATF_REQUIRE(close(pip[1]) == 0);
	ATF_REQUIRE(close(fd) == 0);
}

/*
 * basic pddupfd functionality
 */

#define	EXPECTED_OFFSET		123

ATF_TC_WITHOUT_HEAD(pddupfd_basic);
ATF_TC_BODY(pddupfd_basic, tc)
{
	int *comm;
	struct __wrusage wu;
	struct __siginfo si;
	int fd, pp, rfd, status, workfd, r, r1;
	off_t off;
	pid_t child;

	comm = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED |
	    MAP_ANONYMOUS, -1, 0);
	ATF_REQUIRE(comm != MAP_FAILED);
	atomic_store_int(comm, -1);

	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		workfd = open("/etc/passwd", O_RDONLY);
		ATF_REQUIRE(workfd != -1);
		atomic_store_int(comm, workfd);
		while ((r = (int)atomic_load_int(comm)) >= 0)
			sleep(1);
		lseek(workfd, EXPECTED_OFFSET, SEEK_SET);
		r -= 1;
		atomic_store_int(comm, r);
		while (r == (int)atomic_load_int(comm))
			sleep(1);
		_exit(0x23);
	}

	fd = pdopenpid(child, 0);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE(pdgetpid(fd, &pp) == 0);

	while ((rfd = (int)atomic_load_int(comm)) == -1)
		;
	ATF_REQUIRE(rfd >= 0);
	workfd = pddupfd(fd, rfd, 0);
	ATF_REQUIRE(workfd != -1);

	/*
	 * pddupfd-ed file must dup-ed, i.e. the underlying file must
	 * be same between the remote and local filedescriptors.
	 * Check that the initial seek offset is zero.  Then observe
	 * the updated offset, which is only possible if the file is
	 * indeed shared.
	 */
	off = lseek(workfd, 0, SEEK_CUR);
	ATF_REQUIRE_EQ(off, 0);
	r = -1;
	atomic_store_int(comm, r);
	while ((r1 = (int)atomic_load_int(comm)) == r)
		sleep(1);
	off = lseek(workfd, 0, SEEK_CUR);
	ATF_REQUIRE_EQ(off, EXPECTED_OFFSET);
	r1 -= 1;
	atomic_store_int(comm, r1);
	ATF_REQUIRE(close(workfd) == 0);

	ATF_REQUIRE(pdwait(fd, &status, WEXITED, &wu, &si) != -1);
	ATF_REQUIRE(close(fd) == 0);
}

/*
 * Pins of the process-descriptor behaviour the supervisor-control series
 * must not change for a process that is not attached to a dq(4) queue:
 * what closing the last descriptor does, who is told about the exit and
 * who may reap it, and how long the pid stays reserved.  Every expected
 * value below was read from the kernel (sys_procdesc.c, kern_exit.c) and
 * then confirmed by running the case on the kernel before the series.
 */

static void
sigchld_noop(int sig __unused)
{
}

/*
 * SIGCHLD is counted with sigtimedwait(2): block it and give it a handler.
 * The handler never runs, but without one the signal's default action is
 * to be ignored and the kernel then discards it when it is posted, blocked
 * or not; the counts below would all be zero.  Returns 0, or -1 with errno
 * set; used in forked children too.
 */
/*
 * How long to wait for something that must happen (a signal, a state):
 * it normally takes milliseconds; a loaded emulated guest can be more
 * than ten times slower.  Reaching the limit is a failure.
 */
#define	WAIT_MS	120000

static int
sigchld_setup(void)
{
	struct sigaction sa;
	sigset_t set;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_noop;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGCHLD, &sa, NULL) != 0)
		return (-1);
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	return (sigprocmask(SIG_BLOCK, &set, NULL));
}

static void
sigchld_block(void)
{

	ATF_REQUIRE_EQ(0, sigchld_setup());
}

/*
 * Take one pending SIGCHLD, waiting up to ms milliseconds.  Returns 1 with
 * *si filled, or 0 when none arrived.  Async-signal-safe: also used in
 * forked children, which is why it does not use ATF_REQUIRE.
 */
static int
sigchld_take(int ms, siginfo_t *si)
{
	struct timespec ts;
	siginfo_t dummy;
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000L;
	for (;;) {
		if (sigtimedwait(&set, si != NULL ? si : &dummy, &ts) ==
		    SIGCHLD)
			return (1);
		if (errno != EINTR)
			return (0);
	}
}

/* 1 if sig is pending on the process, 0 if not, -errno. */
static int
proc_sigpending(pid_t pid, int sig)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;
	len = sizeof(kp);
	if (sysctl(mib, nitems(mib), &kp, &len, NULL, 0) == -1)
		return (-errno);
	if (len == 0)
		return (-ESRCH);
	return (sigismember(&kp.ki_siglist, sig));
}

/* The process state (ki_stat), or -errno when the pid names no process. */
static int
proc_stat(pid_t pid, pid_t *ppidp)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;
	len = sizeof(kp);
	if (sysctl(mib, nitems(mib), &kp, &len, NULL, 0) == -1)
		return (-errno);
	if (len == 0)
		return (-ESRCH);
	if (ppidp != NULL)
		*ppidp = kp.ki_ppid;
	return (kp.ki_stat);
}

/* Poll until proc_stat(pid) is want (or, with want2 != 0, want2). */
static int
proc_stat_wait(pid_t pid, int want, int want2, int ms)
{
	int i, st;

	st = 0;
	for (i = 0; i <= ms; i++) {
		st = proc_stat(pid, NULL);
		if (st == want || (want2 != 0 && st == want2))
			break;
		usleep(1000);
	}
	return (st);
}

static int
pid_max_get(void)
{
	size_t len;
	int pid_max;

	len = sizeof(pid_max);
	if (sysctlbyname("kern.pid_max", &pid_max, &len, NULL, 0) != 0)
		return (-1);
	return (pid_max);
}

/*
 * Create processes for one full cycle of the pid space, as pid_recycle
 * does.  Returns 1 if one of them was given the pid `want`, 0 if none
 * was, -1 on an error.  Takes minutes; callers run it in a process of
 * its own.
 */
static int
pid_handed_out(pid_t want)
{
	pid_t pid;
	int i, pid_max, status;

	pid_max = pid_max_get();
	if (pid_max <= 0)
		return (-1);
	for (i = 0; i <= pid_max; i++) {
		pid = vfork();
		if (pid == -1)
			return (-1);
		if (pid == 0)
			_exit(0);
		if (waitpid(pid, &status, 0) != pid)
			return (-1);
		if (pid == want)
			return (1);
	}
	return (0);
}

/* pid_handed_out() in a child; reaping it takes its SIGCHLD back. */
static int
pid_handed_out_child(pid_t want)
{
	pid_t prober;
	int status;

	prober = fork();
	ATF_REQUIRE(prober != -1);
	if (prober == 0)
		_exit(pid_handed_out(want) & 0xff);
	ATF_REQUIRE_EQ(prober, waitpid(prober, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status), "prober status %#x", status);
	ATF_REQUIRE_MSG(WEXITSTATUS(status) <= 1, "prober failed");
	return (WEXITSTATUS(status));
}

/*
 * P1.  Closing the last descriptor of a pdfork(2) child made without
 * PD_DAEMON kills it with SIGKILL (procdesc_close).  The child keeps its
 * parent (PZOMBIEREF_PARENT is set unless PD_NOWAITPID), so the parent
 * gets SIGCHLD and reaps the SIGKILL status with waitpid(2), once.
 */
ATF_TC_WITHOUT_HEAD(close_last_kills);
ATF_TC_BODY(close_last_kills, tc)
{
	siginfo_t si;
	pid_t pid, ppid;
	int pd, status;

	sigchld_block();
	pid = pdfork(&pd, 0);
	ATF_REQUIRE_MSG(pid >= 0, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		for (;;)
			pause();
	}
	wait_for_naptime(pid, "sigsusp");
	ATF_REQUIRE_EQ(0, sigchld_take(0, NULL));

	ATF_REQUIRE_EQ(0, close(pd));

	memset(&si, 0, sizeof(si));
	ATF_REQUIRE_MSG(sigchld_take(WAIT_MS, &si) == 1,
	    "no SIGCHLD after closing the last descriptor");
	ATF_CHECK_EQ_MSG(pid, si.si_pid, "si_pid %d", (int)si.si_pid);
	ATF_CHECK_EQ_MSG(CLD_KILLED, si.si_code, "si_code %d", si.si_code);
	ATF_CHECK_EQ_MSG(SIGKILL, si.si_status, "si_status %d", si.si_status);
	/* A zombie of ours, still under the same parent. */
	ppid = -1;
	ATF_CHECK_EQ(SZOMB, proc_stat(pid, &ppid));
	ATF_CHECK_EQ(getpid(), ppid);

	status = 0;
	ATF_REQUIRE_EQ_MSG(pid, waitpid(pid, &status, 0), "waitpid: %s",
	    strerror(errno));
	ATF_CHECK_MSG(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	    "status %#x", status);
	ATF_CHECK_ERRNO(ECHILD, waitpid(pid, &status, WNOHANG) == -1);
	ATF_CHECK_EQ_MSG(0, sigchld_take(0, NULL), "a second SIGCHLD");
	ATF_CHECK_ERRNO(ESRCH, kill(pid, 0) == -1);
}

/*
 * P2.  With PD_DAEMON the close kills nothing.  The child stays a child
 * of its parent (no reparenting: sys_procdesc.c reparents only when the
 * parent's zombie reference is absent), exits by itself, and the parent
 * gets SIGCHLD and the exit status as for a plain fork(2).
 */
ATF_TC_WITHOUT_HEAD(daemon_close_then_exit);
ATF_TC_BODY(daemon_close_then_exit, tc)
{
	siginfo_t si;
	pid_t pid, ppid;
	int go[2], pd, st, status;
	char b;

	sigchld_block();
	ATF_REQUIRE_EQ(0, pipe(go));
	pid = pdfork(&pd, PD_DAEMON);
	ATF_REQUIRE_MSG(pid >= 0, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		close(go[1]);
		if (read(go[0], &b, 1) != 1)
			_exit(8);
		_exit(7);
	}
	close(go[0]);

	ATF_REQUIRE_EQ(0, close(pd));

	/* Not killed, not signalled, not reparented. */
	ATF_CHECK_EQ_MSG(0, sigchld_take(300, NULL),
	    "SIGCHLD after closing a PD_DAEMON descriptor");
	ppid = -1;
	st = proc_stat(pid, &ppid);
	ATF_CHECK_MSG(st > 0 && st != SZOMB, "child state %d", st);
	ATF_CHECK_EQ(getpid(), ppid);
	ATF_CHECK_EQ(0, waitpid(pid, &status, WNOHANG));

	b = 'g';
	ATF_REQUIRE_EQ(1, write(go[1], &b, 1));
	memset(&si, 0, sizeof(si));
	ATF_REQUIRE_MSG(sigchld_take(WAIT_MS, &si) == 1, "no SIGCHLD at exit");
	ATF_CHECK_EQ_MSG(pid, si.si_pid, "si_pid %d", (int)si.si_pid);
	ATF_CHECK_EQ_MSG(CLD_EXITED, si.si_code, "si_code %d", si.si_code);
	ATF_CHECK_EQ_MSG(7, si.si_status, "si_status %d", si.si_status);
	status = 0;
	ATF_REQUIRE_EQ_MSG(pid, waitpid(pid, &status, 0), "waitpid: %s",
	    strerror(errno));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 7,
	    "status %#x", status);
	ATF_CHECK_ERRNO(ECHILD, waitpid(pid, &status, WNOHANG) == -1);
	ATF_CHECK_EQ_MSG(0, sigchld_take(0, NULL), "a second SIGCHLD");
	close(go[1]);
}

/*
 * P3.  The last descriptor closes while the child is stopped under a
 * debugger that is neither its parent nor the closer.
 *
 * The SIGKILL of the close is queued: a traced, stopped process is not
 * woken by it (tdsendsignal), so the child stays stopped until the
 * debugger lets go.
 *
 * Recorded, and not what one would expect: it does not die then either.
 * The child was asleep in pause(3) when the debugger attached, and an
 * attach leaves a sleeping thread asleep (debug.ptrace_attach_transparent,
 * the default).  PT_DETACH does not wake it, so the SIGKILL stays pending
 * on a process that is neither stopped nor traced until something else
 * wakes the thread; here, a second SIGKILL.  This is a defect (a lost
 * wakeup, also in FreeBSD), recorded as open in the project's issue list
 * (2026-11-11, "SIGKILL to a traced sleeper").  The case pins the value
 * as found, it does not endorse it: the commit that fixes the defect
 * changes these expectations.  See
 * ptrace__sigkill_third_party_stopped_detach in ptrace_test.c for a
 * tracee that stopped itself and does die at the detach.
 *
 * Who it belongs to afterwards depends on the parent's zombie reference:
 *  - pdfork(0): the parent keeps it; at the detach the parent gets a
 *    SIGCHLD for the continue, and after the second SIGKILL one for the
 *    death, and reaps the SIGKILL status.
 *  - pdfork(PD_NOWAITPID): there is no parent reference, so the close
 *    gives the child to the reaper.  It is traced, so it cannot simply
 *    be reparented: its "real parent" (p_oppid) becomes the reaper and
 *    it moves to the reaper's orphan list (the branch this case is
 *    here for).  The process that made it can no longer wait for it
 *    (ECHILD at once) and never hears of it again.
 */
static void
traced_child_close(int pdflags)
{
	struct procctl_reaper_status rs;
	siginfo_t si;
	pid_t dbg, pid, ppid;
	int cmd[2], pd, rep[2], st, status;
	char b;

	/* What is recorded here is the transparent attach's behaviour. */
	ATF_REQUIRE_SYSCTL_INT("debug.ptrace_attach_transparent", 1);
	sigchld_block();
	ATF_REQUIRE_EQ(0, procctl(P_PID, getpid(), PROC_REAP_STATUS, &rs));
	ATF_REQUIRE_MSG(rs.rs_reaper != getpid(),
	    "the test process is its own reaper");

	pid = pdfork(&pd, pdflags);
	ATF_REQUIRE_MSG(pid >= 0, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		for (;;)
			pause();
	}

	/* Asleep in pause(3) before the attach: see above. */
	st = proc_stat_wait(pid, SSLEEP, 0, WAIT_MS);
	ATF_REQUIRE_EQ_MSG(SSLEEP, st, "child state %d", st);

	ATF_REQUIRE_EQ(0, pipe(cmd));
	ATF_REQUIRE_EQ(0, pipe(rep));
	dbg = fork();
	ATF_REQUIRE(dbg != -1);
	if (dbg == 0) {
		close(pd);	/* not the last: the parent holds one */
		close(cmd[1]);
		close(rep[0]);
		if (ptrace(PT_ATTACH, pid, NULL, 0) != 0)
			_exit(11);
		if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status))
			_exit(12);
		b = 'a';
		if (write(rep[1], &b, 1) != 1)
			_exit(13);
		if (read(cmd[0], &b, 1) != 1)
			_exit(14);
		if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) != 0)
			_exit(15);
		_exit(0);
	}
	close(cmd[0]);
	close(rep[1]);
	ATF_REQUIRE_EQ_MSG(1, read(rep[0], &b, 1), "debugger did not attach");
	ATF_REQUIRE_EQ(SSTOP, proc_stat(pid, NULL));

	ATF_REQUIRE_EQ(0, close(pd));

	/* The SIGKILL is queued; the tracee stays stopped. */
	usleep(300000);
	ppid = -1;
	st = proc_stat(pid, &ppid);
	ATF_CHECK_EQ_MSG(SSTOP, st, "state %d after the close", st);
	ATF_CHECK_EQ_MSG(0, sigchld_take(0, NULL), "SIGCHLD before detach");
	if ((pdflags & PD_NOWAITPID) == 0) {
		ATF_CHECK_EQ_MSG(getpid(), ppid, "real parent %d", (int)ppid);
		ATF_CHECK_EQ(0, waitpid(pid, &status, WNOHANG));
	} else {
		ATF_CHECK_EQ_MSG(rs.rs_reaper, ppid,
		    "real parent %d, reaper %d", (int)ppid,
		    (int)rs.rs_reaper);
		errno = 0;
		ATF_CHECK_EQ(-1, waitpid(pid, &status, WNOHANG));
		ATF_CHECK_EQ_MSG(ECHILD, errno, "errno %d", errno);
	}

	/*
	 * Let the debugger detach and exit.  The SIGCHLDs are counted
	 * before anything is reaped: reaping a child takes its pending
	 * SIGCHLD back (proc_reap).
	 */
	b = 'd';
	ATF_REQUIRE_EQ(1, write(cmd[1], &b, 1));

	if ((pdflags & PD_NOWAITPID) == 0) {
		/* Two, in either order: the debugger's exit, the continue. */
		bool saw_child = false, saw_dbg = false;
		int i;

		for (i = 0; i < 2; i++) {
			memset(&si, 0, sizeof(si));
			ATF_REQUIRE_MSG(sigchld_take(WAIT_MS, &si) == 1,
			    "SIGCHLD %d missing", i);
			if (si.si_pid == pid) {
				saw_child = true;
				ATF_CHECK_EQ_MSG(CLD_CONTINUED, si.si_code,
				    "si_code %d", si.si_code);
				ATF_CHECK_EQ_MSG(SIGCONT, si.si_status,
				    "si_status %d", si.si_status);
			} else if (si.si_pid == dbg)
				saw_dbg = true;
		}
		ATF_CHECK(saw_child);
		ATF_CHECK(saw_dbg);
	} else {
		/* Only the debugger's; the child is the reaper's business. */
		memset(&si, 0, sizeof(si));
		ATF_REQUIRE_EQ(1, sigchld_take(WAIT_MS, &si));
		ATF_CHECK_EQ_MSG(dbg, si.si_pid, "si_pid %d", (int)si.si_pid);
	}
	ATF_REQUIRE_EQ(dbg, waitpid(dbg, &status, 0));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "debugger status %#x", status);

	/*
	 * Detached, and still there a second later: asleep, not stopped,
	 * with the SIGKILL of the close pending.
	 */
	ATF_CHECK_EQ_MSG(0, sigchld_take(1000, NULL),
	    "a SIGCHLD after the detach");
	ppid = -1;
	st = proc_stat(pid, &ppid);
	ATF_CHECK_EQ_MSG(SSLEEP, st, "child state %d after the detach", st);
	ATF_CHECK_EQ_MSG(1, proc_sigpending(pid, SIGKILL),
	    "SIGKILL not pending after the detach");
	if ((pdflags & PD_NOWAITPID) == 0) {
		ATF_CHECK_EQ_MSG(getpid(), ppid, "parent %d", (int)ppid);
		ATF_CHECK_EQ(0, waitpid(pid, &status, WNOHANG));
	} else {
		ATF_CHECK_EQ_MSG(rs.rs_reaper, ppid, "parent %d, reaper %d",
		    (int)ppid, (int)rs.rs_reaper);
		errno = 0;
		ATF_CHECK_EQ(-1, waitpid(pid, &status, WNOHANG));
		ATF_CHECK_EQ_MSG(ECHILD, errno, "errno %d", errno);
	}

	/* A second SIGKILL wakes the thread, and the process dies. */
	ATF_REQUIRE_EQ(0, kill(pid, SIGKILL));
	if ((pdflags & PD_NOWAITPID) == 0) {
		memset(&si, 0, sizeof(si));
		ATF_REQUIRE_MSG(sigchld_take(WAIT_MS, &si) == 1,
		    "no SIGCHLD for the death");
		ATF_CHECK_EQ_MSG(pid, si.si_pid, "si_pid %d", (int)si.si_pid);
		ATF_CHECK_EQ_MSG(CLD_KILLED, si.si_code, "si_code %d",
		    si.si_code);
		ATF_CHECK_EQ_MSG(SIGKILL, si.si_status, "si_status %d",
		    si.si_status);
		status = 0;
		ATF_REQUIRE_EQ_MSG(pid, waitpid(pid, &status, 0),
		    "waitpid: %s", strerror(errno));
		ATF_CHECK_MSG(WIFSIGNALED(status) &&
		    WTERMSIG(status) == SIGKILL, "status %#x", status);
	} else {
		st = proc_stat_wait(pid, -ESRCH, SZOMB, WAIT_MS);
		ATF_CHECK_MSG(st == -ESRCH || st == SZOMB,
		    "child state %d after the second SIGKILL", st);
		ATF_CHECK_EQ_MSG(0, sigchld_take(300, NULL),
		    "SIGCHLD for a child given to the reaper");
		errno = 0;
		ATF_CHECK_EQ(-1, waitpid(pid, &status, WNOHANG));
		ATF_CHECK_EQ_MSG(ECHILD, errno, "errno %d", errno);
	}
	ATF_CHECK_EQ(0, sigchld_take(0, NULL));
	close(cmd[1]);
	close(rep[0]);
}

ATF_TC_WITHOUT_HEAD(traced_child_close);
ATF_TC_BODY(traced_child_close, tc)
{

	traced_child_close(0);
}

ATF_TC_WITHOUT_HEAD(traced_child_close_nowaitpid);
ATF_TC_BODY(traced_child_close_nowaitpid, tc)
{

	traced_child_close(PD_NOWAITPID);
}

/*
 * P5.  EVFILT_PROCDESC/NOTE_EXIT on a pdfork(2) child reports the exit
 * once, with the wait status as data and EV_EOF | EV_ONESHOT set.  After
 * the parent has reaped the child with waitpid(2) the descriptor still
 * names it: fstat(2) succeeds (mode S_IFREG, the "not running" form),
 * pdgetpid(2) returns the pid, and a fresh registration fires at once
 * with the same status.  The pid goes when the descriptor is closed.
 */
ATF_TC_WITHOUT_HEAD(kevent_exit_then_reap);
ATF_TC_BODY(kevent_exit_then_reap, tc)
{
	struct timespec ts;
	struct kevent ev;
	struct stat sb;
	siginfo_t si;
	pid_t pid, pid2;
	int go[2], kq, kq2, n, pd, status;
	char b;

	sigchld_block();
	ATF_REQUIRE_EQ(0, pipe(go));
	pid = pdfork(&pd, 0);
	ATF_REQUIRE_MSG(pid >= 0, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		close(go[1]);
		if (read(go[0], &b, 1) != 1)
			_exit(8);
		_exit(4);
	}
	close(go[0]);

	ATF_REQUIRE_EQ(0, fstat(pd, &sb));
	ATF_CHECK_EQ_MSG(S_IFREG | S_IRWXU, sb.st_mode, "live st_mode %#o",
	    (unsigned)sb.st_mode);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&ev, pd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, NULL);
	ATF_REQUIRE_EQ_MSG(0, kevent(kq, &ev, 1, NULL, 0, NULL),
	    "kevent register: %s", strerror(errno));
	ts.tv_sec = 0;
	ts.tv_nsec = 0;
	ATF_REQUIRE_EQ(0, kevent(kq, NULL, 0, &ev, 1, &ts));

	b = 'g';
	ATF_REQUIRE_EQ(1, write(go[1], &b, 1));
	memset(&ev, 0, sizeof(ev));
	ts.tv_sec = 10;
	n = kevent(kq, NULL, 0, &ev, 1, &ts);
	ATF_REQUIRE_EQ_MSG(1, n, "kevent: %d (%s)", n, strerror(errno));
	ATF_CHECK_EQ((uintptr_t)pd, ev.ident);
	ATF_CHECK_EQ(EVFILT_PROCDESC, ev.filter);
	ATF_CHECK_EQ_MSG(EV_CLEAR | EV_EOF | EV_ONESHOT, ev.flags,
	    "flags %#x", ev.flags);
	ATF_CHECK_EQ_MSG(NOTE_EXIT, ev.fflags, "fflags %#x", ev.fflags);
	ATF_CHECK_EQ_MSG(W_EXITCODE(4, 0), ev.data, "data %#jx",
	    (uintmax_t)ev.data);
	/* Once. */
	ts.tv_sec = 0;
	ATF_CHECK_EQ(0, kevent(kq, NULL, 0, &ev, 1, &ts));

	memset(&si, 0, sizeof(si));
	ATF_REQUIRE_EQ(1, sigchld_take(WAIT_MS, &si));
	ATF_CHECK_EQ_MSG(pid, si.si_pid, "si_pid %d", (int)si.si_pid);
	ATF_CHECK_EQ_MSG(CLD_EXITED, si.si_code, "si_code %d", si.si_code);
	ATF_CHECK_EQ_MSG(4, si.si_status, "si_status %d", si.si_status);
	status = 0;
	ATF_REQUIRE_EQ_MSG(pid, waitpid(pid, &status, 0), "waitpid: %s",
	    strerror(errno));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 4,
	    "status %#x", status);

	/* Reaped by pid; the descriptor still answers. */
	memset(&sb, 0xff, sizeof(sb));
	ATF_CHECK_EQ(0, fstat(pd, &sb));
	ATF_CHECK_EQ_MSG(S_IFREG, sb.st_mode, "reaped st_mode %#o",
	    (unsigned)sb.st_mode);
	pid2 = -1;
	ATF_CHECK_EQ_MSG(0, pdgetpid(pd, &pid2), "pdgetpid: %s",
	    strerror(errno));
	ATF_CHECK_EQ_MSG(pid, pid2, "pdgetpid gave %d", (int)pid2);
	ATF_CHECK_ERRNO(ECHILD, waitpid(pid, &status, WNOHANG) == -1);
	status = -1;
	ATF_CHECK_EQ_MSG(0, pdwait(pd, &status, WEXITED, NULL, NULL),
	    "pdwait after waitpid: %s", strerror(errno));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 4,
	    "pdwait status %#x", status);

	kq2 = kqueue();
	ATF_REQUIRE(kq2 >= 0);
	EV_SET(&ev, pd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, NULL);
	ATF_CHECK_EQ_MSG(0, kevent(kq2, &ev, 1, NULL, 0, NULL),
	    "second registration: %s", strerror(errno));
	memset(&ev, 0, sizeof(ev));
	ts.tv_sec = 0;
	n = kevent(kq2, NULL, 0, &ev, 1, &ts);
	ATF_CHECK_EQ_MSG(1, n, "fresh registration: %d events", n);
	if (n == 1) {
		ATF_CHECK_EQ_MSG(EV_CLEAR | EV_EOF | EV_ONESHOT, ev.flags,
		    "flags %#x", ev.flags);
		ATF_CHECK_EQ_MSG(NOTE_EXIT, ev.fflags, "fflags %#x",
		    ev.fflags);
		ATF_CHECK_EQ_MSG(W_EXITCODE(4, 0), ev.data, "data %#jx",
		    (uintmax_t)ev.data);
	}

	/* The pid is held by the descriptor, and released by its close. */
	ATF_CHECK_EQ_MSG(SZOMB, proc_stat(pid, NULL), "state %d",
	    proc_stat(pid, NULL));
	ATF_CHECK_EQ(0, close(pd));
	ATF_CHECK_EQ_MSG(-ESRCH, proc_stat(pid, NULL), "state %d",
	    proc_stat(pid, NULL));
	ATF_CHECK_EQ_MSG(0, sigchld_take(0, NULL), "a second SIGCHLD");
	close(kq);
	close(kq2);
	close(go[1]);
}

/*
 * P6.  A forks B with fork(2); an unrelated process C opens B with
 * pdopenpid(2) and sleeps in pdwait(2).  When B exits, A is told and
 * reaps exactly as if C did not exist (one SIGCHLD, one wait4(-1)), C's
 * pdwait returns the same status, and the only trace of C's descriptor
 * is that B's pid cannot be handed out again until C closes it.
 */
struct foreign_rep {
	int	step;		/* 1: opened, 2: pdwait returned, 3: closed */
	int	rv, err, status;
};

ATF_TC(foreign_open_parent_wait);
ATF_TC_HEAD(foreign_open_parent_wait, tc)
{
	/* Two cycles of the pid space, about a minute each; ten times that. */
	atf_tc_set_md_var(tc, "timeout", "1800");
}
ATF_TC_BODY(foreign_open_parent_wait, tc)
{
	struct foreign_rep fr;
	siginfo_t si;
	pid_t b, c, wpid;
	int bgo[2], ccmd[2], crep[2], pd, st, status;
	char ch;

	sigchld_block();
	ATF_REQUIRE_EQ(0, pipe(bgo));
	ATF_REQUIRE_EQ(0, pipe(ccmd));
	ATF_REQUIRE_EQ(0, pipe(crep));

	b = fork();
	ATF_REQUIRE(b != -1);
	if (b == 0) {
		close(bgo[1]);
		close(ccmd[1]);
		close(ccmd[0]);
		close(crep[0]);
		close(crep[1]);
		if (read(bgo[0], &ch, 1) != 1)
			_exit(8);
		_exit(9);
	}
	c = fork();
	ATF_REQUIRE(c != -1);
	if (c == 0) {
		close(bgo[0]);
		close(bgo[1]);
		close(ccmd[1]);
		close(crep[0]);
		memset(&fr, 0, sizeof(fr));
		pd = pdopenpid(b, 0);
		fr.step = 1;
		fr.rv = pd;
		fr.err = pd == -1 ? errno : 0;
		if (write(crep[1], &fr, sizeof(fr)) != sizeof(fr) || pd == -1)
			_exit(11);
		fr.step = 2;
		fr.status = -1;
		fr.rv = pdwait(pd, &fr.status, WEXITED, NULL, NULL);
		fr.err = fr.rv == -1 ? errno : 0;
		if (write(crep[1], &fr, sizeof(fr)) != sizeof(fr))
			_exit(12);
		if (read(ccmd[0], &ch, 1) != 1)
			_exit(13);
		fr.step = 3;
		fr.rv = close(pd);
		fr.err = fr.rv == -1 ? errno : 0;
		if (write(crep[1], &fr, sizeof(fr)) != sizeof(fr))
			_exit(14);
		if (read(ccmd[0], &ch, 1) != 1)
			_exit(15);
		_exit(0);
	}
	close(bgo[0]);
	close(ccmd[0]);
	close(crep[1]);

	ATF_REQUIRE_EQ(sizeof(fr), (size_t)read(crep[0], &fr, sizeof(fr)));
	ATF_REQUIRE_EQ(1, fr.step);
	ATF_REQUIRE_MSG(fr.rv >= 0, "pdopenpid in C: %s", strerror(fr.err));
	/* C is asleep in pdwait before B exits. */
	wait_for_naptime(c, "pdwait");
	ATF_REQUIRE_EQ(0, sigchld_take(0, NULL));

	ch = 'g';
	ATF_REQUIRE_EQ(1, write(bgo[1], &ch, 1));

	/* A: one SIGCHLD, for B. */
	memset(&si, 0, sizeof(si));
	ATF_REQUIRE_MSG(sigchld_take(WAIT_MS, &si) == 1, "no SIGCHLD for B");
	ATF_CHECK_EQ_MSG(b, si.si_pid, "si_pid %d", (int)si.si_pid);
	ATF_CHECK_EQ_MSG(CLD_EXITED, si.si_code, "si_code %d", si.si_code);
	ATF_CHECK_EQ_MSG(9, si.si_status, "si_status %d", si.si_status);

	/* C: its pdwait returns B's status. */
	ATF_REQUIRE_EQ(sizeof(fr), (size_t)read(crep[0], &fr, sizeof(fr)));
	ATF_REQUIRE_EQ(2, fr.step);
	ATF_CHECK_EQ_MSG(0, fr.rv, "pdwait in C: %s", strerror(fr.err));
	ATF_CHECK_MSG(WIFEXITED(fr.status) && WEXITSTATUS(fr.status) == 9,
	    "pdwait status in C %#x", fr.status);

	/* A: C's wait consumed nothing; wait4(-1) returns B, once. */
	ATF_CHECK_EQ(0, sigchld_take(300, NULL));
	status = 0;
	wpid = wait4(-1, &status, WNOHANG, NULL);
	ATF_REQUIRE_EQ_MSG(b, wpid, "wait4(-1) returned %d (%s)", (int)wpid,
	    strerror(errno));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 9,
	    "status %#x", status);
	/* C is alive and still our child: nothing more to report. */
	ATF_CHECK_EQ(0, wait4(-1, &status, WNOHANG, NULL));
	ATF_CHECK_ERRNO(ECHILD, waitpid(b, &status, WNOHANG) == -1);

	/* B is reaped, but C's descriptor keeps the pid. */
	st = proc_stat(b, NULL);
	ATF_CHECK_EQ_MSG(SZOMB, st, "B state %d while C holds it", st);
	ATF_CHECK_EQ_MSG(0, pid_handed_out_child(b),
	    "B's pid was handed out while C held its descriptor");

	ch = 'c';
	ATF_REQUIRE_EQ(1, write(ccmd[1], &ch, 1));
	ATF_REQUIRE_EQ(sizeof(fr), (size_t)read(crep[0], &fr, sizeof(fr)));
	ATF_REQUIRE_EQ(3, fr.step);
	ATF_CHECK_EQ_MSG(0, fr.rv, "close in C: %s", strerror(fr.err));
	st = proc_stat(b, NULL);
	ATF_CHECK_EQ_MSG(-ESRCH, st, "B state %d after C closed", st);
	ATF_CHECK_EQ_MSG(1, pid_handed_out_child(b),
	    "B's pid was not handed out within one cycle after C closed");

	ch = 'x';
	ATF_REQUIRE_EQ(1, write(ccmd[1], &ch, 1));
	ATF_REQUIRE_EQ(c, waitpid(c, &status, 0));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "C status %#x", status);
	close(bgo[1]);
	close(ccmd[1]);
	close(crep[0]);
}

/*
 * P17.  pdfork(PD_NOWAITPID) by a process that is its own child's
 * reaper.  The child has no parent zombie reference, and when its last
 * descriptor closes the "give it to the reaper" step is a no-op because
 * the parent already is the reaper (proc_reparent returns early), so it
 * is left with no zombie reference at all.
 *
 * Variant "exit, then close": the parent is not signalled and cannot
 * wait(2) for the zombie; the close reaps it and frees the pid.
 *
 * Variant "close, then exit": the close kills the child.  The parent is
 * signalled (it is the child's p_pptr and its reaper) but wait(2) finds
 * nothing to reap: the zombie stays, holding its pid, until the parent
 * itself exits.
 * This is a defect (a zombie nobody can reap, also in FreeBSD), recorded
 * as open in the project's issue list (2026-11-11, same entry as the
 * traced sleeper).  The case pins it as found, it does not endorse it:
 * the commit that fixes the defect changes these expectations.
 *
 * Each variant runs in a process of its own that acquires reaper status,
 * so the test program does not become a reaper.
 */
struct nwp_res {
	int	setup;		/* 0, or the step that failed */
	int	sigchld;	/* SIGCHLDs for the child before the close/reap */
	int	si_code, si_status;
	int	wait_any, wait_any_errno;	/* wait4(-1, WNOHANG) */
	int	wait_pid, wait_pid_errno;	/* wait4(pid, WNOHANG) */
	int	stat_mid;	/* child state when the waits ran */
	int	close_rv;
	int	sigchld_late;	/* SIGCHLDs after that */
	int	stat_end;	/* child state at the end */
	int	kill0_errno;	/* kill(pid, 0) at the end */
	int	reused;		/* pid handed out again within a cycle */
};

static void
nwp_waits(pid_t pid, struct nwp_res *r)
{
	int status;

	errno = 0;
	r->wait_any = wait4(-1, &status, WNOHANG, NULL);
	r->wait_any_errno = r->wait_any == -1 ? errno : 0;
	errno = 0;
	r->wait_pid = wait4(pid, &status, WNOHANG, NULL);
	r->wait_pid_errno = r->wait_pid == -1 ? errno : 0;
}

static void
nwp_run(bool close_first, struct nwp_res *r)
{
	struct pollfd pfd;
	siginfo_t si;
	pid_t pid;
	int pd;

	memset(r, 0, sizeof(*r));
	r->setup = 1;
	if (sigchld_setup() != 0)
		return;
	r->setup = 2;
	if (procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL) != 0)
		return;
	r->setup = 3;
	pid = pdfork(&pd, PD_NOWAITPID);
	if (pid == -1)
		return;
	if (pid == 0) {
		if (close_first) {
			for (;;)
				pause();
		}
		_exit(5);
	}
	r->setup = 4;
	if (close_first) {
		/* Running, and in pause(3), when the descriptor closes. */
		if (proc_stat_wait(pid, SSLEEP, 0, WAIT_MS) != SSLEEP)
			return;
		r->close_rv = close(pd);
		r->setup = 5;
		if (proc_stat_wait(pid, SZOMB, -ESRCH, WAIT_MS) == 0)
			return;
		memset(&si, 0, sizeof(si));
		while (sigchld_take(1000, &si) == 1) {
			if (si.si_pid != pid)
				continue;
			r->sigchld++;
			r->si_code = si.si_code;
			r->si_status = si.si_status;
		}
		r->stat_mid = proc_stat(pid, NULL);
		nwp_waits(pid, r);
	} else {
		pfd.fd = pd;
		pfd.events = POLLHUP;
		pfd.revents = 0;
		if (poll(&pfd, 1, 10000) != 1)
			return;
		r->setup = 5;
		if (proc_stat_wait(pid, SZOMB, 0, WAIT_MS) != SZOMB)
			return;
		while (sigchld_take(1000, &si) == 1) {
			if (si.si_pid == pid)
				r->sigchld++;
		}
		r->stat_mid = proc_stat(pid, NULL);
		nwp_waits(pid, r);
		r->close_rv = close(pd);
	}
	while (sigchld_take(300, &si) == 1) {
		if (si.si_pid == pid)
			r->sigchld_late++;
	}
	r->stat_end = proc_stat(pid, NULL);
	errno = 0;
	r->kill0_errno = kill(pid, 0) == -1 ? errno : 0;
	/*
	 * Only where the pid is gone.  A zombie holds its pid by being
	 * there (stat_end, kill0_errno); a whole cycle of the pid space
	 * to see that again proves nothing more and takes minutes on a
	 * slow machine.
	 */
	r->reused = close_first ? -1 : pid_handed_out(pid);
	r->setup = 0;
}

static void
nwp_child(bool close_first, struct nwp_res *r)
{
	pid_t mid;
	int p[2], status;

	ATF_REQUIRE_EQ(0, pipe(p));
	mid = fork();
	ATF_REQUIRE(mid != -1);
	if (mid == 0) {
		close(p[0]);
		nwp_run(close_first, r);
		if (write(p[1], r, sizeof(*r)) != sizeof(*r))
			_exit(1);
		_exit(0);
	}
	close(p[1]);
	ATF_REQUIRE_EQ(sizeof(*r), (size_t)read(p[0], r, sizeof(*r)));
	close(p[0]);
	ATF_REQUIRE_EQ(mid, waitpid(mid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "intermediate status %#x", status);
	ATF_REQUIRE_EQ_MSG(0, r->setup, "scenario stopped at step %d",
	    r->setup);
}

#define	NWP_CHECK(r, field, want)					\
	ATF_CHECK_EQ_MSG((want), (r).field, #field " is %d, expected %d", \
	    (r).field, (want))

ATF_TC(nowaitpid_parent_is_reaper);
ATF_TC_HEAD(nowaitpid_parent_is_reaper, tc)
{
	atf_tc_set_md_var(tc, "descr", "pdfork(PD_NOWAITPID) by the child's "
	    "own reaper; the child exits and then the descriptor closes");
	/* One cycle of the pid space, about a minute; ten times that. */
	atf_tc_set_md_var(tc, "timeout", "1200");
}
ATF_TC_BODY(nowaitpid_parent_is_reaper, tc)
{
	struct nwp_res r;

	nwp_child(false, &r);
	NWP_CHECK(r, sigchld, 0);
	NWP_CHECK(r, stat_mid, SZOMB);
	NWP_CHECK(r, wait_any, -1);
	NWP_CHECK(r, wait_any_errno, ECHILD);
	NWP_CHECK(r, wait_pid, -1);
	NWP_CHECK(r, wait_pid_errno, ECHILD);
	NWP_CHECK(r, close_rv, 0);
	NWP_CHECK(r, sigchld_late, 0);
	NWP_CHECK(r, stat_end, -ESRCH);
	NWP_CHECK(r, kill0_errno, ESRCH);
	NWP_CHECK(r, reused, 1);
}

ATF_TC(nowaitpid_parent_is_reaper_close_first);
ATF_TC_HEAD(nowaitpid_parent_is_reaper_close_first, tc)
{
	atf_tc_set_md_var(tc, "descr", "pdfork(PD_NOWAITPID) by the child's "
	    "own reaper; the descriptor closes while the child runs");
}
ATF_TC_BODY(nowaitpid_parent_is_reaper_close_first, tc)
{
	struct nwp_res r;

	nwp_child(true, &r);
	NWP_CHECK(r, close_rv, 0);
	NWP_CHECK(r, sigchld, 1);
	NWP_CHECK(r, si_code, CLD_KILLED);
	NWP_CHECK(r, si_status, SIGKILL);
	NWP_CHECK(r, stat_mid, SZOMB);
	NWP_CHECK(r, wait_any, -1);
	NWP_CHECK(r, wait_any_errno, ECHILD);
	NWP_CHECK(r, wait_pid, -1);
	NWP_CHECK(r, wait_pid_errno, ECHILD);
	NWP_CHECK(r, sigchld_late, 0);
	NWP_CHECK(r, stat_end, SZOMB);
	NWP_CHECK(r, kill0_errno, 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, pid_recycle);
	ATF_TP_ADD_TC(tp, poll_close_race);
	ATF_TP_ADD_TC(tp, poll_exit_wakeup);

	ATF_TP_ADD_TC(tp, pdopenpid_basic);
	ATF_TP_ADD_TC(tp, pdopenpid_cloexec);
	ATF_TP_ADD_TC(tp, pdopenpid_einval);
	ATF_TP_ADD_TC(tp, pdopenpid_emfile);
	ATF_TP_ADD_TC(tp, pdopenpid_esrch);
	ATF_TP_ADD_TC(tp, pdopenpid_child);
	ATF_TP_ADD_TC(tp, pdopenpid_capmode);
	ATF_TP_ADD_TC(tp, pdopenpid_pdfork_then_open);
	ATF_TP_ADD_TC(tp, pdopenpid_fork_then_open);
	ATF_TP_ADD_TC(tp, pdopenpid_close_one_of_two);
	ATF_TP_ADD_TC(tp, pdopenpid_open_twice);
	ATF_TP_ADD_TC(tp, pdopenpid_pdwait_only_one);
	ATF_TP_ADD_TC(tp, pdopenpid_self);
	ATF_TP_ADD_TC(tp, pdopenpid_exiting);
	ATF_TP_ADD_TC(tp, pdopenpid_no_wakeup);

	ATF_TP_ADD_TC(tp, pddupfd_basic);
	ATF_TP_ADD_TC(tp, close_last_kills);
	ATF_TP_ADD_TC(tp, daemon_close_then_exit);
	ATF_TP_ADD_TC(tp, traced_child_close);
	ATF_TP_ADD_TC(tp, traced_child_close_nowaitpid);
	ATF_TP_ADD_TC(tp, kevent_exit_then_reap);
	ATF_TP_ADD_TC(tp, foreign_open_parent_wait);
	ATF_TP_ADD_TC(tp, nowaitpid_parent_is_reaper);
	ATF_TP_ADD_TC(tp, nowaitpid_parent_is_reaper_close_first);

	return (atf_no_error());
}
