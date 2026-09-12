/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Adversarial pidfd tests: churn (thousands of spawn/pidfd_open/poll/reap
 * cycles), pid reuse safety, pidfd_getfd racing the target closing the
 * descriptor, close() racing a poller, epoll fan-in of hundreds of
 * children with exactly-once exit events, mass SIGKILL through pidfds,
 * zombie/reaped state transitions, and waitid(P_PIDFD) races.  Exit
 * status = failed check number.
 */
#include "linux_test.h"

#define	POLLIN		1
#define	POLLNVAL	0x20
#define	EPOLL_CTL_ADD	1
#define	EPOLLIN		1
#define	EPOLLET		(1u << 31)
#define	NCHILD		200
#define	CHURN		1500
#define	SYS_epoll_ctl_	233

struct pollfd { int fd; short events, revents; };
struct epoll_event { unsigned int events; unsigned long data; } __attribute__((packed));

static int
child_spin(void *arg)
{
	long ms = (long)arg;

	sleep_ms(ms);
	return (3);
}

static long
spawn(int (*fn)(void *), void *arg)
{
	long pid;

	pid = sys0(SYS_fork);
	if (pid == 0)
		(void)sys1(SYS_exit_group, fn(arg) & 0xff);
	return (pid);
}

static int poller_pidfd;
static int poller_result;

static int
poller(void *arg)
{
	struct pollfd pf;
	long r;

	(void)arg;
	pf.fd = poller_pidfd;
	pf.events = POLLIN;
	pf.revents = 0;
	r = sys3(SYS_poll, &pf, 1, 5000);
	/* closed underneath: POLLNVAL, or already-exited: POLLIN */
	poller_result = (r == 1 && (pf.revents & (POLLNVAL | POLLIN)) != 0) ?
	    1 : (int)r;
	return (0);
}

/* Target for pidfd_getfd races: open/close a file in a tight loop. */
static int
churn_fds(void *arg)
{
	long i, fd;

	(void)arg;
	for (i = 0; i < 20000; i++) {
		fd = sys3(SYS_open, "/dev/null", O_RDONLY, 0);
		if (fd >= 0)
			(void)sys1(SYS_close, fd);
	}
	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	struct thread th;
	struct pollfd pf;
	struct epoll_event ev, evs[64];
	long pids[NCHILD], pfds[NCHILD];
	long pid, pidfd, r, i, n, seen;
	int status;
	unsigned char got[NCHILD];

	(void)argc; (void)argv; (void)envp;

	/* 1-3: churn: spawn, pidfd_open, poll to exit, wait, close; 1500x. */
	for (i = 0; i < CHURN; i++) {
		pid = spawn(child_spin, (void *)0);
		if (pid <= 0) return (1);
		pidfd = sys2(SYS_pidfd_open, pid, 0);
		if (pidfd < 0) return (1);
		pf.fd = pidfd; pf.events = POLLIN; pf.revents = 0;
		if (sys3(SYS_poll, &pf, 1, 10000) != 1) return (2);
		/* readiness implies reapable: WNOHANG must find it */
		if (sys4(SYS_wait4, pid, &status, WNOHANG, 0) != pid) return (2);
		if (((status >> 8) & 0xff) != 3) return (2);
		/* after the reap: ESRCH */
		if (sys4(SYS_pidfd_send_signal, pidfd, 0, 0, 0) != -ESRCH)
			return (3);
		(void)sys1(SYS_close, pidfd);
	}
	/* 4: no descriptor leak: the next pidfd number is small. */
	pid = spawn(child_spin, (void *)0);
	pidfd = sys2(SYS_pidfd_open, pid, 0);
	if (pidfd < 0 || pidfd > 32) return (4);
	(void)sys4(SYS_wait4, pid, &status, 0, 0);
	(void)sys1(SYS_close, pidfd);

	/*
	 * 5-7: pid reuse: a pidfd for a reaped process must never come alive
	 * again, even after the pid is handed out to a new process.  Spawn
	 * until the pid is reused (bounded by the pid space; we try 3000).
	 */
	pid = spawn(child_spin, (void *)0);
	pidfd = sys2(SYS_pidfd_open, pid, 0);
	if (pidfd < 0) return (5);
	(void)sys4(SYS_wait4, pid, &status, 0, 0);
	for (i = 0; i < 3000; i++) {
		long np;

		np = spawn(child_spin, (void *)200);
		if (np == pid) {
			/* the stale pidfd must not see the new process */
			if (sys4(SYS_pidfd_send_signal, pidfd, SIGKILL, 0, 0) !=
			    -ESRCH) return (6);
			if (sys3(SYS_pidfd_getfd, pidfd, 0, 0) != -ESRCH)
				return (6);
			pf.fd = pidfd; pf.events = POLLIN; pf.revents = 0;
			if (sys3(SYS_poll, &pf, 1, 0) != 1) return (6);
			/* and the new process is alive (a fresh pidfd works) */
			r = sys2(SYS_pidfd_open, np, 0);
			if (r < 0) return (7);
			if (sys4(SYS_pidfd_send_signal, r, 0, 0, 0) != 0)
				return (7);
			(void)sys1(SYS_close, r);
			(void)sys4(SYS_wait4, np, &status, 0, 0);
			break;
		}
		(void)sys2(SYS_kill, np, SIGKILL);
		(void)sys4(SYS_wait4, np, &status, 0, 0);
	}
	if (i == 3000)
		msg("note: pid not reused within 3000 spawns; reuse check skipped\n");
	(void)sys1(SYS_close, pidfd);

	/* 8-9: pidfd_getfd racing the target's close(): copy or EBADF only. */
	pid = spawn(churn_fds, 0);
	if (pid <= 0) return (8);
	pidfd = sys2(SYS_pidfd_open, pid, 0);
	if (pidfd < 0) return (8);
	for (i = 0; i < 5000; i++) {
		r = sys3(SYS_pidfd_getfd, pidfd, 3, 0);
		if (r >= 0) {
			/* it must be a usable /dev/null */
			char c;

			if (sys3(SYS_read, r, &c, 1) != 0) return (9);
			(void)sys1(SYS_close, r);
		} else if (r != -EBADF && r != -ESRCH) {
			msgnum("pidfd_getfd returned ", r);
			return (9);
		}
	}
	(void)sys2(SYS_kill, pid, SIGKILL);
	(void)sys4(SYS_wait4, pid, &status, 0, 0);
	(void)sys1(SYS_close, pidfd);

	/* 10-11: close(pidfd) while another thread polls it: no hang. */
	pid = spawn(child_spin, (void *)500);
	poller_pidfd = sys2(SYS_pidfd_open, pid, 0);
	if (poller_pidfd < 0) return (10);
	poller_result = -1;
	if (thread_create(&th, poller, 0) != 0) return (10);
	sleep_ms(50);
	(void)sys1(SYS_close, poller_pidfd);
	if (thread_join(&th) != 0) return (11);
	/* either it saw the close (POLLNVAL) or the exit (POLLIN) */
	if (poller_result != 1) { msgnum("poller result ", poller_result); return (11); }
	(void)sys4(SYS_wait4, pid, &status, 0, 0);

	/* 12-15: epoll fan-in: 200 children, exactly one EPOLLET event each. */
	r = sys1(SYS_epoll_create1, 0);
	if (r < 0) return (12);
	for (i = 0; i < NCHILD; i++) {
		pids[i] = spawn(child_spin, (void *)(long)((i * 7) % 50));
		if (pids[i] <= 0) return (12);
		pfds[i] = sys2(SYS_pidfd_open, pids[i], 0);
		if (pfds[i] < 0) return (12);
		ev.events = EPOLLIN | EPOLLET;
		ev.data = i;
		if (sys4(SYS_epoll_ctl_, r, EPOLL_CTL_ADD, pfds[i], &ev) != 0)
			return (13);
	}
	xmemset(got, 0, sizeof(got));
	seen = 0;
	while (seen < NCHILD) {
		n = sys4(SYS_epoll_wait, r, evs, 64, 10000);
		if (n <= 0) { msgnum("epoll_wait ", n); return (14); }
		for (i = 0; i < n; i++) {
			if (evs[i].data >= NCHILD) return (14);
			if (got[evs[i].data]++ != 0) return (15);	/* twice */
			seen++;
			/* readiness => reapable now */
			if (sys4(SYS_wait4, pids[evs[i].data], &status, WNOHANG,
			    0) != pids[evs[i].data]) return (15);
		}
	}
	/* no further events (all edge-triggered, all consumed) */
	if (sys4(SYS_epoll_wait, r, evs, 64, 100) != 0) return (15);
	for (i = 0; i < NCHILD; i++)
		(void)sys1(SYS_close, pfds[i]);
	(void)sys1(SYS_close, r);

	/* 16-18: mass kill through pidfds; every child ends by SIGKILL. */
	for (i = 0; i < NCHILD; i++) {
		pids[i] = spawn(child_spin, (void *)30000);
		if (pids[i] <= 0) return (16);
		pfds[i] = sys2(SYS_pidfd_open, pids[i], 0);
		if (pfds[i] < 0) return (16);
	}
	for (i = 0; i < NCHILD; i++)
		if (sys4(SYS_pidfd_send_signal, pfds[i], SIGKILL, 0, 0) != 0)
			return (17);
	for (i = 0; i < NCHILD; i++) {
		long si[16];

		xmemset(si, 0, sizeof(si));
		if (sys5(SYS_waitid, P_PIDFD, pfds[i], si, WEXITED, 0) != 0)
			return (18);
		/* si_code CLD_KILLED (2) at offset 8, si_status SIGKILL at 24 */
		if (((int *)si)[2] != 2 || ((int *)si)[6] != SIGKILL) return (18);
		(void)sys1(SYS_close, pfds[i]);
	}

	/* 19-21: zombie transitions on one pidfd. */
	pid = spawn(child_spin, (void *)0);
	pidfd = sys2(SYS_pidfd_open, pid, 0);
	pf.fd = pidfd; pf.events = POLLIN; pf.revents = 0;
	if (sys3(SYS_poll, &pf, 1, 5000) != 1) return (19);
	/* zombie: signal 0 succeeds, getfd fails (table gone) */
	if (sys4(SYS_pidfd_send_signal, pidfd, 0, 0, 0) != 0) return (20);
	if (sys3(SYS_pidfd_getfd, pidfd, 0, 0) != -ESRCH) return (20);
	/* waitid(P_PIDFD) twice: second is ECHILD */
	{
		long si[16];

		if (sys5(SYS_waitid, P_PIDFD, pidfd, si, WEXITED, 0) != 0)
			return (21);
		if (sys5(SYS_waitid, P_PIDFD, pidfd, si, WEXITED, 0) != -ECHILD)
			return (21);
	}
	(void)sys1(SYS_close, pidfd);
	/* 22: nothing left behind. */
	if (sys4(SYS_wait4, -1, &status, WNOHANG | __WALL, 0) != -ECHILD)
		return (22);
	return (0);
}
