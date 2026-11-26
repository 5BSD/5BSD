/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wait, in a test, for one of its own threads to go to sleep in a
 * mac_capability channel wait, without polling.  The kernel tells a process
 * no other way that another thread is asleep; dtrace(1)'s sched:::sleep
 * probe fires as a thread goes to sleep (as tests/sys/vfs does).  Events
 * name the sleeping thread and the sleep's absolute timeout (td_sleeptimo,
 * an sbintime_t; 0 for none):
 *
 *   'S' tid timo	a send sleeping for queue room
 *			(MAC_CAPABILITY_SEND_F_WAIT, "mcapsnd");
 *   'R' tid timo	a receive sleeping for a message
 *			(MAC_CAPABILITY_RECV_F_WAIT, "mac_capabilityrv"), only
 *			for a receive whose buffer is `recv_len` bytes, so a
 *			test can wait for one particular receive of several
 *			(SLEEP_WATCH_ANY_LEN: every receive);
 *   'C' tid timo	a MAC_CAPABILITY_CHANNEL_CALL sleeping for its reply
 *			("mac_capabilitycl").
 *
 * Events of one thread come out in the order they happened, so a sleep
 * caused after the test acted (a restart after a signal) is the next event
 * read for that thread.  dtraceall must be preloaded (vm-provider.sh does it
 * for the suites that use this): the plane refuses a late kldload.
 *
 * A helper thread that reads the watch must not be joined while dtrace may
 * still run: if the sleep it waits for never comes (a regression), the join
 * would hang.  Call sleep_watch_end() first, which makes dtrace print what
 * it has and exit, so the helper reads end of file; then join the helper;
 * then sleep_watch_stop().
 *
 * The same consumer runs other scripts too (sleep_watch_dtrace()), such as
 * one that counts probe firings and prints the count on a marker system
 * call (sleep_watch_count()).
 */
#ifndef _SLEEP_WATCH_H_
#define	_SLEEP_WATCH_H_

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#define	SLEEP_WATCH_PROG	"/usr/sbin/dtrace"
#define	SLEEP_WATCH_ANY_LEN	0xffffffffu
/*
 * getpgid(2) of a process ID above PID_MAX fails with ESRCH and has no
 * other effect: the marker a counting script prints its count on.
 */
#define	SLEEP_WATCH_MARK	0x7ffffff0

struct sleep_watch {
	pid_t	pid;
	FILE	*out;
};

/*
 * The payload length sits right after the payload pointer in
 * struct mac_capability_recvmsg_args.
 */
_Static_assert(__offsetof(struct mac_capability_recvmsg_args, payload_len) ==
    sizeof(void *), "recvmsg payload_len offset");

/*
 * Start dtrace(1) on `script`, whose BEGIN clause prints READY; $1 is this
 * process's ID and $2, $3 the optional arguments (dtrace refuses an
 * argument the script does not reference).  Returns once every probe is
 * enabled.
 */
static inline void
sleep_watch_dtrace(struct sleep_watch *w, const char *script,
    const char *arg2, const char *arg3)
{
	char self[32], line[64];
	int p[2];

	ATF_REQUIRE(arg3 == NULL || arg2 != NULL);
	snprintf(self, sizeof(self), "%d", (int)getpid());
	ATF_REQUIRE_EQ(0, pipe(p));
	w->pid = fork();
	ATF_REQUIRE(w->pid >= 0);
	if (w->pid == 0) {
		if (dup2(p[1], STDOUT_FILENO) < 0)
			_exit(126);
		closefrom(3);
		execl(SLEEP_WATCH_PROG, "dtrace", "-q", "-x", "switchrate=100hz",
		    "-n", script, self, arg2, arg3, (char *)NULL);
		_exit(127);
	}
	close(p[1]);
	w->out = fdopen(p[0], "r");
	ATF_REQUIRE(w->out != NULL);
	while (fgets(line, sizeof(line), w->out) != NULL)
		if (strcmp(line, "READY\n") == 0)
			return;
	atf_tc_fail("dtrace exited before its probes were enabled");
}

static inline void
sleep_watch_start(struct sleep_watch *w, unsigned recv_len)
{
	char script[1536], cmd[32], len[32];

	snprintf(cmd, sizeof(cmd), "%lu",
	    (unsigned long)MAC_CAPABILITY_RECVMSG);
	snprintf(len, sizeof(len), "%u", recv_len);
	snprintf(script, sizeof(script),
	    "BEGIN { printf(\"READY\\n\"); }\n"
	    "syscall::ioctl:entry /pid == $1 && arg1 == $2/ {\n"
	    "	self->rlen = *(uint32_t *)copyin(arg2 + %zu, 4); }\n"
	    "syscall::ioctl:return /pid == $1/ { self->rlen = 0; }\n"
	    "sched:::sleep /pid == $1 &&\n"
	    "    stringof(curthread->td_wmesg) == \"mcapsnd\"/ {\n"
	    "	printf(\"S %%d %%d\\n\", tid, curthread->td_sleeptimo); }\n"
	    "sched:::sleep /pid == $1 && $3 != 0 &&\n"
	    "    ($3 == 0xffffffff || self->rlen == $3) &&\n"
	    "    stringof(curthread->td_wmesg) == \"mac_capabilityrv\"/ {\n"
	    "	printf(\"R %%d %%d\\n\", tid, curthread->td_sleeptimo); }\n"
	    "sched:::sleep /pid == $1 &&\n"
	    "    stringof(curthread->td_wmesg) == \"mac_capabilitycl\"/ {\n"
	    "	printf(\"C %%d %%d\\n\", tid, curthread->td_sleeptimo); }\n",
	    sizeof(void *));
	sleep_watch_dtrace(w, script, cmd, len);
}

/*
 * The next sleep of thread `tid` in a wait of `kind`, with its timeout in
 * *timop (if not NULL).  False once dtrace has exited without one: a helper
 * thread then returns, and the test thread reports the failure.
 */
static inline bool
sleep_watch_next(struct sleep_watch *w, char kind, long tid, int64_t *timop)
{
	char line[64], k;
	long t;
	long long timo;

	while (fgets(line, sizeof(line), w->out) != NULL) {
		timo = 0;
		if (sscanf(line, "%c %ld %lld", &k, &t, &timo) >= 2 &&
		    k == kind && t == tid) {
			if (timop != NULL)
				*timop = timo;
			return (true);
		}
	}
	return (false);
}

/* Block until thread `tid` next goes to sleep in a wait of `kind`. */
static inline void
sleep_watch_wait(struct sleep_watch *w, char kind, long tid)
{

	ATF_REQUIRE_MSG(sleep_watch_next(w, kind, tid, NULL),
	    "dtrace exited before thread %ld slept", tid);
}

/*
 * Make dtrace print what it has and exit, so that a thread reading the
 * watch reads end of file rather than wait for a sleep that will not come.
 * The watch stays open for sleep_watch_stop().
 */
static inline void
sleep_watch_end(struct sleep_watch *w)
{

	if (w->out != NULL)
		(void)kill(w->pid, SIGINT);
}

/* Once no other thread reads the watch (after sleep_watch_end()). */
static inline void
sleep_watch_stop(struct sleep_watch *w)
{
	int status;

	if (w->out == NULL)
		return;
	(void)kill(w->pid, SIGINT);
	fclose(w->out);
	w->out = NULL;
	(void)waitpid(w->pid, &status, 0);
}

/*
 * For a script with a clause on the marker,
 *	syscall::getpgid:entry /pid == $1 && arg0 == <SLEEP_WATCH_MARK>/
 *	    { printf("COUNT %d\n", n); exit(0); }
 * make the marker call and return the count it prints.  dtrace acts on
 * exit() after it has processed every record made before the marker.
 */
static inline long
sleep_watch_count(struct sleep_watch *w)
{
	char line[64];
	long n;
	int status;

	(void)getpgid(SLEEP_WATCH_MARK);
	n = -1;
	while (fgets(line, sizeof(line), w->out) != NULL)
		if (sscanf(line, "COUNT %ld", &n) == 1)
			break;
	fclose(w->out);
	w->out = NULL;
	(void)waitpid(w->pid, &status, 0);
	ATF_REQUIRE_MSG(n >= 0, "dtrace exited without a count");
	return (n);
}

#endif /* !_SLEEP_WATCH_H_ */
