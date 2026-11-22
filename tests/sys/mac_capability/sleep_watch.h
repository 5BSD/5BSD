/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wait, in a test, for one of its own threads to go to sleep in a
 * mac_capability channel wait, without polling.  The kernel tells a process
 * no other way that another thread is asleep; dtrace(1)'s sched:::sleep
 * probe fires as a thread goes to sleep (as tests/sys/vfs does).  Events
 * name the sleeping thread:
 *
 *   'S' tid	a send sleeping for queue room (MAC_CAPABILITY_SEND_F_WAIT,
 *		"mcapsnd");
 *   'R' tid	a receive sleeping for a message (MAC_CAPABILITY_RECV_F_WAIT),
 *		only for a receive whose buffer is `recv_len` bytes, so a
 *		test can wait for one particular receive of several.
 *
 * Events of one thread come out in the order they happened, so a sleep
 * caused after the test acted (a restart after a signal) is the next event
 * read for that thread.  dtraceall must be preloaded (vm-provider.sh does it
 * for the suites that use this): the plane refuses a late kldload.
 */
#ifndef _SLEEP_WATCH_H_
#define	_SLEEP_WATCH_H_

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#define	SLEEP_WATCH_PROG	"/usr/sbin/dtrace"

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

static inline void
sleep_watch_start(struct sleep_watch *w, unsigned recv_len)
{
	char script[1024], self[32], cmd[32], len[32], line[64];
	int p[2];

	snprintf(self, sizeof(self), "%d", (int)getpid());
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
	    "	printf(\"S %%d\\n\", tid); }\n"
	    "sched:::sleep /pid == $1 && $3 != 0 && self->rlen == $3 &&\n"
	    "    stringof(curthread->td_wmesg) == \"mac_capabilityrv\"/ {\n"
	    "	printf(\"R %%d\\n\", tid); }\n",
	    sizeof(void *));
	ATF_REQUIRE_EQ(0, pipe(p));
	w->pid = fork();
	ATF_REQUIRE(w->pid >= 0);
	if (w->pid == 0) {
		if (dup2(p[1], STDOUT_FILENO) < 0)
			_exit(126);
		closefrom(3);
		execl(SLEEP_WATCH_PROG, "dtrace", "-q", "-x", "switchrate=100hz",
		    "-n", script, self, cmd, len, (char *)NULL);
		_exit(127);
	}
	close(p[1]);
	w->out = fdopen(p[0], "r");
	ATF_REQUIRE(w->out != NULL);
	while (fgets(line, sizeof(line), w->out) != NULL)
		if (strcmp(line, "READY\n") == 0)
			return;
	atf_tc_fail("dtrace exited before tracing sched:::sleep");
}

/* Block until thread `tid` next goes to sleep in a wait of `kind`. */
static inline void
sleep_watch_wait(struct sleep_watch *w, char kind, long tid)
{
	char line[64], k;
	long t;

	for (;;) {
		ATF_REQUIRE_MSG(fgets(line, sizeof(line), w->out) != NULL,
		    "dtrace exited before thread %ld slept", tid);
		if (sscanf(line, "%c %ld", &k, &t) == 2 && k == kind &&
		    t == tid)
			return;
	}
}

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

#endif /* !_SLEEP_WATCH_H_ */
