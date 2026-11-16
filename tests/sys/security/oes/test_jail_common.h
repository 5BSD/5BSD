/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * Shared helpers for the OES tests that put subjects in jails.
 */
#ifndef _OES_TEST_JAIL_COMMON_H_
#define _OES_TEST_JAIL_COMMON_H_

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/uio.h>

#include <jail.h>
#include <signal.h>
#include <stdint.h>

#include "test_common.h"

#define JT_MAXJAILS	16

static int jt_jails[JT_MAXJAILS];	/* Creation order */
static int jt_njails;

static inline void
jt_name(char *buf, size_t len, const char *prefix, const char *suffix)
{

	snprintf(buf, len, "%s_%d_%s", prefix, (int)getpid(), suffix);
}

/*
 * Create a persistent jail on the host's root.  A dotted name creates a
 * child of the named parent, whose children.max must be larger than
 * childmax.  jid may be NULL (kernel chooses).  Returns the
 * jid or -1 with a message printed.
 */
static inline int
jt_make_jail(const char *name, const char *hostname, const char *jid,
    const char *childmax)
{
	int id;

	if (jid != NULL)
		id = jail_setv(JAIL_CREATE, "jid", jid, "name", name, "path",
		    "/", "host.hostname", hostname, "children.max", childmax,
		    "persist", NULL, NULL);
	else
		id = jail_setv(JAIL_CREATE, "name", name, "path", "/",
		    "host.hostname", hostname, "children.max", childmax,
		    "persist", NULL, NULL);
	if (id == -1) {
		printf("    jail_setv(%s): %s\n", name, jail_errmsg);
		return (-1);
	}
	if (jt_njails < JT_MAXJAILS)
		jt_jails[jt_njails++] = id;
	return (id);
}

/* Forget a jail the test removed itself. */
static inline void
jt_forget_jail(int jid)
{
	int i;

	for (i = 0; i < jt_njails; i++) {
		if (jt_jails[i] == jid)
			jt_jails[i] = -1;
	}
}

/* Remove every jail still recorded, children (created later) first. */
static inline void
jt_remove_jails(void)
{
	int i;

	for (i = jt_njails - 1; i >= 0; i--) {
		if (jt_jails[i] > 0)
			(void)jail_remove(jt_jails[i]);
	}
	jt_njails = 0;
}

/* Does a jail of this name exist in any state, dying included? */
static inline bool
jt_jail_exists_dying(const char *name)
{

	return (jail_getv(JAIL_DYING, "name", name, NULL) != -1);
}

/*
 * Fork a child that enters the jail (jid -1: stays on the host) and execs
 * /usr/bin/true.  The parent gets the pid; the exit status tells whether the
 * attach and exec worked (0).
 */
static inline pid_t
jt_true_in_jail(int jid)
{
	pid_t pid;

	fflush(NULL);
	pid = fork();
	if (pid != 0)
		return (pid);
	if (jid != -1 && jail_attach(jid) != 0)
		_exit(101);
	execl("/usr/bin/true", "true", (char *)NULL);
	_exit(102);
}

static inline int
jt_reap(pid_t pid)
{
	int status;

	if (pid <= 0)
		return (-1);
	while (waitpid(pid, &status, 0) != pid) {
		if (errno != EINTR)
			return (-1);
	}
	if (WIFEXITED(status))
		return (WEXITSTATUS(status));
	return (256 + WTERMSIG(status));
}

/* Run true in the jail to completion; returns its pid, or -1 on failure. */
static inline pid_t
jt_run_true(int jid)
{
	pid_t pid;
	int rc;

	pid = jt_true_in_jail(jid);
	rc = jt_reap(pid);
	if (rc != 0) {
		printf("    true in jail %d: status %d\n", jid, rc);
		return (-1);
	}
	return (pid);
}

static inline long
jt_elapsed_ms(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return ((now.tv_sec - start->tv_sec) * 1000L +
	    (now.tv_nsec - start->tv_nsec) / 1000000L);
}

/*
 * Wait for an event of the given type from the given process; the whole
 * message, strings included, is left in *out.  Returns 0 or ETIMEDOUT.
 */
static inline int
jt_collect(int fd, pid_t pid, oes_event_type_t event, int timeout_ms,
    test_msg_buf *out)
{
	struct timespec start;
	long left;

	clock_gettime(CLOCK_MONOTONIC, &start);
	while ((left = timeout_ms - jt_elapsed_ms(&start)) > 0) {
		if (test_wait_event(fd, &out->msg, left > 100 ? 100 :
		    (int)left) != 0)
			continue;
		if (out->msg.em_process.ep_pid == pid &&
		    out->msg.em_event == event)
			return (0);
	}
	return (ETIMEDOUT);
}

struct jt_watch {
	pid_t	pid;
	int	seen;		/* Events of that process, any type */
};

/*
 * Read events until `event' of process `stop' arrives, counting the events
 * of every watched process on the way.  Absence is therefore judged against
 * a marker that was generated later, not against a timeout.  Returns 0, or
 * ETIMEDOUT when the marker itself never arrived.
 */
static inline int
jt_scan(int fd, pid_t stop, oes_event_type_t event, int timeout_ms,
    struct jt_watch *watch, int nwatch)
{
	struct timespec start;
	test_msg_buf buf;
	long left;
	int i;

	clock_gettime(CLOCK_MONOTONIC, &start);
	while ((left = timeout_ms - jt_elapsed_ms(&start)) > 0) {
		if (test_wait_event(fd, &buf.msg, left > 100 ? 100 :
		    (int)left) != 0)
			continue;
		for (i = 0; i < nwatch; i++) {
			if (buf.msg.em_process.ep_pid == watch[i].pid)
				watch[i].seen++;
		}
		if (buf.msg.em_process.ep_pid == stop &&
		    buf.msg.em_event == event)
			return (0);
	}
	return (ETIMEDOUT);
}

/* A fresh NOTIFY client subscribed to the given events. */
static inline int
jt_notify_setup(int fd, oes_event_type_t *events, size_t count)
{

	if (test_set_mode(fd, OES_MODE_NOTIFY) != 0)
		return (-1);
	return (test_subscribe(fd, events, count, OES_SUB_REPLACE));
}

static inline int
jt_mute_pid(int fd, pid_t pid)
{
	struct oes_mute_args args;

	/* An explicit token: OES_MUTE_SELF would bypass scope validation. */
	memset(&args, 0, sizeof(args));
	args.emu_token.ept_id = (uint64_t)pid;
	return (ioctl(fd, OES_IOC_MUTE_PROCESS, &args));
}

static inline uint32_t
jt_get_scope(int fd)
{
	struct oes_scope_args args;

	memset(&args, 0xff, sizeof(args));
	if (ioctl(fd, OES_IOC_GET_SCOPE, &args) != 0)
		return (UINT32_MAX);
	return (args.esa_scope);
}

/*
 * Sustained load on the deferred delivery queue.
 *
 * Every pipe read and write is a NOSLEEP event: it is queued for the one
 * delivery thread, which hands a copy to each subscribed client.  A few
 * processes that do nothing but write to and read from a pipe, and enough
 * global clients that subscribe to those events and never read them, keep
 * that queue full for as long as the load runs.  "Full" is observed, not
 * assumed: the kernel counts the events it had to discard at the queue's
 * limit (es_nosleep_drops), and clients are added until that count moves.
 */
#define JT_LOAD_WRITERS		4
#define JT_LOAD_STEP		8
#define JT_LOAD_MAXCLIENTS	48
/*
 * What must end under load is bounded by the kernel in deliveries, two
 * rounds of at most OES_DEFER_MAX (16384) each, not in time.  The load
 * measures how many events the delivery thread gets through in a second
 * and allows four times what that bound then takes, 20 seconds at least.
 */
#define JT_LOAD_BOUND_EVENTS	(2 * 16384)
#define JT_LOAD_MIN_MS		20000

struct jt_load {
	pid_t	writers[JT_LOAD_WRITERS];
	int	clients[JT_LOAD_MAXCLIENTS];
	int	nclients;
	long	rate;		/* Deliveries per second under the load */
	long	limit_ms;	/* Time allowed for the kernel's bound */
};

/* Events the delivery thread has offered to this client, kept or not. */
static inline uint64_t
jt_client_offered(int fd)
{
	struct oes_stats st;

	memset(&st, 0, sizeof(st));
	if (ioctl(fd, OES_IOC_GET_STATS, &st) != 0)
		return (0);
	return (st.es_events_received + st.es_events_dropped);
}

static inline void
jt_load_signal(struct jt_load *l, int sig)
{
	int i;

	for (i = 0; i < JT_LOAD_WRITERS; i++) {
		if (l->writers[i] > 0)
			(void)kill(l->writers[i], sig);
	}
}

static inline uint64_t
jt_nosleep_drops(int fd)
{
	struct oes_stats st;

	memset(&st, 0, sizeof(st));
	if (ioctl(fd, OES_IOC_GET_STATS, &st) != 0)
		return (0);
	return (st.es_nosleep_drops);
}

/*
 * Is the load still keeping the queue full?  Asked after a wait under
 * load and reported, so that a result obtained with a load that fell off
 * can be told from one obtained under it: the kernel discards another
 * event within two seconds.  Not asserted: in an emulated guest that the
 * host leaves short of CPU the delivery thread at times keeps up.
 */
static inline bool
jt_load_still_full(int statfd)
{
	struct timespec start;
	uint64_t drops;

	drops = jt_nosleep_drops(statfd);
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (jt_elapsed_ms(&start) < 2000) {
		usleep(20000);
		if (jt_nosleep_drops(statfd) > drops)
			return (true);
	}
	return (false);
}

static inline void
jt_load_stop(struct jt_load *l)
{
	int i;

	for (i = 0; i < JT_LOAD_WRITERS; i++) {
		if (l->writers[i] > 0) {
			(void)kill(l->writers[i], SIGKILL);
			(void)jt_reap(l->writers[i]);
		}
		l->writers[i] = -1;
	}
	for (i = 0; i < l->nclients; i++)
		close(l->clients[i]);
	l->nclients = 0;
}

/*
 * Start the load and return once the queue is full.  statfd is any OES
 * descriptor of the caller, used to read the statistics.  Returns 0, or -1
 * (load stopped) when the queue could not be filled.
 */
static inline int
jt_load_start(struct jt_load *l, int statfd)
{
	oes_event_type_t evs[] = { OES_EVENT_NOTIFY_PIPE_WRITE,
	    OES_EVENT_NOTIFY_PIPE_READ };
	struct timespec start;
	uint64_t drops, seen;
	pid_t parent;
	int fd, i, n, p[2];
	char c;

	memset(l, 0, sizeof(*l));
	parent = getpid();
	fflush(NULL);
	for (i = 0; i < JT_LOAD_WRITERS; i++) {
		l->writers[i] = fork();
		if (l->writers[i] < 0)
			goto fail;
		if (l->writers[i] == 0) {
			if (pipe(p) != 0)
				_exit(1);
			for (;;) {
				for (n = 0; n < 256; n++) {
					if (write(p[1], "x", 1) != 1 ||
					    read(p[0], &c, 1) != 1)
						_exit(1);
				}
				/* Do not outlive a test that died. */
				if (getppid() != parent)
					_exit(0);
			}
		}
	}
	drops = jt_nosleep_drops(statfd);
	while (l->nclients < JT_LOAD_MAXCLIENTS) {
		for (i = 0; i < JT_LOAD_STEP; i++) {
			fd = test_open_oes();
			if (fd < 0)
				goto fail;
			l->clients[l->nclients++] = fd;
			if (jt_notify_setup(fd, evs, 2) != 0)
				goto fail;
		}
		clock_gettime(CLOCK_MONOTONIC, &start);
		while (jt_elapsed_ms(&start) < 3000) {
			usleep(100000);
			if (jt_nosleep_drops(statfd) > drops)
				goto full;
		}
	}
	printf("    the deferred queue did not fill with %d clients\n",
	    l->nclients);
fail:
	jt_load_stop(l);
	return (-1);
full:
	/* Every delivery is offered to each subscribed client once. */
	seen = jt_client_offered(l->clients[0]);
	clock_gettime(CLOCK_MONOTONIC, &start);
	usleep(1000000);
	l->rate = (long)((jt_client_offered(l->clients[0]) - seen) * 1000 /
	    (uint64_t)jt_elapsed_ms(&start));
	if (l->rate < 1)
		l->rate = 1;
	l->limit_ms = 4L * JT_LOAD_BOUND_EVENTS * 1000 / l->rate;
	if (l->limit_ms < JT_LOAD_MIN_MS)
		l->limit_ms = JT_LOAD_MIN_MS;
	printf("    deferred queue full with %d unread clients; %ld "
	    "deliveries a second; limit %ld ms\n", l->nclients, l->rate,
	    l->limit_ms);
	return (0);
}

#endif /* !_OES_TEST_JAIL_COMMON_H_ */
