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

#endif /* !_OES_TEST_JAIL_COMMON_H_ */
