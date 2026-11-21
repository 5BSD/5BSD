/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * OES jail scope: a client limited to one jail, by jid or by name, with or
 * without the jails nested beneath it.
 *
 * Every AUTH client here is jail-scoped to one of the test's own jails, so
 * it can only hold or deny the test's own children, never the rest of the
 * guest.  Absence of an event is always judged against a later event that
 * must arrive, not against a timeout alone.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <pthread.h>

#include "test_jail_common.h"

#define WAIT_MS		10000

static char n_a[64], n_b[80], n_c[96], n_d[112], n_s[64];
static int j_a = -1, j_b = -1, j_c = -1, j_d = -1, j_s = -1;
static char file1[] = "/tmp/oesjs-f1.XXXXXX";
static char file2[] = "/tmp/oesjs-f2.XXXXXX";
static uint64_t ino1, ino2;

/* ------------------------------------------------------------ helpers -- */

static int
set_jail(int fd, int jid, const char *name, uint32_t flags)
{
	struct oes_jail_scope_args args;

	memset(&args, 0, sizeof(args));
	args.ejs_flags = flags;
	args.ejs_jid = jid;
	if (name != NULL) {
		args.ejs_flags |= OES_JAIL_SCOPE_BYNAME;
		strlcpy(args.ejs_name, name, sizeof(args.ejs_name));
	}
	return (ioctl(fd, OES_IOC_SET_JAIL_SCOPE, &args));
}

static int
get_jail(int fd, struct oes_jail_scope_args *args)
{

	memset(args, 0xa5, sizeof(*args));
	return (ioctl(fd, OES_IOC_GET_JAIL_SCOPE, args));
}

static bool
is_dead(int fd)
{
	struct oes_jail_scope_args args;

	return (get_jail(fd, &args) == 0 &&
	    (args.ejs_flags & OES_JAIL_SCOPE_DEAD) != 0);
}

#define EXPECT_ERRNO(_call, _want, _what) do {				\
	int _rc = (_call);						\
	int _e = errno;							\
	ASSERT_MSG(_rc == -1 && _e == (_want),				\
	    "%s: rc %d errno %d (%s), want errno %d", (_what), _rc,	\
	    _rc == -1 ? _e : 0, _rc == -1 ? strerror(_e) : "-", (_want)); \
} while (0)

#define EXPECT_OK(_call, _what) do {					\
	int _rc = (_call);						\
	int _e = errno;							\
	ASSERT_MSG(_rc == 0, "%s: rc %d errno %d (%s)", (_what), _rc,	\
	    _e, strerror(_e));						\
} while (0)

/* A NOTIFY client scoped to a jail by jid; returns the fd or -1. */
static int
jclient(int jid, uint32_t flags, oes_event_type_t *evs, size_t n)
{
	int fd;

	fd = test_open_oes();
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return (-1);
	}
	if (set_jail(fd, jid, NULL, flags) != 0) {
		TEST_FAIL("set jail %d flags 0x%x: %s", jid, flags,
		    strerror(errno));
		close(fd);
		return (-1);
	}
	if (jt_notify_setup(fd, evs, n) != 0) {
		TEST_FAIL("mode/subscribe: %s", strerror(errno));
		close(fd);
		return (-1);
	}
	return (fd);
}

static int
exit_client(int jid, uint32_t flags)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_EXIT;

	return (jclient(jid, flags, &ev, 1));
}

static uint64_t
sysctl_u64(const char *name)
{
	uint64_t v;
	size_t len;

	v = 0;
	len = sizeof(v);
	if (sysctlbyname(name, &v, &len, NULL, 0) != 0)
		return (UINT64_MAX);
	return (v);
}

static int
sysctl_int(const char *name)
{
	size_t len;
	int v;

	v = -1;
	len = sizeof(v);
	if (sysctlbyname(name, &v, &len, NULL, 0) != 0)
		return (-1);
	return (v);
}

static void
get_stats(int fd, struct oes_stats *st)
{

	memset(st, 0, sizeof(*st));
	if (ioctl(fd, OES_IOC_GET_STATS, st) != 0)
		TEST_FAIL("GET_STATS: %s", strerror(errno));
}

/*
 * A child process that enters a jail (-1: stays on the host), tells the
 * parent it is there, optionally waits for a go byte, and runs fn.
 */
struct kid {
	pid_t	pid;
	int	go;		/* Write end, -1 if not held */
};

static int
kid_start(struct kid *k, int jid, int (*fn)(void *), void *arg, bool hold)
{
	int ready[2], go[2];
	char byte;

	k->pid = -1;
	k->go = -1;
	if (pipe(ready) != 0 || pipe(go) != 0)
		return (-1);
	fflush(NULL);
	k->pid = fork();
	if (k->pid < 0)
		return (-1);
	if (k->pid == 0) {
		close(ready[0]);
		close(go[1]);
		if (jid != -1 && jail_attach(jid) != 0)
			_exit(101);
		if (write(ready[1], "R", 1) != 1)
			_exit(102);
		close(ready[1]);
		if (hold && read(go[0], &byte, 1) != 1)
			_exit(103);
		close(go[0]);
		_exit(fn(arg));
	}
	close(ready[1]);
	close(go[0]);
	if (read(ready[0], &byte, 1) != 1) {
		close(ready[0]);
		close(go[1]);
		printf("    child for jail %d did not start: status %d\n", jid,
		    jt_reap(k->pid));
		k->pid = -1;
		return (-1);
	}
	close(ready[0]);
	if (hold)
		k->go = go[1];
	else
		close(go[1]);
	return (0);
}

static void
kid_go(struct kid *k)
{

	if (k->go != -1) {
		(void)write(k->go, "G", 1);
		close(k->go);
		k->go = -1;
	}
}

static int
kid_finish(struct kid *k)
{

	kid_go(k);
	return (jt_reap(k->pid));
}

static void
kid_kill(struct kid *k)
{

	if (k->pid > 0) {
		(void)kill(k->pid, SIGKILL);
		(void)jt_reap(k->pid);
	}
	if (k->go != -1)
		close(k->go);
	k->pid = -1;
	k->go = -1;
}

static int
fn_pause(void *arg __unused)
{

	(void)signal(SIGUSR1, SIG_IGN);
	for (;;)
		pause();
}

struct open_arg {
	const char	*path;
	int		count;
	int		oflags;
};

/* Exit status: 0, or 50 for EACCES, or 51 for any other failure. */
static int
fn_open(void *arg)
{
	struct open_arg *oa = arg;
	int fd, i;

	for (i = 0; i < oa->count; i++) {
		fd = open(oa->path, oa->oflags | O_CLOEXEC);
		if (fd < 0)
			return (errno == EACCES ? 50 : 51);
		close(fd);
	}
	return (0);
}

static int
fn_kill_usr1(void *arg)
{

	return (kill(*(pid_t *)arg, SIGUSR1) == 0 ? 0 : 60);
}

static int	fn_append(void *arg);

/* What one process was seen doing. */
struct rec {
	pid_t	pid;
	int	open1;		/* NOTIFY_OPEN of file1 */
	int	open2;		/* NOTIFY_OPEN of file2 */
	int	exits;
	int	signals;	/* NOTIFY_SIGNAL sent by pid */
	pid_t	sigtarget;	/* Target of the last one */
	int	sigtarget_jid;
	int	subject_jid;	/* ep_jid of the last event */
	int	other;
};

static void
rec_note(struct rec *r, const oes_message_t *msg)
{

	if (msg->em_process.ep_pid != r->pid)
		return;
	r->subject_jid = msg->em_process.ep_jid;
	switch (msg->em_event) {
	case OES_EVENT_NOTIFY_OPEN:
		if (msg->em_event_data.open.file.ef_token.eft_id == ino1)
			r->open1++;
		else if (msg->em_event_data.open.file.ef_token.eft_id == ino2)
			r->open2++;
		else
			r->other++;
		break;
	case OES_EVENT_NOTIFY_EXIT:
		r->exits++;
		break;
	case OES_EVENT_NOTIFY_SIGNAL:
		r->signals++;
		r->sigtarget = msg->em_event_data.signal.target.ep_pid;
		r->sigtarget_jid = msg->em_event_data.signal.target.ep_jid;
		break;
	default:
		r->other++;
		break;
	}
}

/*
 * Read until `event' of process `stop' arrives, noting what the recorded
 * processes did on the way.  0, or ETIMEDOUT if the stop event never came.
 */
static int
scan(int fd, pid_t stop, oes_event_type_t event, struct rec *recs, int nrec)
{
	struct timespec start;
	test_msg_buf buf;
	long left;
	int i;

	clock_gettime(CLOCK_MONOTONIC, &start);
	while ((left = WAIT_MS - jt_elapsed_ms(&start)) > 0) {
		if (test_wait_event(fd, &buf.msg, left > 100 ? 100 :
		    (int)left) != 0)
			continue;
		for (i = 0; i < nrec; i++)
			rec_note(&recs[i], &buf.msg);
		if (buf.msg.em_process.ep_pid == stop &&
		    buf.msg.em_event == event)
			return (0);
	}
	return (ETIMEDOUT);
}

/*
 * Run true once in each listed jail (-1: the host), then once more in
 * marker_jid, which the client must cover; check which exits were seen.
 */
static void
membership(int fd, const char *what, const int *jids, const bool *expect,
    int n, int marker_jid)
{
	struct rec recs[8];
	pid_t marker;
	int i;

	if (fd < 0)
		return;
	memset(recs, 0, sizeof(recs));
	for (i = 0; i < n; i++) {
		recs[i].pid = jt_run_true(jids[i]);
		if (recs[i].pid <= 0) {
			TEST_FAIL("%s: cannot run in jail %d", what, jids[i]);
			return;
		}
	}
	marker = jt_run_true(marker_jid);
	if (marker <= 0 ||
	    scan(fd, marker, OES_EVENT_NOTIFY_EXIT, recs, n) != 0) {
		TEST_FAIL("%s: marker exit (jail %d) not delivered", what,
		    marker_jid);
		return;
	}
	for (i = 0; i < n; i++) {
		ASSERT_MSG((recs[i].exits == 1) == expect[i] &&
		    recs[i].exits <= 1,
		    "%s: process in jail %d: %d exit events, expected %s",
		    what, jids[i], recs[i].exits, expect[i] ? "one" : "none");
	}
}

/*
 * Read a dead or dying client to end of file with plain read(2) calls.
 * Counts the exit events of pid.  0 at end of file, ETIMEDOUT otherwise.
 * The descriptor must not have been read through test_wait_event().
 */
static int
read_to_eof_ms(int fd, pid_t pid, int *exits, int *events, long limit_ms)
{
	static uint8_t buf[OES_MSG_MAX_SIZE * 4];
	struct timespec start;
	struct pollfd pfd;
	const oes_message_t *msg;
	ssize_t n;
	size_t off;

	*exits = *events = 0;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (jt_elapsed_ms(&start) < limit_ms) {
		pfd.fd = fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 100) <= 0)
			continue;
		n = read(fd, buf, sizeof(buf));
		if (n == 0)
			return (0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return (errno);
		}
		for (off = 0; off + sizeof(*msg) <= (size_t)n;
		    off += msg->em_size) {
			msg = (const oes_message_t *)(const void *)(buf + off);
			if (msg->em_size < sizeof(*msg))
				return (EPROTO);
			(*events)++;
			if (msg->em_event == OES_EVENT_NOTIFY_EXIT &&
			    msg->em_process.ep_pid == pid)
				(*exits)++;
		}
	}
	return (ETIMEDOUT);
}

static int
read_to_eof(int fd, pid_t pid, int *exits, int *events)
{

	return (read_to_eof_ms(fd, pid, exits, events, WAIT_MS));
}

static bool
wait_jail_gone(const char *name)
{
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);
	while (jt_elapsed_ms(&start) < WAIT_MS) {
		if (!jt_jail_exists_dying(name))
			return (true);
		usleep(50000);
	}
	return (false);
}

static void
remove_jail(int jid)
{

	if (jail_remove(jid) != 0)
		TEST_FAIL("jail_remove(%d): %s", jid, strerror(errno));
	jt_forget_jail(jid);
}

static int
scratch_jail(const char *suffix, char *name, size_t len, const char *jid)
{

	jt_name(name, len, "oesjs", suffix);
	return (jt_make_jail(name, "oesjs-scratch", jid, "4"));
}

/* ------------------------------------------- arguments and ordering -- */

static void
test_arguments(void)
{
	struct oes_jail_scope_args args;
	oes_event_type_t ev = OES_EVENT_NOTIFY_EXEC;
	struct oes_event_deadline_args da;
	struct oes_mode_args mode;
	int fd;

	TEST_BEGIN("T-ARG malformed arguments are EINVAL, unknown jails ENOENT");
	fd = test_open_oes();
	EXPECT_ERRNO(set_jail(fd, j_a, NULL, 0x8), EINVAL, "flag 0x8");
	EXPECT_ERRNO(set_jail(fd, j_a, NULL, OES_JAIL_SCOPE_DEAD), EINVAL,
	    "DEAD flag");
	EXPECT_ERRNO(set_jail(fd, j_a, NULL, OES_JAIL_SCOPE_BYNAME), EINVAL,
	    "BYNAME with a jid and no name");
	EXPECT_ERRNO(set_jail(fd, 1, n_a, 0), EINVAL, "BYNAME with a jid");
	EXPECT_ERRNO(set_jail(fd, 0, "", 0), EINVAL, "empty name");
	memset(&args, 'x', sizeof(args));
	args.ejs_flags = OES_JAIL_SCOPE_BYNAME;
	args.ejs_jid = 0;
	EXPECT_ERRNO(ioctl(fd, OES_IOC_SET_JAIL_SCOPE, &args), EINVAL,
	    "unterminated name");
	EXPECT_ERRNO(set_jail(fd, -1, NULL, 0), EINVAL, "negative jid");
	memset(&args, 0, sizeof(args));
	args.ejs_jid = j_a;
	args.ejs_name[0] = 'x';
	EXPECT_ERRNO(ioctl(fd, OES_IOC_SET_JAIL_SCOPE, &args), EINVAL,
	    "jid with a name");
	memset(&args, 0, sizeof(args));
	args.ejs_jid = j_a;
	args.ejs_name[200] = 'x';
	EXPECT_ERRNO(ioctl(fd, OES_IOC_SET_JAIL_SCOPE, &args), EINVAL,
	    "jid with stray name bytes");
	EXPECT_ERRNO(set_jail(fd, 999999, NULL, 0), ENOENT, "unused jid");
	EXPECT_ERRNO(set_jail(fd, 0, "oesjs_none", 0), ENOENT, "unused name");
	ASSERT_MSG(jt_get_scope(fd) == OES_SCOPE_GLOBAL, "scope changed");
	TEST_BEGIN("T-GET-1 no jail scope: GET is ENOENT");
	EXPECT_ERRNO(get_jail(fd, &args), ENOENT, "GET on a global client");
	close(fd);

	TEST_BEGIN("T-ORD order of configuration and errno precedence");
	fd = test_open_oes();
	EXPECT_OK(test_set_mode(fd, OES_MODE_NOTIFY), "set mode");
	EXPECT_ERRNO(set_jail(fd, j_a, NULL, 0), EBUSY, "after mode");
	EXPECT_ERRNO(set_jail(fd, j_a, NULL, 0x8), EINVAL,
	    "EINVAL before EBUSY");
	EXPECT_ERRNO(set_jail(fd, 999999, NULL, 0), EBUSY,
	    "EBUSY before ENOENT");
	close(fd);
	fd = test_open_oes();
	EXPECT_OK(test_subscribe(fd, &ev, 1, OES_SUB_ADD), "subscribe");
	EXPECT_ERRNO(set_jail(fd, j_a, NULL, 0), EBUSY, "after subscribe");
	close(fd);
	fd = test_open_oes();
	EXPECT_OK(set_jail(fd, j_a, NULL, 0), "first set");
	EXPECT_ERRNO(set_jail(fd, j_a, NULL, 0), EPERM, "second set");
	EXPECT_ERRNO(set_jail(fd, 999999, NULL, 0), EPERM,
	    "EPERM before ENOENT");
	EXPECT_ERRNO(test_set_descendants_scope(fd), EPERM,
	    "descendants after jail");
	ASSERT_MSG(jt_get_scope(fd) == OES_SCOPE_JAIL, "GET_SCOPE %u",
	    jt_get_scope(fd));
	memset(&args, 0, sizeof(args));
	args.ejs_flags = 2;	/* The old ioctl must not accept the new value. */
	{
		struct oes_scope_args sa = { .esa_scope = OES_SCOPE_JAIL };

		EXPECT_ERRNO(ioctl(fd, OES_IOC_SET_SCOPE, &sa), EINVAL,
		    "SET_SCOPE(2)");
	}

	TEST_BEGIN("T-MIN-1 deadline floors stay descendants-only");
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	EXPECT_OK(ioctl(fd, OES_IOC_SET_MODE, &mode), "AUTH mode");
	memset(&da, 0, sizeof(da));
	da.oeda_event = OES_EVENT_AUTH_OPEN;
	da.oeda_milliseconds = 2000;
	EXPECT_ERRNO(ioctl(fd, OES_IOC_SET_DEADLINE_MIN, &da), EPERM,
	    "SET_DEADLINE_MIN");
	close(fd);

	TEST_BEGIN("T-GET what the scope reports");
	fd = test_open_oes();
	EXPECT_OK(set_jail(fd, j_a, NULL, OES_JAIL_SCOPE_NOCHILDREN),
	    "set by jid");
	EXPECT_OK(get_jail(fd, &args), "GET");
	ASSERT_MSG(args.ejs_flags == OES_JAIL_SCOPE_NOCHILDREN &&
	    args.ejs_jid == j_a && strcmp(args.ejs_name, n_a) == 0,
	    "flags 0x%x jid %d name '%s'", args.ejs_flags, args.ejs_jid,
	    args.ejs_name);
	close(fd);
	fd = test_open_oes();
	EXPECT_OK(set_jail(fd, 0, n_b, 0), "set by name");
	EXPECT_OK(get_jail(fd, &args), "GET");
	ASSERT_MSG(args.ejs_flags == 0 && args.ejs_jid == j_b &&
	    strcmp(args.ejs_name, n_b) == 0, "flags 0x%x jid %d name '%s'",
	    args.ejs_flags, args.ejs_jid, args.ejs_name);
	close(fd);
	fd = test_open_oes();
	EXPECT_OK(set_jail(fd, 0, NULL, 0), "set jid 0");
	EXPECT_OK(get_jail(fd, &args), "GET");
	ASSERT_MSG(args.ejs_flags == 0 && args.ejs_jid == 0 &&
	    strcmp(args.ejs_name, "0") == 0, "flags 0x%x jid %d name '%s'",
	    args.ejs_flags, args.ejs_jid, args.ejs_name);
	close(fd);
	fd = test_open_oes();
	EXPECT_OK(test_set_descendants_scope(fd), "descendants");
	EXPECT_ERRNO(set_jail(fd, j_a, NULL, 0), EPERM, "jail after descendants");
	EXPECT_ERRNO(set_jail(fd, 999999, NULL, 0), EPERM,
	    "EPERM before ENOENT (descendants)");
	EXPECT_ERRNO(get_jail(fd, &args), ENOENT, "GET on descendants");
	close(fd);
}

/*
 * A descriptor handed to a third party is limited to
 * OES_IOCTLS_THIRD_PARTY_INIT.  Its holder must be able to ask whether a
 * jail scope is dead, the only way to tell the end of a scope from other
 * failures, and must not be able to set one.
 */
static void
test_third_party_ioctls(void)
{
	static const cap_ioctl_t allowed[] = OES_IOCTLS_THIRD_PARTY_INIT;
	struct oes_jail_scope_args args;
	int fd;

	TEST_BEGIN("T-CAP the third-party ioctl set can read a jail scope");
	fd = test_open_oes();
	EXPECT_OK(cap_ioctls_limit(fd, allowed, nitems(allowed)),
	    "cap_ioctls_limit");
	EXPECT_ERRNO(get_jail(fd, &args), ENOENT, "GET, no jail scope");
	EXPECT_ERRNO(set_jail(fd, j_a, NULL, 0), ENOTCAPABLE,
	    "SET through the limited descriptor");
	close(fd);

	fd = test_open_oes();
	EXPECT_OK(set_jail(fd, j_a, NULL, 0), "set");
	EXPECT_OK(cap_ioctls_limit(fd, allowed, nitems(allowed)),
	    "cap_ioctls_limit");
	EXPECT_OK(get_jail(fd, &args), "GET through the limited descriptor");
	ASSERT_MSG(args.ejs_jid == j_a && args.ejs_flags == 0,
	    "GET: jid %d flags 0x%x", args.ejs_jid, args.ejs_flags);
	ASSERT_MSG(jt_get_scope(fd) == OES_SCOPE_JAIL, "GET_SCOPE");
	close(fd);
}

/* ---------------------------------------------------------- membership -- */

static void
test_membership(void)
{
	static const bool t = true, f = false;
	int fd, fd2;

	TEST_BEGIN("T-JID-1 by jid: the jail, not the host, not a sibling");
	fd = exit_client(j_a, 0);
	membership(fd, "T-JID-1", (int[]){ j_a, -1, j_s },
	    (bool[]){ t, f, f }, 3, j_a);
	TEST_BEGIN("T-NEST-1 nested jails, three levels down");
	membership(fd, "T-NEST-1", (int[]){ j_b, j_c, j_d },
	    (bool[]){ t, t, t }, 3, j_a);
	close(fd);

	TEST_BEGIN("T-NEST-2 a nested jail is identified in the record");
	fd = jclient(j_a, 0, &(oes_event_type_t){ OES_EVENT_NOTIFY_EXEC }, 1);
	if (fd >= 0) {
		test_msg_buf buf;
		const oes_process_t *tp = &buf.msg.em_event_data.exec.target;
		pid_t pid = jt_run_true(j_c);

		/* The exec target is filled with the process locked. */
		if (jt_collect(fd, pid, OES_EVENT_NOTIFY_EXEC, WAIT_MS, &buf) != 0)
			TEST_FAIL("exec in the nested jail not delivered");
		else
			ASSERT_MSG(tp->ep_jid == j_c && (tp->ep_meta_flags &
			    OES_PROC_META_JAIL_FULLNAME) != 0 &&
			    strcmp(oes_msg_string(&buf.msg,
			    tp->ep_jail_fullname_off), n_c) == 0,
			    "jid %d (want %d) fullname '%s'", tp->ep_jid, j_c,
			    oes_msg_string(&buf.msg, tp->ep_jail_fullname_off));
		close(fd);
	}

	TEST_BEGIN("T-NAME-1 by name");
	fd = test_open_oes();
	EXPECT_OK(set_jail(fd, 0, n_a, 0), "set by name");
	EXPECT_OK(jt_notify_setup(fd, &(oes_event_type_t){
	    OES_EVENT_NOTIFY_EXIT }, 1), "setup");
	membership(fd, "T-NAME-1", (int[]){ j_a, -1, j_s, j_c },
	    (bool[]){ t, f, f, t }, 4, j_a);
	close(fd);

	TEST_BEGIN("T-NOCH-1 NOCHILDREN: the jail only");
	fd = exit_client(j_a, OES_JAIL_SCOPE_NOCHILDREN);
	membership(fd, "T-NOCH-1", (int[]){ j_a, j_b, j_d, -1 },
	    (bool[]){ t, f, f, f }, 4, j_a);
	close(fd);

	TEST_BEGIN("T-NOCH-2 NOCHILDREN on a middle jail");
	fd = exit_client(j_b, OES_JAIL_SCOPE_NOCHILDREN);
	membership(fd, "T-NOCH-2", (int[]){ j_a, j_b, j_c },
	    (bool[]){ f, t, f }, 3, j_b);
	close(fd);

	TEST_BEGIN("T-MID-1 a middle jail and what is beneath it");
	fd = exit_client(j_b, 0);
	membership(fd, "T-MID-1", (int[]){ j_a, j_b, j_d, j_s },
	    (bool[]){ f, t, t, f }, 4, j_b);
	close(fd);

	TEST_BEGIN("T-HOST-1 jid 0 from the host, NOCHILDREN: host only");
	fd = exit_client(0, OES_JAIL_SCOPE_NOCHILDREN);
	membership(fd, "T-HOST-1", (int[]){ -1, j_a, j_d },
	    (bool[]){ t, f, f }, 3, -1);
	close(fd);

	TEST_BEGIN("T-HOST-2 jid 0 from the host: everything");
	fd = exit_client(0, 0);
	membership(fd, "T-HOST-2", (int[]){ -1, j_b }, (bool[]){ t, t }, 2,
	    j_a);
	close(fd);

	TEST_BEGIN("T-MULTI two scopes at once each see their own jail");
	fd = exit_client(j_a, OES_JAIL_SCOPE_NOCHILDREN);
	fd2 = exit_client(j_s, 0);
	membership(fd, "T-MULTI a", (int[]){ j_a, j_s }, (bool[]){ t, f }, 2,
	    j_a);
	membership(fd2, "T-MULTI s", (int[]){ j_s, j_a }, (bool[]){ t, f }, 2,
	    j_s);
	close(fd);
	close(fd2);

	TEST_BEGIN("T-PERSIST-1 an empty persistent jail: quiet, not dead");
	fd = exit_client(j_s, 0);
	if (fd >= 0) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };

		ASSERT_MSG(poll(&pfd, 1, 1000) == 0, "poll revents 0x%x",
		    pfd.revents);
		ASSERT_MSG(!is_dead(fd), "scope dead");
		membership(fd, "T-PERSIST-1", (int[]){ j_s }, (bool[]){ t }, 1,
		    j_s);
		close(fd);
	}
}

/* PASSIVE mode: AUTH subscriptions arrive as notifications, in scope only. */
static void
test_passive(void)
{
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	struct open_arg oa = { file1, 1, O_RDONLY };
	struct oes_mode_args mode;
	struct rec recs[2];
	struct kid h, j;
	int fd;

	TEST_BEGIN("T-PASSIVE a passive client is scoped like any other");
	fd = test_open_oes();
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_PASSIVE;
	if (fd < 0 || set_jail(fd, j_a, NULL, 0) != 0 ||
	    ioctl(fd, OES_IOC_SET_MODE, &mode) != 0 ||
	    test_subscribe(fd, &ev, 1, OES_SUB_REPLACE) != 0) {
		TEST_FAIL("passive client: %s", strerror(errno));
		return;
	}
	if (kid_start(&h, -1, fn_open, &oa, false) != 0 ||
	    kid_finish(&h) != 0 ||
	    kid_start(&j, j_a, fn_open, &oa, false) != 0 ||
	    kid_finish(&j) != 0) {
		TEST_FAIL("openers");
		close(fd);
		return;
	}
	memset(recs, 0, sizeof(recs));
	recs[0].pid = h.pid;
	recs[1].pid = j.pid;
	if (scan(fd, j.pid, OES_EVENT_NOTIFY_OPEN, recs, 2) != 0)
		TEST_FAIL("jailed open not delivered");
	ASSERT_MSG(recs[1].open1 == 1, "jailed opens delivered: %d",
	    recs[1].open1);
	ASSERT_MSG(recs[0].open1 == 0 && recs[0].other == 0,
	    "outside open was delivered");
	close(fd);
}

/* Opens file1, enters jail(s), opens file2. */
struct enter_arg {
	int	first;		/* Jail entered before file1, or -1 */
	int	second;		/* Jail entered between the opens */
};

static int
fn_enter(void *arg)
{
	struct enter_arg *ea = arg;
	int fd;

	if (ea->first != -1 && jail_attach(ea->first) != 0)
		return (70);
	fd = open(file1, O_RDONLY);
	if (fd < 0)
		return (71);
	close(fd);
	if (jail_attach(ea->second) != 0)
		return (72);
	fd = open(file2, O_RDONLY);
	if (fd < 0)
		return (73);
	close(fd);
	return (0);
}

static void
test_entering(void)
{
	oes_event_type_t evs[] = { OES_EVENT_NOTIFY_OPEN,
	    OES_EVENT_NOTIFY_EXIT };
	struct enter_arg ea;
	struct rec r;
	struct kid k;
	pid_t ma, mb;
	int x, y, z, rc;

	TEST_BEGIN("T-ENTER-1 a process is covered from when it enters");
	x = jclient(j_a, 0, evs, 2);
	ea.first = -1;
	ea.second = j_a;
	if (x >= 0 && kid_start(&k, -1, fn_enter, &ea, false) == 0) {
		rc = kid_finish(&k);
		ASSERT_MSG(rc == 0, "entering child status %d", rc);
		memset(&r, 0, sizeof(r));
		r.pid = k.pid;
		if (scan(x, k.pid, OES_EVENT_NOTIFY_EXIT, &r, 1) != 0)
			TEST_FAIL("exit of the entrant not delivered");
		ASSERT_MSG(r.open1 == 0, "open before entering was delivered");
		ASSERT_MSG(r.open2 == 1, "open after entering: %d events",
		    r.open2);
	}
	if (x >= 0)
		close(x);

	TEST_BEGIN("T-DEEPER-1 a process moving into a nested jail");
	x = jclient(j_a, 0, evs, 2);
	y = jclient(j_a, OES_JAIL_SCOPE_NOCHILDREN, evs, 2);
	z = jclient(j_b, 0, evs, 2);
	ea.first = j_a;
	ea.second = j_b;
	if (x >= 0 && y >= 0 && z >= 0 &&
	    kid_start(&k, -1, fn_enter, &ea, false) == 0) {
		rc = kid_finish(&k);
		ASSERT_MSG(rc == 0, "moving child status %d", rc);
		ma = jt_run_true(j_a);
		mb = jt_run_true(j_b);

		memset(&r, 0, sizeof(r));
		r.pid = k.pid;
		if (scan(x, mb, OES_EVENT_NOTIFY_EXIT, &r, 1) != 0)
			TEST_FAIL("X: marker not delivered");
		ASSERT_MSG(r.open1 == 1 && r.open2 == 1 && r.exits == 1,
		    "X (A and below): open1 %d open2 %d exits %d", r.open1,
		    r.open2, r.exits);

		memset(&r, 0, sizeof(r));
		r.pid = k.pid;
		if (scan(y, ma, OES_EVENT_NOTIFY_EXIT, &r, 1) != 0)
			TEST_FAIL("Y: marker not delivered");
		ASSERT_MSG(r.open1 == 1 && r.open2 == 0 && r.exits == 0,
		    "Y (A only): open1 %d open2 %d exits %d", r.open1,
		    r.open2, r.exits);

		memset(&r, 0, sizeof(r));
		r.pid = k.pid;
		if (scan(z, mb, OES_EVENT_NOTIFY_EXIT, &r, 1) != 0)
			TEST_FAIL("Z: marker not delivered");
		ASSERT_MSG(r.open1 == 0 && r.open2 == 1 && r.exits == 1,
		    "Z (A.b): open1 %d open2 %d exits %d", r.open1, r.open2,
		    r.exits);
	}
	if (x >= 0)
		close(x);
	if (y >= 0)
		close(y);
	if (z >= 0)
		close(z);
}

static void
test_rename_jail(void)
{
	struct oes_jail_scope_args args;
	char newname[64], jidstr[16];
	int fd, fd2;

	TEST_BEGIN("T-RENAME-1 renaming the jail does not move the scope");
	fd = test_open_oes();
	EXPECT_OK(set_jail(fd, 0, n_s, 0), "set by name");
	EXPECT_OK(jt_notify_setup(fd, &(oes_event_type_t){
	    OES_EVENT_NOTIFY_EXIT }, 1), "setup");
	jt_name(newname, sizeof(newname), "oesjs", "renamed");
	snprintf(jidstr, sizeof(jidstr), "%d", j_s);
	if (jail_setv(JAIL_UPDATE, "jid", jidstr, "name", newname, NULL) ==
	    -1) {
		TEST_FAIL("rename: %s", jail_errmsg);
		close(fd);
		return;
	}
	membership(fd, "T-RENAME-1", (int[]){ j_s, j_a },
	    (bool[]){ true, false }, 2, j_s);
	EXPECT_OK(get_jail(fd, &args), "GET");
	ASSERT_MSG(strcmp(args.ejs_name, n_s) == 0 && args.ejs_jid == j_s,
	    "GET after rename: jid %d name '%s'", args.ejs_jid, args.ejs_name);
	fd2 = test_open_oes();
	EXPECT_ERRNO(set_jail(fd2, 0, n_s, 0), ENOENT, "old name");
	EXPECT_OK(set_jail(fd2, 0, newname, 0), "new name");
	close(fd2);
	close(fd);
	if (jail_setv(JAIL_UPDATE, "jid", jidstr, "name", n_s, NULL) == -1)
		TEST_FAIL("rename back: %s", jail_errmsg);
}

static void
test_linux(void)
{
	static const char touch[] = "/compat/linux/usr/bin/touch";
	char target[] = "/tmp/oesjs-linux.XXXXXX";
	struct rec recs[2];
	test_msg_buf buf;
	pid_t pid, marker;
	int fd, i, tfd;

	TEST_BEGIN("T-LINUX-1 a Linux process in the jail");
	if (access(touch, X_OK) != 0) {
		TEST_SKIP("NOT COVERED: no %s in this guest", touch);
		return;
	}
	tfd = mkstemp(target);
	if (tfd >= 0)
		close(tfd);
	fd = exit_client(j_a, 0);
	if (fd < 0)
		return;
	memset(recs, 0, sizeof(recs));
	for (i = 0; i < 2; i++) {
		fflush(NULL);
		pid = fork();
		if (pid == 0) {
			if (i == 0 && jail_attach(j_a) != 0)
				_exit(101);
			execl(touch, "touch", target, (char *)NULL);
			_exit(102);
		}
		recs[i].pid = pid;
		if (jt_reap(pid) != 0) {
			TEST_SKIP("NOT COVERED: Linux touch does not run here");
			close(fd);
			unlink(target);
			return;
		}
	}
	/* Jailed one first: find its exit and look at the ABI. */
	if (jt_collect(fd, recs[0].pid, OES_EVENT_NOTIFY_EXIT, WAIT_MS,
	    &buf) != 0)
		TEST_FAIL("exit of the jailed Linux process not delivered");
	else {
		/* A subject whose lock was busy is recorded without details. */
		if (buf.msg.em_process.ep_start_sec == 0)
			printf("    exit record without process details\n");
		else {
			ASSERT_MSG(buf.msg.em_process.ep_abi == EP_ABI_LINUX,
			    "ep_abi %u", buf.msg.em_process.ep_abi);
			ASSERT_MSG(buf.msg.em_process.ep_jid == j_a,
			    "ep_jid %d", buf.msg.em_process.ep_jid);
		}
	}
	marker = jt_run_true(j_a);
	if (scan(fd, marker, OES_EVENT_NOTIFY_EXIT, &recs[1], 1) != 0)
		TEST_FAIL("marker not delivered");
	ASSERT_MSG(recs[1].exits == 0, "host Linux process was delivered");
	close(fd);
	unlink(target);
}

/* ------------------------------------------------------------- inbound -- */

static void
inbound_case(const char *what, uint32_t flags, int victim_jid,
    bool expect_seen)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_SIGNAL;
	struct kid victim, inside, killer, marker;
	struct rec recs[2];
	int fd;

	fd = jclient(j_a, flags, &ev, 1);
	if (fd < 0)
		return;
	victim.pid = inside.pid = -1;
	victim.go = inside.go = -1;
	if (kid_start(&victim, victim_jid, fn_pause, NULL, false) != 0 ||
	    kid_start(&inside, j_a, fn_pause, NULL, false) != 0 ||
	    kid_start(&killer, -1, fn_kill_usr1, &victim.pid, false) != 0) {
		TEST_FAIL("%s: cannot start the processes", what);
		goto out;
	}
	ASSERT_MSG(kid_finish(&killer) == 0, "%s: host sender failed", what);
	/* Marker: a process in A signals a process in A (subject in scope). */
	if (kid_start(&marker, j_a, fn_kill_usr1, &inside.pid, false) != 0) {
		TEST_FAIL("%s: cannot start the marker", what);
		goto out;
	}
	ASSERT_MSG(kid_finish(&marker) == 0, "%s: marker sender failed", what);
	memset(recs, 0, sizeof(recs));
	recs[0].pid = killer.pid;
	recs[1].pid = marker.pid;
	if (scan(fd, marker.pid, OES_EVENT_NOTIFY_SIGNAL, recs, 2) != 0) {
		TEST_FAIL("%s: signal sent inside the jail not delivered",
		    what);
		goto out;
	}
	ASSERT_MSG(recs[1].sigtarget == inside.pid, "%s: marker target %d",
	    what, recs[1].sigtarget);
	if (expect_seen) {
		ASSERT_MSG(recs[0].signals == 1, "%s: %d inbound signal events",
		    what, recs[0].signals);
		ASSERT_MSG(recs[0].sigtarget == victim.pid &&
		    recs[0].sigtarget_jid == victim_jid &&
		    recs[0].subject_jid == 0,
		    "%s: target %d (jid %d), sender jid %d", what,
		    recs[0].sigtarget, recs[0].sigtarget_jid,
		    recs[0].subject_jid);
	} else
		ASSERT_MSG(recs[0].signals == 0 && recs[0].other == 0,
		    "%s: outside sender was delivered", what);
out:
	kid_kill(&victim);
	kid_kill(&inside);
	close(fd);
}

static int
fn_ptrace_attach(void *arg)
{
	pid_t pid = *(pid_t *)arg;
	int status;

	if (ptrace(PT_ATTACH, pid, NULL, 0) != 0)
		return (61);
	if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status))
		return (62);
	if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) != 0)
		return (63);
	return (0);
}

static int
fn_renice(void *arg)
{

	return (setpriority(PRIO_PROCESS, *(pid_t *)arg, 5) == 0 ? 0 : 64);
}

/*
 * As inbound_case(), for the other two kinds of event that have a target
 * process: a host process attaches to (NOTIFY_PTRACE) or renices
 * (NOTIFY_PROC_SCHED) a process in victim_jid.  The marker is the same
 * operation done inside jail A on a process inside it.
 */
static void
inbound_proc_case(const char *what, oes_event_type_t event,
    int (*act)(void *), uint32_t flags, int victim_jid, bool expect_seen)
{
	struct kid victim, inside, actor, marker;
	struct timespec start;
	const oes_process_t *tp;
	test_msg_buf buf;
	long left;
	int fd, seen;
	bool marked;

	fd = jclient(j_a, flags, &event, 1);
	if (fd < 0)
		return;
	victim.pid = inside.pid = -1;
	victim.go = inside.go = -1;
	if (kid_start(&victim, victim_jid, fn_pause, NULL, false) != 0 ||
	    kid_start(&inside, j_a, fn_pause, NULL, false) != 0 ||
	    kid_start(&actor, -1, act, &victim.pid, false) != 0) {
		TEST_FAIL("%s: cannot start the processes", what);
		goto out;
	}
	ASSERT_MSG(kid_finish(&actor) == 0, "%s: host actor failed", what);
	if (kid_start(&marker, j_a, act, &inside.pid, false) != 0) {
		TEST_FAIL("%s: cannot start the marker", what);
		goto out;
	}
	ASSERT_MSG(kid_finish(&marker) == 0, "%s: marker actor failed", what);

	seen = 0;
	marked = false;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (!marked && (left = WAIT_MS - jt_elapsed_ms(&start)) > 0) {
		if (test_wait_event(fd, &buf.msg, left > 100 ? 100 :
		    (int)left) != 0 || buf.msg.em_event != event)
			continue;
		tp = event == OES_EVENT_NOTIFY_PTRACE ?
		    &buf.msg.em_event_data.ptrace.target :
		    &buf.msg.em_event_data.proc_sched.target;
		if (buf.msg.em_process.ep_pid == actor.pid) {
			seen++;
			ASSERT_MSG(tp->ep_pid == victim.pid &&
			    tp->ep_jid == victim_jid &&
			    (tp->ep_flags & EP_FLAG_JAILED) != 0,
			    "%s: target %d jid %d flags 0x%x, want %d in "
			    "jail %d", what, tp->ep_pid, tp->ep_jid,
			    tp->ep_flags, victim.pid, victim_jid);
		} else if (buf.msg.em_process.ep_pid == marker.pid &&
		    tp->ep_pid == inside.pid)
			marked = true;
	}
	if (!marked)
		TEST_FAIL("%s: the operation inside the jail not delivered",
		    what);
	else if (expect_seen)
		ASSERT_MSG(seen >= 1, "%s: inbound event not delivered", what);
	else
		ASSERT_MSG(seen == 0, "%s: outside actor was delivered (%d)",
		    what, seen);
out:
	kid_kill(&victim);
	kid_kill(&inside);
	close(fd);
}

static void
test_inbound(void)
{

	TEST_BEGIN("T-IN-1/5 default: only the sender's jail counts");
	inbound_case("T-IN-1", 0, j_a, false);
	TEST_BEGIN("T-IN-2 INBOUND: a signal sent into the jail");
	inbound_case("T-IN-2", OES_JAIL_SCOPE_INBOUND, j_a, true);
	TEST_BEGIN("T-IN-2b INBOUND reaches nested jails");
	inbound_case("T-IN-2b", OES_JAIL_SCOPE_INBOUND, j_c, true);
	TEST_BEGIN("T-IN-3 INBOUND: host to host is not delivered");
	inbound_case("T-IN-3", OES_JAIL_SCOPE_INBOUND, -1, false);
	TEST_BEGIN("T-IN-3b INBOUND: host to a sibling jail is not delivered");
	inbound_case("T-IN-3b", OES_JAIL_SCOPE_INBOUND, j_s, false);
	TEST_BEGIN("T-IN-4 INBOUND with NOCHILDREN: nested target not covered");
	inbound_case("T-IN-4", OES_JAIL_SCOPE_INBOUND |
	    OES_JAIL_SCOPE_NOCHILDREN, j_b, false);

	TEST_BEGIN("T-IN-6 INBOUND: ptrace attach from outside the jail");
	inbound_proc_case("T-IN-6", OES_EVENT_NOTIFY_PTRACE, fn_ptrace_attach,
	    OES_JAIL_SCOPE_INBOUND, j_a, true);
	inbound_proc_case("T-IN-6 nested", OES_EVENT_NOTIFY_PTRACE,
	    fn_ptrace_attach, OES_JAIL_SCOPE_INBOUND, j_c, true);
	TEST_BEGIN("T-IN-6b default: ptrace from outside is not delivered");
	inbound_proc_case("T-IN-6b", OES_EVENT_NOTIFY_PTRACE,
	    fn_ptrace_attach, 0, j_a, false);
	inbound_proc_case("T-IN-6b sibling", OES_EVENT_NOTIFY_PTRACE,
	    fn_ptrace_attach, OES_JAIL_SCOPE_INBOUND, j_s, false);
	TEST_BEGIN("T-IN-7 INBOUND: scheduling change from outside the jail");
	inbound_proc_case("T-IN-7", OES_EVENT_NOTIFY_PROC_SCHED, fn_renice,
	    OES_JAIL_SCOPE_INBOUND, j_a, true);
	inbound_proc_case("T-IN-7 nested", OES_EVENT_NOTIFY_PROC_SCHED,
	    fn_renice, OES_JAIL_SCOPE_INBOUND, j_c, true);
	TEST_BEGIN("T-IN-7b default: scheduling from outside is not delivered");
	inbound_proc_case("T-IN-7b", OES_EVENT_NOTIFY_PROC_SCHED, fn_renice,
	    0, j_a, false);
	inbound_proc_case("T-IN-7b sibling", OES_EVENT_NOTIFY_PROC_SCHED,
	    fn_renice, OES_JAIL_SCOPE_INBOUND, j_s, false);
}

/* ------------------------------------------------------ jailed caller -- */

/*
 * Runs in a child that opens its descriptors on the host and then enters
 * jail A.  Returns 0 or the number of the failed step.
 */
static int
jailed_caller(int ready_fd, int go_fd)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_EXIT;
	struct oes_jail_scope_args args;
	struct rec recs[2];
	pid_t pids[3];
	int fds[8], i;

	for (i = 0; i < 8; i++) {
		fds[i] = test_open_oes();
		if (fds[i] < 0)
			return (1);
	}
	/* Set from the host: a jailed reader must not learn the host's view. */
	if (set_jail(fds[7], j_a, NULL, 0) != 0)
		return (2);
	if (jail_attach(j_a) != 0)
		return (3);
	if (get_jail(fds[7], &args) != 0 || args.ejs_jid != 0 ||
	    args.ejs_name[0] != '\0' || args.ejs_flags != 0)
		return (4);

	/* T-JAILED-1: jid 0 is this jail. */
	if (set_jail(fds[0], 0, NULL, 0) != 0)
		return (10);
	if (get_jail(fds[0], &args) != 0 || args.ejs_jid != 0 ||
	    strcmp(args.ejs_name, "0") != 0)
		return (11);
	/* T-JAILED-2: jails beneath this one, by jid and by relative name. */
	if (set_jail(fds[1], j_b, NULL, 0) != 0)
		return (20);
	if (set_jail(fds[2], 0, "b", 0) != 0)
		return (21);
	if (get_jail(fds[2], &args) != 0 || args.ejs_jid != j_b ||
	    strcmp(args.ejs_name, "b") != 0)
		return (22);
	if (set_jail(fds[3], 0, "b.c", OES_JAIL_SCOPE_NOCHILDREN) != 0)
		return (23);
	/* T-JAILED-3: nothing outside, not even this jail by its own id. */
	if (set_jail(fds[4], j_s, NULL, 0) != -1 || errno != ENOENT)
		return (30);
	if (set_jail(fds[4], j_a, NULL, 0) != -1 || errno != ENOENT)
		return (31);
	if (set_jail(fds[4], 0, n_a, 0) != -1 || errno != ENOENT)
		return (32);
	if (set_jail(fds[4], 0, n_s, 0) != -1 || errno != ENOENT)
		return (33);
	/* T-JAILED-4/5: INBOUND is refused, before the lookup. */
	if (set_jail(fds[4], 0, NULL, OES_JAIL_SCOPE_INBOUND) != -1 ||
	    errno != EPERM)
		return (40);
	if (set_jail(fds[4], j_s, NULL, OES_JAIL_SCOPE_INBOUND) != -1 ||
	    errno != EPERM)
		return (41);
	if (jt_get_scope(fds[4]) != OES_SCOPE_GLOBAL)
		return (42);

	/* The jid 0 scope covers this jail and below, not the host. */
	if (jt_notify_setup(fds[0], &ev, 1) != 0)
		return (50);
	if (write(ready_fd, "R", 1) != 1)
		return (51);
	if (read(go_fd, pids, sizeof(pids)) != sizeof(pids))
		return (52);
	memset(recs, 0, sizeof(recs));
	recs[0].pid = pids[0];		/* host */
	recs[1].pid = pids[1];		/* A */
	if (scan(fds[0], pids[2], OES_EVENT_NOTIFY_EXIT, recs, 2) != 0)
		return (53);		/* A.b, the marker */
	if (recs[0].exits != 0)
		return (54);
	if (recs[1].exits != 1)
		return (55);
	return (0);
}

static void
test_jailed_caller(void)
{
	int ready[2], go[2], rc;
	pid_t child, pids[3];
	char byte;

	TEST_BEGIN("T-JAILED a client whose owner is itself jailed");
	if (pipe(ready) != 0 || pipe(go) != 0) {
		TEST_FAIL("pipe");
		return;
	}
	fflush(NULL);
	child = fork();
	if (child == 0) {
		close(ready[0]);
		close(go[1]);
		_exit(jailed_caller(ready[1], go[0]));
	}
	close(ready[1]);
	close(go[0]);
	if (read(ready[0], &byte, 1) != 1) {
		rc = jt_reap(child);
		TEST_FAIL("jailed caller failed at step %d", rc);
	} else {
		pids[0] = jt_run_true(-1);
		pids[1] = jt_run_true(j_a);
		pids[2] = jt_run_true(j_b);
		(void)write(go[1], pids, sizeof(pids));
		rc = jt_reap(child);
		ASSERT_MSG(rc == 0, "jailed caller failed at step %d", rc);
	}
	close(ready[0]);
	close(go[1]);
}

/*
 * OES_IOC_GET_JAIL_SCOPE reports the jail as the setter named it, which is
 * the view of the setter's own jail.  The descriptor is shared by fork, so
 * one process sets the scope from inside jail A and others read it from the
 * host, from A and from jails that are not A.
 */
struct scope_io {
	int		fd;
	int		jid;		/* To set, or expected */
	const char	*name;		/* To set by name (NULL: by jid), or expected */
};

static int
fn_set_scope(void *arg)
{
	struct scope_io *io = arg;

	return (set_jail(io->fd, io->jid, io->name, 0) == 0 ? 0 : 70);
}

static int
fn_get_scope(void *arg)
{
	struct oes_jail_scope_args args;
	struct scope_io *io = arg;

	if (get_jail(io->fd, &args) != 0)
		return (71);
	if (args.ejs_jid != io->jid)
		return (72);
	if (strcmp(args.ejs_name, io->name) != 0)
		return (73);
	return (0);
}

static int
run_in_jail(int jid, int (*fn)(void *), void *arg)
{
	struct kid k;

	if (kid_start(&k, jid, fn, arg, false) != 0)
		return (-1);
	return (kid_finish(&k));
}

static void
test_getter_views(void)
{
	struct oes_jail_scope_args args;
	struct scope_io io;
	char pname[64], cname[80];
	int fd, jid_c, jid_p, rc;

	TEST_BEGIN("T-GET-2 the setter's view is shown in the setter's jail only");
	fd = test_open_oes();
	io.fd = fd;
	io.jid = j_b;
	io.name = NULL;
	rc = run_in_jail(j_a, fn_set_scope, &io);
	ASSERT_MSG(rc == 0, "set from inside jail A: status %d", rc);
	/* Jail A calls its child "b" and knows its jid. */
	io.name = "b";
	EXPECT_OK(get_jail(fd, &args), "GET from the host");
	ASSERT_MSG(args.ejs_jid == j_b && strcmp(args.ejs_name, "b") == 0,
	    "host reader: jid %d name '%s'", args.ejs_jid, args.ejs_name);
	rc = run_in_jail(j_a, fn_get_scope, &io);
	ASSERT_MSG(rc == 0, "reader in the setter's jail: step %d", rc);
	/* Nobody else is shown it: not a sibling, not the scoped jail itself. */
	io.jid = 0;
	io.name = "";
	rc = run_in_jail(j_s, fn_get_scope, &io);
	ASSERT_MSG(rc == 0, "reader in a sibling jail: step %d "
	    "(72: it was shown the jid, 73: the name)", rc);
	rc = run_in_jail(j_b, fn_get_scope, &io);
	ASSERT_MSG(rc == 0, "reader in the scoped jail: step %d", rc);
	close(fd);

	TEST_BEGIN("T-GET-3 remembering the setter's jail does not keep it");
	jid_p = scratch_jail("gp", pname, sizeof(pname), NULL);
	snprintf(cname, sizeof(cname), "%s.kid", pname);
	jid_c = jt_make_jail(cname, "oesjs-scratch", NULL, "1");
	fd = test_open_oes();
	if (jid_p == -1 || jid_c == -1 || fd < 0)
		return;
	io.fd = fd;
	io.jid = jid_c;
	io.name = NULL;
	rc = run_in_jail(jid_p, fn_set_scope, &io);
	ASSERT_MSG(rc == 0, "set from inside the scratch jail: status %d", rc);
	/* The scope ends first; its setter's jail is still there. */
	remove_jail(jid_c);
	ASSERT_MSG(wait_jail_gone(cname), "removed scope jail still exists");
	io.name = "kid";
	rc = run_in_jail(jid_p, fn_get_scope, &io);
	ASSERT_MSG(rc == 0, "setter's jail reading the dead scope: step %d",
	    rc);
	/* Then the setter's jail goes, with the descriptor still open. */
	remove_jail(jid_p);
	ASSERT_MSG(wait_jail_gone(pname),
	    "the setter's jail still exists (dying) while the client is open");
	EXPECT_OK(get_jail(fd, &args), "GET from the host afterwards");
	ASSERT_MSG((args.ejs_flags & OES_JAIL_SCOPE_DEAD) != 0 &&
	    args.ejs_jid == jid_c, "host reader afterwards: flags 0x%x jid %d",
	    args.ejs_flags, args.ejs_jid);
	close(fd);

	/* The same when the setter scoped its own jail. */
	jid_p = scratch_jail("go", pname, sizeof(pname), NULL);
	fd = test_open_oes();
	if (jid_p == -1 || fd < 0)
		return;
	io.fd = fd;
	io.jid = 0;
	io.name = NULL;
	rc = run_in_jail(jid_p, fn_set_scope, &io);
	ASSERT_MSG(rc == 0, "set own jail from inside: status %d", rc);
	remove_jail(jid_p);
	ASSERT_MSG(wait_jail_gone(pname),
	    "the setter's own jail still exists while the client is open");
	close(fd);
}

/*
 * The jail a scope was set from is remembered by the client and given up
 * by close or by that jail's removal, whichever comes first, while readers
 * compare against it.  Race all four.
 */
struct gstress {
	int		fd;
	int		jid;
	volatile int	stop;
};

static void *
gstress_getter(void *arg)
{
	struct oes_jail_scope_args args;
	struct gstress *g = arg;

	while (!g->stop)
		(void)ioctl(g->fd, OES_IOC_GET_JAIL_SCOPE, &args);
	return (NULL);
}

static void *
gstress_remover(void *arg)
{
	struct gstress *g = arg;

	usleep((useconds_t)(arc4random_uniform(2000)));
	(void)jail_remove(g->jid);
	return (NULL);
}

static void
test_getter_stress(void)
{
	char pname[64], cname[80];
	struct scope_io io;
	struct gstress g;
	pthread_t th[2];
	pid_t child;
	int i, jid_c, sets;

	TEST_BEGIN("T-GET-STRESS set, read, close and remove the setter's "
	    "jail, concurrently");
	jt_name(pname, sizeof(pname), "oesjs", "gs");
	snprintf(cname, sizeof(cname), "%s.kid", pname);
	sets = 0;
	for (i = 0; i < 200; i++) {
		memset(&g, 0, sizeof(g));
		g.jid = jail_setv(JAIL_CREATE, "name", pname, "path", "/",
		    "children.max", "2", "persist", NULL, NULL);
		jid_c = g.jid == -1 ? -1 : jail_setv(JAIL_CREATE, "name",
		    cname, "path", "/", "persist", NULL, NULL);
		g.fd = test_open_oes();
		if (g.jid == -1 || jid_c == -1 || g.fd < 0) {
			TEST_FAIL("round %d: setup: %s", i, jail_errmsg);
			if (g.jid != -1)
				(void)jail_remove(g.jid);
			break;
		}
		io.fd = g.fd;
		io.jid = jid_c;
		io.name = NULL;
		fflush(NULL);
		child = fork();
		if (child == 0) {
			if (jail_attach(g.jid) != 0)
				_exit(101);
			_exit(fn_set_scope(&io));
		}
		if (pthread_create(&th[0], NULL, gstress_getter, &g) != 0 ||
		    pthread_create(&th[1], NULL, gstress_remover, &g) != 0) {
			TEST_FAIL("pthread_create");
			(void)jt_reap(child);
			break;
		}
		usleep((useconds_t)(arc4random_uniform(3000)));
		/* The getter may still be in its ioctl: that is the point. */
		g.stop = 1;
		close(g.fd);
		pthread_join(th[0], NULL);
		pthread_join(th[1], NULL);
		if (jt_reap(child) == 0)
			sets++;
		/* The removal may have lost to nothing; make sure of it. */
		(void)jail_remove(g.jid);
		if (!wait_jail_gone(cname) || !wait_jail_gone(pname)) {
			TEST_FAIL("round %d: a removed jail still exists "
			    "(dying) after the close", i);
			break;
		}
	}
	printf("    %d of %d scopes were set before the jail went\n", sets,
	    i);
	ASSERT_MSG(sets > 0, "no scope was ever set: the race never ran");
}

/* ------------------------------------------------- more kinds of subject -- */

struct kinds {
	pid_t	pid;
	int	forks, sockets, pipes, exits;
};

static int
fn_kinds(void *arg __unused)
{
	pid_t pid;
	int p[2], s;

	pid = fork();
	if (pid < 0)
		return (90);
	if (pid == 0)
		_exit(0);
	if (jt_reap(pid) != 0)
		return (91);
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0)
		return (92);
	close(s);
	if (pipe(p) != 0 || write(p[1], "x", 1) != 1)
		return (93);
	return (0);
}

static void
test_event_kinds(void)
{
	oes_event_type_t evs[] = { OES_EVENT_NOTIFY_FORK,
	    OES_EVENT_NOTIFY_SOCKET_CREATE, OES_EVENT_NOTIFY_PIPE_WRITE,
	    OES_EVENT_NOTIFY_EXIT };
	struct kinds seen[2], *k;
	struct timespec start;
	test_msg_buf buf;
	long left;
	int fd, i, rc;

	TEST_BEGIN("T-KIND fork, socket and pipe events of a jailed subject");
	fd = jclient(j_a, 0, evs, nitems(evs));
	if (fd < 0)
		return;
	memset(seen, 0, sizeof(seen));
	for (i = 0; i < 2; i++) {
		/*
		 * The host process first: its events must not arrive.  No
		 * kid_start() here: its handshake is itself a pipe write.
		 */
		fflush(NULL);
		seen[i].pid = fork();
		if (seen[i].pid == 0) {
			if (i == 1 && jail_attach(j_a) != 0)
				_exit(101);
			_exit(fn_kinds(NULL));
		}
		rc = jt_reap(seen[i].pid);
		ASSERT_MSG(rc == 0, "subject %d: status %d", i, rc);
	}
	/* All four are queued in order: the jailed exit is the last. */
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (seen[1].exits == 0 &&
	    (left = WAIT_MS - jt_elapsed_ms(&start)) > 0) {
		if (test_wait_event(fd, &buf.msg, left > 100 ? 100 :
		    (int)left) != 0)
			continue;
		for (i = 0; i < 2; i++) {
			k = &seen[i];
			if (buf.msg.em_process.ep_pid != k->pid)
				continue;
			switch (buf.msg.em_event) {
			case OES_EVENT_NOTIFY_FORK:
				k->forks++;
				break;
			case OES_EVENT_NOTIFY_SOCKET_CREATE:
				k->sockets++;
				ASSERT_MSG(buf.msg.em_event_data.socket_create.
				    domain == AF_UNIX, "socket domain %d",
				    buf.msg.em_event_data.socket_create.domain);
				break;
			case OES_EVENT_NOTIFY_PIPE_WRITE:
				k->pipes++;
				break;
			case OES_EVENT_NOTIFY_EXIT:
				k->exits++;
				break;
			default:
				break;
			}
		}
	}
	ASSERT_MSG(seen[1].exits == 1, "exit of the jailed subject not seen");
	ASSERT_MSG(seen[1].forks == 1 && seen[1].sockets == 1 &&
	    seen[1].pipes == 1, "jailed subject: %d fork, %d socket, %d pipe "
	    "events, want one each", seen[1].forks, seen[1].sockets,
	    seen[1].pipes);
	ASSERT_MSG(seen[0].forks == 0 && seen[0].sockets == 0 &&
	    seen[0].pipes == 0 && seen[0].exits == 0,
	    "host subject delivered: %d fork, %d socket, %d pipe, %d exit",
	    seen[0].forks, seen[0].sockets, seen[0].pipes, seen[0].exits);
	close(fd);
}

/*
 * One thread of a process enters the jail.  The credential belongs to the
 * process; another thread takes it up when it next enters the kernel, so
 * what that thread does afterwards is in scope too.
 */
static int mt_go[2], mt_ready[2];

static void *
mt_thread(void *arg __unused)
{
	char c;
	int fd;

	fd = open(file2, O_RDONLY | O_CLOEXEC);		/* Before: outside */
	if (fd < 0)
		return ((void *)1);
	close(fd);
	if (write(mt_ready[1], "R", 1) != 1 || read(mt_go[0], &c, 1) != 1)
		return ((void *)2);
	fd = open(file1, O_RDONLY | O_CLOEXEC);		/* After: inside */
	if (fd < 0)
		return ((void *)3);
	close(fd);
	return (NULL);
}

static int
fn_mt_attach(void *arg __unused)
{
	pthread_t th;
	void *res;
	char c;
	int fd;

	if (pipe(mt_go) != 0 || pipe(mt_ready) != 0 ||
	    pthread_create(&th, NULL, mt_thread, NULL) != 0)
		return (80);
	/* The other thread is now blocked in read(2), outside the jail. */
	if (read(mt_ready[0], &c, 1) != 1)
		return (81);
	usleep(50000);
	if (jail_attach(j_a) != 0)
		return (82);
	fd = open(file1, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (83);
	close(fd);
	if (write(mt_go[1], "G", 1) != 1 || pthread_join(th, &res) != 0)
		return (84);
	return (res == NULL ? 0 : 85);
}

static void
test_multithreaded_attach(void)
{
	oes_event_type_t evs[] = { OES_EVENT_NOTIFY_OPEN,
	    OES_EVENT_NOTIFY_EXIT };
	struct kid k;
	struct rec r;
	int fd, rc;

	TEST_BEGIN("T-MT one thread of a process enters the jail");
	fd = jclient(j_a, 0, evs, 2);
	if (fd < 0)
		return;
	if (kid_start(&k, -1, fn_mt_attach, NULL, false) != 0) {
		TEST_FAIL("cannot start the process");
		close(fd);
		return;
	}
	rc = kid_finish(&k);
	ASSERT_MSG(rc == 0, "threaded child status %d", rc);
	memset(&r, 0, sizeof(r));
	r.pid = k.pid;
	if (scan(fd, k.pid, OES_EVENT_NOTIFY_EXIT, &r, 1) != 0)
		TEST_FAIL("exit of the threaded process not delivered");
	ASSERT_MSG(r.open2 == 0,
	    "opens made before the attach were delivered: %d", r.open2);
	ASSERT_MSG(r.open1 == 2, "opens after the attach, one by each "
	    "thread: %d delivered, want 2", r.open1);
	close(fd);
}

/*
 * A jail with its own root directory.  Every other jail here is on "/".
 * The subject names its files relative to its root, and that is the path
 * the record carries and the path a mute is matched against; the file's
 * identity is the same from wherever it is looked at.
 */
static int
copy_file(const char *from, const char *to, mode_t mode)
{
	static char buf[65536];
	ssize_t n;
	int in, out, rc;

	in = open(from, O_RDONLY | O_CLOEXEC);
	out = open(to, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
	rc = (in < 0 || out < 0) ? -1 : 0;
	while (rc == 0 && (n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, (size_t)n) != n)
			rc = -1;
	}
	if (rc == 0 && n < 0)
		rc = -1;
	if (in >= 0)
		close(in);
	if (out >= 0)
		close(out);
	return (rc);
}

static int
fn_exec_path(void *arg)
{

	/* A copy of the rescue binary, which acts by the name it is given. */
	execl((const char *)arg, "sleep", "0", (char *)NULL);
	return (102);
}

static int
mute_path(int fd, const char *path)
{
	struct oes_mute_path_args args;

	memset(&args, 0, sizeof(args));
	strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = OES_MUTE_PATH_LITERAL;
	return (ioctl(fd, OES_IOC_MUTE_PATH, &args));
}

/* Run a path in the jail; was its exec delivered before the marker's? */
static int
rooted_run(int fd, int jid, const char *path, const char *marker_path,
    test_msg_buf *out)
{
	struct timespec start;
	struct kid k, m;
	test_msg_buf buf;
	long left;
	int rc, seen;

	rc = kid_start(&k, jid, fn_exec_path, __DECONST(char *, path),
	    false) == 0 ? kid_finish(&k) : -1;
	if (rc != 0) {
		TEST_FAIL("exec of %s in the rooted jail: status %d", path, rc);
		return (-1);
	}
	rc = kid_start(&m, jid, fn_exec_path, __DECONST(char *, marker_path),
	    false) == 0 ? kid_finish(&m) : -1;
	if (rc != 0) {
		TEST_FAIL("exec of the marker %s: status %d", marker_path, rc);
		return (-1);
	}
	seen = 0;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while ((left = WAIT_MS - jt_elapsed_ms(&start)) > 0) {
		if (test_wait_event(fd, &buf.msg, left > 100 ? 100 :
		    (int)left) != 0 ||
		    buf.msg.em_event != OES_EVENT_NOTIFY_EXEC)
			continue;
		if (buf.msg.em_process.ep_pid == k.pid) {
			seen++;
			if (out != NULL)
				memcpy(out->raw, buf.raw, buf.msg.em_size);
		} else if (buf.msg.em_process.ep_pid == m.pid)
			return (seen);
	}
	TEST_FAIL("exec of the marker %s not delivered", marker_path);
	return (-1);
}

static void
test_rooted_jail(void)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_EXEC;
	char root[] = "/tmp/oesjs-root.XXXXXX";
	char host1[96], host2[96], name[64];
	const oes_event_exec_t *ex;
	test_msg_buf buf;
	struct stat sb;
	int fd, jid, n;

	TEST_BEGIN("T-ROOT a jail whose root is not /");
	if (mkdtemp(root) == NULL) {
		TEST_FAIL("mkdtemp: %s", strerror(errno));
		return;
	}
	(void)chmod(root, 0755);
	snprintf(host1, sizeof(host1), "%s/oesjs-prog", root);
	snprintf(host2, sizeof(host2), "%s/oesjs-mark", root);
	/* A static binary: the jail has nothing else in it. */
	if (copy_file("/rescue/sleep", host1, 0555) != 0 ||
	    copy_file("/rescue/sleep", host2, 0555) != 0 ||
	    stat(host1, &sb) != 0) {
		TEST_FAIL("cannot populate %s: %s", root, strerror(errno));
		goto out;
	}
	jt_name(name, sizeof(name), "oesjs", "root");
	jid = jail_setv(JAIL_CREATE, "name", name, "path", root,
	    "host.hostname", "oesjs-root", "persist", NULL, NULL);
	if (jid == -1) {
		TEST_FAIL("jail_setv(%s): %s", name, jail_errmsg);
		goto out;
	}
	if (jt_njails < JT_MAXJAILS)
		jt_jails[jt_njails++] = jid;

	fd = jclient(jid, 0, &ev, 1);
	if (fd >= 0) {
		n = rooted_run(fd, jid, "/oesjs-prog", "/oesjs-mark", &buf);
		ASSERT_MSG(n == 1, "exec in the rooted jail: %d events", n);
		if (n == 1) {
			ex = &buf.msg.em_event_data.exec;
			ASSERT_MSG(ex->target.ep_jid == jid, "ep_jid %d, want "
			    "%d", ex->target.ep_jid, jid);
			ASSERT_MSG(ex->executable.ef_ino == (uint64_t)sb.st_ino &&
			    ex->executable.ef_dev == (uint64_t)sb.st_dev,
			    "executable identity %ju/%ju, want %ju/%ju",
			    (uintmax_t)ex->executable.ef_dev,
			    (uintmax_t)ex->executable.ef_ino,
			    (uintmax_t)sb.st_dev, (uintmax_t)sb.st_ino);
			ASSERT_MSG(strcmp(oes_msg_string(&buf.msg,
			    ex->executable.ef_path_off), "/oesjs-prog") == 0 &&
			    strcmp(oes_msg_string(&buf.msg,
			    ex->target.ep_path_off), "/oesjs-prog") == 0,
			    "paths in the record: executable '%s' target '%s', "
			    "want the subject's own '/oesjs-prog'",
			    oes_msg_string(&buf.msg, ex->executable.ef_path_off),
			    oes_msg_string(&buf.msg, ex->target.ep_path_off));
		}

		TEST_BEGIN("T-ROOT-2 a path mute matches the path in the record");
		/* The host's name for the file is not what the record says. */
		EXPECT_OK(mute_path(fd, host1), "mute by the host path");
		n = rooted_run(fd, jid, "/oesjs-prog", "/oesjs-mark", NULL);
		ASSERT_MSG(n == 1, "muted by the host's path: %d events", n);
		EXPECT_OK(mute_path(fd, "/oesjs-prog"), "mute by the jail path");
		n = rooted_run(fd, jid, "/oesjs-prog", "/oesjs-mark", NULL);
		ASSERT_MSG(n == 0, "not muted by the path in the record: %d "
		    "events", n);
		close(fd);
	}
	remove_jail(jid);
out:
	unlink(host1);
	unlink(host2);
	rmdir(root);
}

/* Jail scopes on different jails and a descendants scope, all at once. */
static void
test_scopes_together(void)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_EXIT;
	struct rec recs[3];
	pid_t pa, ps, ph, ma, ms, mh;
	int fa, fs, fd;

	TEST_BEGIN("T-MULTI-2 two jail scopes and a descendants scope at once");
	fa = exit_client(j_a, 0);
	fs = exit_client(j_s, 0);
	fd = test_open_oes();
	if (fa < 0 || fs < 0 || fd < 0 || test_set_descendants_scope(fd) != 0 ||
	    jt_notify_setup(fd, &ev, 1) != 0) {
		TEST_FAIL("setup");
		goto out;
	}
	pa = jt_run_true(j_b);
	ps = jt_run_true(j_s);
	ph = jt_run_true(-1);
	ma = jt_run_true(j_a);
	ms = jt_run_true(j_s);
	mh = jt_run_true(-1);
	if (pa <= 0 || ps <= 0 || ph <= 0 || ma <= 0 || ms <= 0 || mh <= 0) {
		TEST_FAIL("cannot run the subjects");
		goto out;
	}
#define	THREE(_fd, _marker, _what, _ea, _es, _eh) do {			\
	memset(recs, 0, sizeof(recs));					\
	recs[0].pid = pa;						\
	recs[1].pid = ps;						\
	recs[2].pid = ph;						\
	if (scan((_fd), (_marker), OES_EVENT_NOTIFY_EXIT, recs, 3) != 0) \
		TEST_FAIL("%s: marker not delivered", (_what));		\
	ASSERT_MSG(recs[0].exits == (_ea) && recs[1].exits == (_es) &&	\
	    recs[2].exits == (_eh), "%s: exits seen: A.b %d, S %d, "	\
	    "host %d; want %d, %d, %d", (_what), recs[0].exits,		\
	    recs[1].exits, recs[2].exits, (_ea), (_es), (_eh));		\
} while (0)
	THREE(fa, ma, "scope A", 1, 0, 0);
	THREE(fs, ms, "scope S", 0, 1, 0);
	/* Descendants are followed into whatever jail they enter. */
	THREE(fd, mh, "descendants scope", 1, 1, 1);
#undef THREE
out:
	if (fa >= 0)
		close(fa);
	if (fs >= 0)
		close(fs);
	if (fd >= 0)
		close(fd);
}

/* ------------------------------------------------- removal and reuse -- */

struct reader {
	int		fd;
	ssize_t		n;
	int		error;
	volatile int	done;
};

static void *
reader_thread(void *arg)
{
	static uint8_t buf[OES_MSG_MAX_SIZE];
	struct reader *r = arg;

	r->n = read(r->fd, buf, sizeof(buf));
	r->error = errno;
	r->done = 1;
	return (NULL);
}

static bool
reader_wait(struct reader *r)
{
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);
	while (!r->done && jt_elapsed_ms(&start) < WAIT_MS)
		usleep(20000);
	return (r->done != 0);
}

static void
test_dead_blocked_reader(void)
{
	struct oes_jail_scope_args args;
	struct pollfd pfd;
	struct reader r;
	pthread_t th;
	char name[64], buf[sizeof(oes_message_t)];
	ssize_t n;
	int fd, jid;

	TEST_BEGIN("T-DEAD-1 removal wakes a blocked reader with end of file");
	jid = scratch_jail("r1", name, sizeof(name), NULL);
	fd = exit_client(jid, 0);
	if (jid == -1 || fd < 0)
		return;
	EXPECT_OK(fcntl(fd, F_SETFL, 0), "clear O_NONBLOCK");
	memset(&r, 0, sizeof(r));
	r.fd = fd;
	if (pthread_create(&th, NULL, reader_thread, &r) != 0) {
		TEST_FAIL("pthread_create");
		return;
	}
	usleep(300000);
	ASSERT_MSG(!r.done, "reader returned before the removal: %zd", r.n);
	remove_jail(jid);
	if (!reader_wait(&r)) {
		TEST_FAIL("blocked reader not woken by the removal");
		return;		/* The thread still owns the descriptor. */
	}
	pthread_join(th, NULL);
	ASSERT_MSG(r.n == 0, "blocked read: %zd errno %d", r.n, r.error);

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	ASSERT_MSG(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLHUP) != 0,
	    "poll revents 0x%x", pfd.revents);
	EXPECT_OK(get_jail(fd, &args), "GET");
	ASSERT_MSG((args.ejs_flags & OES_JAIL_SCOPE_DEAD) != 0 &&
	    args.ejs_jid == jid && strcmp(args.ejs_name, name) == 0,
	    "GET: flags 0x%x jid %d name '%s'", args.ejs_flags, args.ejs_jid,
	    args.ejs_name);
	ASSERT_MSG(jt_get_scope(fd) == OES_SCOPE_JAIL, "GET_SCOPE");
	n = read(fd, buf, sizeof(buf));
	ASSERT_MSG(n == 0, "second blocking read: %zd errno %d", n, errno);
	EXPECT_OK(fcntl(fd, F_SETFL, O_NONBLOCK), "set O_NONBLOCK");
	n = read(fd, buf, sizeof(buf));
	ASSERT_MSG(n == 0, "non-blocking read: %zd errno %d", n, errno);

	TEST_BEGIN("T-DEAD-7 a dead scope observes nothing and pins nothing");
	EXPECT_ERRNO(jt_mute_pid(fd, getpid()), EPERM, "mute on a dead scope");
	EXPECT_ERRNO(set_jail(fd, j_a, NULL, 0), EBUSY, "re-aim a dead scope");
	/* The descriptor is still open: the dead scope must hold no jail. */
	ASSERT_MSG(wait_jail_gone(name),
	    "removed jail still exists (dying) while the client is open");
	EXPECT_OK(close(fd), "close");
}

static void
test_dead_queued(void)
{
	char name[64];
	int events, exits, fd, jid, rc;
	pid_t pid;

	TEST_BEGIN("T-DEAD-2 events generated before the removal are kept");
	jid = scratch_jail("r2", name, sizeof(name), NULL);
	fd = exit_client(jid, 0);
	if (jid == -1 || fd < 0)
		return;
	pid = jt_run_true(jid);
	remove_jail(jid);
	rc = read_to_eof(fd, pid, &exits, &events);
	ASSERT_MSG(rc == 0, "no end of file: %d", rc);
	ASSERT_MSG(exits == 1, "exit before the removal: %d events (of %d)",
	    exits, events);
	ASSERT_MSG(is_dead(fd), "not dead after end of file");
	close(fd);
	ASSERT_MSG(wait_jail_gone(name), "removed jail still exists");
}

/*
 * What a waiting consumer is told once the scope is dead: while events are
 * still queued the descriptor is both readable and hung up; once they are
 * read it is hung up only, and a read that would otherwise block or fail
 * with EAGAIN returns end of file.
 */
static void
test_dead_poll_select(void)
{
	static uint8_t buf[OES_MSG_MAX_SIZE * 4];
	struct timeval tv = { 0, 0 };
	const oes_message_t *msg;
	struct timespec start;
	struct pollfd pfd;
	fd_set rfds;
	char name[64];
	ssize_t n;
	size_t off;
	pid_t pid;
	int exits, fd, jid, rc;

	TEST_BEGIN("T-DEAD-8 poll, select and non-blocking read on a dead scope");
	jid = scratch_jail("r8", name, sizeof(name), NULL);
	fd = exit_client(jid, 0);
	if (jid == -1 || fd < 0)
		return;
	pid = jt_run_true(jid);
	remove_jail(jid);
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (!is_dead(fd) && jt_elapsed_ms(&start) < WAIT_MS)
		usleep(20000);
	ASSERT_MSG(is_dead(fd), "scope not dead after the removal");

	/* The exit is still queued. */
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	rc = poll(&pfd, 1, 0);
	ASSERT_MSG(rc == 1 && (pfd.revents & (POLLIN | POLLHUP)) ==
	    (POLLIN | POLLHUP), "poll with an event queued: rc %d revents "
	    "0x%x, want POLLIN|POLLHUP", rc, pfd.revents);
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	rc = select(fd + 1, &rfds, NULL, NULL, &tv);
	ASSERT_MSG(rc == 1 && FD_ISSET(fd, &rfds),
	    "select with an event queued: rc %d", rc);

	/* Non-blocking reads: the events, then end of file, never EAGAIN. */
	exits = 0;
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		for (off = 0; off + sizeof(*msg) <= (size_t)n;
		    off += msg->em_size) {
			msg = (const oes_message_t *)(const void *)(buf + off);
			if (msg->em_size < sizeof(*msg))
				break;
			if (msg->em_event == OES_EVENT_NOTIFY_EXIT &&
			    msg->em_process.ep_pid == pid)
				exits++;
		}
	}
	ASSERT_MSG(n == 0, "non-blocking read after the events: %zd errno %d "
	    "(%s), want end of file", n, n < 0 ? errno : 0,
	    n < 0 ? strerror(errno) : "-");
	ASSERT_MSG(exits == 1, "exit queued before the removal: %d", exits);

	/* Drained: hung up, no longer readable data. */
	pfd.revents = 0;
	rc = poll(&pfd, 1, 0);
	ASSERT_MSG(rc == 1 && (pfd.revents & (POLLIN | POLLHUP)) == POLLHUP,
	    "poll once drained: rc %d revents 0x%x, want POLLHUP alone", rc,
	    pfd.revents);
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = tv.tv_usec = 0;
	rc = select(fd + 1, &rfds, NULL, NULL, &tv);
	ASSERT_MSG(rc == 1 && FD_ISSET(fd, &rfds),
	    "select once drained: rc %d (end of file must be readable)", rc);
	n = read(fd, buf, sizeof(buf));
	ASSERT_MSG(n == 0, "second non-blocking read: %zd errno %d", n,
	    n < 0 ? errno : 0);
	close(fd);
	ASSERT_MSG(wait_jail_gone(name), "removed jail still exists");
}

/*
 * The end of a scope must not wait for the deferred queue to be empty: on a
 * busy system it never is.  With the queue kept full by other processes the
 * removal must still be followed by end of file, and by the release of the
 * removed jail, within a bounded number of deliveries.
 */
static void
test_dead_under_load(void)
{
	struct timespec start;
	struct jt_load load;
	uint64_t d0, d1;
	char name[64];
	long ms;
	int events, exits, fd, jid, rc;
	pid_t pid;

	TEST_BEGIN("T-DEAD-LOAD the scope ends while the deferred queue is busy");
	jid = scratch_jail("ld", name, sizeof(name), NULL);
	fd = exit_client(jid, 0);
	if (jid == -1 || fd < 0)
		return;
	/*
	 * Before the load: an event generated while the queue is full may
	 * be discarded, and this one must be found queued at the end.
	 */
	pid = jt_run_true(jid);
	if (jt_load_start(&load, fd) != 0) {
		TEST_FAIL("cannot keep the deferred queue full");
		close(fd);
		return;
	}
	d0 = jt_nosleep_drops(fd);
	remove_jail(jid);
	clock_gettime(CLOCK_MONOTONIC, &start);
	rc = read_to_eof_ms(fd, pid, &exits, &events, load.limit_ms);
	ms = jt_elapsed_ms(&start);
	d1 = jt_nosleep_drops(fd);
	if (!jt_load_still_full(fd))
		printf("    note: the queue was no longer full after the "
		    "wait\n");
	ASSERT_MSG(rc == 0, "no end of file %ld ms after the removal while "
	    "the deferred queue was kept full (%ju more events discarded at "
	    "its limit meanwhile): %d", ms, (uintmax_t)(d1 - d0), rc);
	if (rc == 0) {
		printf("    end of file %ld ms after the removal; %ju events "
		    "were discarded at the full queue meanwhile\n", ms,
		    (uintmax_t)(d1 - d0));
		ASSERT_MSG(exits == 1, "exit before the removal: %d events",
		    exits);
		ASSERT_MSG(is_dead(fd), "not dead after end of file");
		/* Still under load: the dead scope must not keep the jail. */
		ASSERT_MSG(wait_jail_gone(name),
		    "removed jail still exists while the load continues");
	}
	jt_load_stop(&load);
	if (rc != 0) {
		rc = read_to_eof(fd, pid, &exits, &events);
		printf("    after the load stopped: %s\n", rc == 0 ?
		    "end of file" : "still no end of file");
	}
	close(fd);
	ASSERT_MSG(wait_jail_gone(name), "removed jail still exists");
}

/*
 * The other half of the bound: the scope must not end early either.  An
 * event that sits behind a full queue when the jail is removed is still
 * delivered before end of file.  The writers are stopped while the event is
 * generated, so that it is queued behind the backlog rather than discarded
 * at the limit, and started again before the removal.
 */
static void
test_dead_behind_backlog(void)
{
	struct oes_stats st;
	struct jt_load load;
	uint64_t da, db;
	char name[64];
	int events, exits, fd, jid, rc, try;
	pid_t pid;
	bool behind;

	TEST_BEGIN("T-DEAD-LOAD-2 an event behind a deep queue precedes end "
	    "of file");
	jid = scratch_jail("ld2", name, sizeof(name), NULL);
	fd = exit_client(jid, 0);
	if (jid == -1 || fd < 0)
		return;
	if (jt_load_start(&load, fd) != 0) {
		TEST_FAIL("cannot keep the deferred queue full");
		close(fd);
		return;
	}
	pid = -1;
	behind = false;
	for (try = 0; try < 5 && !behind; try++) {
		if (try != 0) {
			/* Fill the queue again. */
			da = jt_nosleep_drops(fd);
			jt_load_signal(&load, SIGCONT);
			for (rc = 0; rc < 200 &&
			    jt_nosleep_drops(fd) == da; rc++)
				usleep(50000);
		}
		jt_load_signal(&load, SIGSTOP);
		usleep(20000);		/* Let the writers come to rest. */
		get_stats(fd, &st);
		da = jt_nosleep_drops(fd);
		pid = jt_run_true(jid);
		db = jt_nosleep_drops(fd);
		/*
		 * Nothing discarded: the exit is queued.  Nothing new on
		 * the scoped client: it is still behind the backlog.
		 */
		rc = (int)st.es_events_received;
		get_stats(fd, &st);
		behind = pid > 0 && da == db &&
		    (int)st.es_events_received == rc;
	}
	jt_load_signal(&load, SIGCONT);
	if (!behind) {
		TEST_FAIL("could not queue an event behind the backlog in "
		    "five attempts");
		jt_load_stop(&load);
		close(fd);
		return;
	}
	remove_jail(jid);
	rc = read_to_eof_ms(fd, pid, &exits, &events, load.limit_ms);
	if (!jt_load_still_full(fd))
		printf("    note: the queue was no longer full after the "
		    "wait\n");
	jt_load_stop(&load);
	ASSERT_MSG(rc == 0, "no end of file: %d", rc);
	ASSERT_MSG(exits == 1, "the exit queued behind the backlog: %d "
	    "events before end of file (attempt %d)", exits, try);
	close(fd);
	ASSERT_MSG(wait_jail_gone(name), "removed jail still exists");
}

static int
fn_wait_exit(void *arg __unused)
{

	return (0);
}

/*
 * The jail dies because its last process exits.  The exit event is queued
 * for deferred delivery by the exiting thread, which then gives up the
 * jail's last user reference; the removal races the delivery.  The event
 * must win every time.
 */
static void
test_dead_last_exit(void)
{
	char name[64], jidstr[16];
	int events, exits, fd, i, jid, lost, rc;
	struct kid k;

	TEST_BEGIN("T-DEAD-LAST the last exit of a jail is always delivered");
	lost = 0;
	for (i = 0; i < 25; i++) {
		jid = scratch_jail("last", name, sizeof(name), NULL);
		if (jid == -1)
			return;
		fd = exit_client(jid, 0);
		if (fd < 0 || kid_start(&k, jid, fn_wait_exit, NULL, true) != 0) {
			TEST_FAIL("setup, round %d", i);
			return;
		}
		/* Only the process keeps the jail now. */
		snprintf(jidstr, sizeof(jidstr), "%d", jid);
		if (jail_setv(JAIL_UPDATE, "jid", jidstr, "nopersist", NULL,
		    NULL) == -1) {
			TEST_FAIL("nopersist: %s", jail_errmsg);
			kid_kill(&k);
			return;
		}
		jt_forget_jail(jid);
		ASSERT_MSG(!is_dead(fd), "dead while a process is inside");
		rc = kid_finish(&k);
		ASSERT_MSG(rc == 0, "child status %d", rc);
		rc = read_to_eof(fd, k.pid, &exits, &events);
		if (rc != 0) {
			TEST_FAIL("round %d: no end of file: %d", i, rc);
			close(fd);
			return;
		}
		if (exits != 1)
			lost++;
		close(fd);
		if (!wait_jail_gone(name)) {
			TEST_FAIL("round %d: jail did not go away", i);
			return;
		}
	}
	ASSERT_MSG(lost == 0, "last exit lost in %d of 25 rounds", lost);
}

static void
test_dead_kqueue(void)
{
	struct timespec to = { .tv_sec = WAIT_MS / 1000 };
	struct kevent kev;
	char name[64];
	int fd, jid, kq, n;

	TEST_BEGIN("T-DEAD-3 kqueue reports EV_EOF");
	jid = scratch_jail("r3", name, sizeof(name), NULL);
	fd = exit_client(jid, 0);
	kq = kqueue();
	if (jid == -1 || fd < 0 || kq < 0)
		return;
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	EXPECT_OK(kevent(kq, &kev, 1, NULL, 0, NULL), "EV_ADD");
	remove_jail(jid);
	memset(&kev, 0, sizeof(kev));
	n = kevent(kq, NULL, 0, &kev, 1, &to);
	ASSERT_MSG(n == 1 && (int)kev.ident == fd &&
	    (kev.flags & EV_EOF) != 0, "kevent: n %d flags 0x%x", n,
	    kev.flags);
	close(kq);
	close(fd);
}

static void
test_dead_with_process(void)
{
	char name[64];
	int events, exits, fd, jid, rc;
	struct kid k;

	TEST_BEGIN("T-DEAD-4 removing a jail that still has a process");
	jid = scratch_jail("r4", name, sizeof(name), NULL);
	fd = exit_client(jid, 0);
	if (jid == -1 || fd < 0 ||
	    kid_start(&k, jid, fn_pause, NULL, false) != 0)
		return;
	remove_jail(jid);		/* Kills the process. */
	rc = read_to_eof(fd, k.pid, &exits, &events);
	ASSERT_MSG(rc == 0, "no end of file: %d", rc);
	printf("    exit of the killed process delivered: %s\n",
	    exits != 0 ? "yes" : "no");
	(void)jt_reap(k.pid);
	close(fd);
	ASSERT_MSG(wait_jail_gone(name), "removed jail still exists");
}

static void
test_reuse(void)
{
	struct oes_jail_scope_args args;
	char name[64], jidstr[16];
	int events, exits, fd, fd2, jid, jid2, rc, want;
	pid_t pid;

	TEST_BEGIN("T-REUSE-1 a new jail with the same jid is another jail");
	want = 20000 + (int)(getpid() % 10000);
	snprintf(jidstr, sizeof(jidstr), "%d", want);
	jid = scratch_jail("u1", name, sizeof(name), jidstr);
	fd = exit_client(want, 0);
	if (jid == -1 || fd < 0)
		return;
	ASSERT_MSG(jid == want, "jid %d, asked for %d", jid, want);
	remove_jail(jid);
	jid2 = scratch_jail("u1b", name, sizeof(name), jidstr);
	ASSERT_MSG(jid2 == want, "second jail: jid %d", jid2);
	fd2 = exit_client(want, 0);
	pid = jt_run_true(jid2);
	rc = read_to_eof(fd, pid, &exits, &events);
	ASSERT_MSG(rc == 0 && events == 0,
	    "old client: rc %d, %d events delivered", rc, events);
	EXPECT_OK(get_jail(fd, &args), "GET");
	ASSERT_MSG((args.ejs_flags & OES_JAIL_SCOPE_DEAD) != 0 &&
	    args.ejs_jid == want, "old client: flags 0x%x jid %d",
	    args.ejs_flags, args.ejs_jid);
	membership(fd2, "T-REUSE-1 new client", (int[]){ jid2 },
	    (bool[]){ true }, 1, jid2);
	close(fd);
	if (fd2 >= 0)
		close(fd2);
	remove_jail(jid2);

	TEST_BEGIN("T-REUSE-2 a new jail with the same name is another jail");
	jid = scratch_jail("u2", name, sizeof(name), NULL);
	fd = test_open_oes();
	EXPECT_OK(set_jail(fd, 0, name, 0), "set by name");
	EXPECT_OK(jt_notify_setup(fd, &(oes_event_type_t){
	    OES_EVENT_NOTIFY_EXIT }, 1), "setup");
	remove_jail(jid);
	jid2 = scratch_jail("u2", name, sizeof(name), NULL);
	pid = jt_run_true(jid2);
	rc = read_to_eof(fd, pid, &exits, &events);
	ASSERT_MSG(rc == 0 && events == 0,
	    "old client: rc %d, %d events delivered", rc, events);
	close(fd);
	remove_jail(jid2);
}

static void
test_dead_relatives(void)
{
	char pname[64], cname[80];
	int events, exits, fd, jid_p, jid_c, rc;

	TEST_BEGIN("T-DEAD-5 removing a nested jail leaves the scope alive");
	fd = exit_client(j_a, 0);
	remove_jail(j_d);
	j_d = -1;
	ASSERT_MSG(!is_dead(fd), "dead after a descendant was removed");
	membership(fd, "T-DEAD-5", (int[]){ j_c }, (bool[]){ true }, 1, j_a);
	if (fd >= 0)
		close(fd);

	TEST_BEGIN("T-DEAD-6 removing an ancestor ends the scope");
	jid_p = scratch_jail("p", pname, sizeof(pname), NULL);
	snprintf(cname, sizeof(cname), "%s.kid", pname);
	jid_c = jt_make_jail(cname, "oesjs-scratch", NULL, "1");
	fd = exit_client(jid_c, 0);
	if (jid_p == -1 || jid_c == -1 || fd < 0)
		return;
	remove_jail(jid_p);
	jt_forget_jail(jid_c);
	rc = read_to_eof(fd, -1, &exits, &events);
	ASSERT_MSG(rc == 0 && is_dead(fd), "not dead: rc %d", rc);
	close(fd);
	ASSERT_MSG(wait_jail_gone(cname) && wait_jail_gone(pname),
	    "removed jails still exist");
}

/*
 * The reference a scope holds on its jail must be dropped exactly once on
 * each path.  A leaked reference leaves the jail in the dying state for
 * ever, which jail_get(2) shows only with JAIL_DYING; first show that this
 * check does see a jail kept dying by a reference (a zombie's credential).
 */
static void
test_references(void)
{
	char name[64];
	struct kid k;
	int fd, i, jid;

	TEST_BEGIN("T-REF-0 control: a held jail is seen as dying");
	jid = scratch_jail("z", name, sizeof(name), NULL);
	if (jid == -1 || kid_start(&k, jid, fn_pause, NULL, false) != 0)
		return;
	remove_jail(jid);		/* Kills the child; not reaped yet. */
	usleep(300000);
	ASSERT_MSG(jail_getid(name) == -1, "removed jail still alive");
	ASSERT_MSG(jt_jail_exists_dying(name),
	    "control failed: a jail held by a zombie is not reported dying");
	(void)jt_reap(k.pid);
	ASSERT_MSG(wait_jail_gone(name), "jail still dying after the reap");

	TEST_BEGIN("T-REF-1 close before removal releases the jail");
	jid = scratch_jail("c1", name, sizeof(name), NULL);
	fd = exit_client(jid, 0);
	if (jid == -1 || fd < 0)
		return;
	close(fd);
	remove_jail(jid);
	ASSERT_MSG(wait_jail_gone(name), "jail still dying: leaked by close");

	TEST_BEGIN("T-REF-2 removal before close releases the jail");
	jid = scratch_jail("c2", name, sizeof(name), NULL);
	fd = exit_client(jid, 0);
	if (jid == -1 || fd < 0)
		return;
	remove_jail(jid);
	ASSERT_MSG(wait_jail_gone(name),
	    "jail still dying: leaked by the removal");
	close(fd);

	TEST_BEGIN("T-REF-3 several clients, events in flight");
	for (i = 0; i < 10; i++) {
		int fds[3], n;

		jid = scratch_jail("c3", name, sizeof(name), NULL);
		if (jid == -1)
			return;
		for (n = 0; n < 3; n++)
			fds[n] = exit_client(jid, n == 1 ?
			    OES_JAIL_SCOPE_NOCHILDREN : 0);
		(void)jt_run_true(jid);
		(void)jt_run_true(jid);
		close(fds[0]);
		remove_jail(jid);
		close(fds[1]);
		if (!wait_jail_gone(name)) {
			TEST_FAIL("round %d: jail still dying", i);
			close(fds[2]);
			return;
		}
		close(fds[2]);
	}
}

struct stress {
	char		name[64];
	volatile int	stop;
	int		sets;
	int		failures;
};

static void *
stress_setter(void *arg)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_EXIT;
	struct stress *s = arg;
	int fd;

	while (!s->stop) {
		fd = test_open_oes();
		if (fd < 0) {
			s->failures++;
			break;
		}
		if (set_jail(fd, 0, s->name, 0) == 0) {
			s->sets++;
			if (jt_notify_setup(fd, &ev, 1) != 0)
				s->failures++;
		} else if (errno != ENOENT)
			s->failures++;
		close(fd);
	}
	return (NULL);
}

static void
test_stress(void)
{
	struct stress s;
	pthread_t th[2];
	int i, jid;

	TEST_BEGIN("T-STRESS set scope, remove jail and close, concurrently");
	memset(&s, 0, sizeof(s));
	jt_name(s.name, sizeof(s.name), "oesjs", "stress");
	if (pthread_create(&th[0], NULL, stress_setter, &s) != 0 ||
	    pthread_create(&th[1], NULL, stress_setter, &s) != 0) {
		TEST_FAIL("pthread_create");
		return;
	}
	for (i = 0; i < 150; i++) {
		jid = jail_setv(JAIL_CREATE, "name", s.name, "path", "/",
		    "persist", NULL, NULL);
		if (jid == -1) {
			TEST_FAIL("round %d: create: %s", i, jail_errmsg);
			break;
		}
		if ((i & 3) == 0)
			(void)jt_run_true(jid);
		usleep(2000);
		if (jail_remove(jid) != 0) {
			TEST_FAIL("round %d: remove: %s", i, strerror(errno));
			break;
		}
	}
	s.stop = 1;
	pthread_join(th[0], NULL);
	pthread_join(th[1], NULL);
	printf("    %d scopes set while the jail came and went\n", s.sets);
	ASSERT_MSG(s.failures == 0, "%d unexpected errors", s.failures);
	ASSERT_MSG(s.sets > 0, "no scope was ever set: the race never ran");
	ASSERT_MSG(wait_jail_gone(s.name), "stress jail still exists (dying)");
}

/* ---------------------------------------------------------------- AUTH -- */

static int
auth_client(int jid, uint32_t deadline_ms, oes_event_type_t *evs, size_t n)
{
	struct oes_mode_args mode;
	int fd;

	fd = test_open_oes();
	if (fd < 0 || set_jail(fd, jid, NULL, 0) != 0) {
		TEST_FAIL("AUTH client: %s", strerror(errno));
		return (-1);
	}
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_default_deadline_ms = deadline_ms;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) != 0 ||
	    test_subscribe(fd, evs, n, OES_SUB_REPLACE) != 0) {
		TEST_FAIL("AUTH mode/subscribe: %s", strerror(errno));
		close(fd);
		return (-1);
	}
	return (fd);
}

/* Host work that a jail-scoped AUTH client must never hold up. */
static int
fn_host_work(void *arg __unused)
{
	pid_t pid;
	int fd, i;

	for (i = 0; i < 50; i++) {
		fd = open(file1, O_RDONLY);
		if (fd < 0)
			return (80);
		close(fd);
	}
	for (i = 0; i < 3; i++) {
		pid = fork();
		if (pid == 0) {
			execl("/usr/bin/true", "true", (char *)NULL);
			_exit(127);
		}
		if (jt_reap(pid) != 0)
			return (81);
	}
	return (0);
}

static void
outside_never_waits(int fd, const char *what)
{
	struct timespec start;
	struct oes_stats st;
	struct kid k;
	long ms;
	int rc;

	if (kid_start(&k, -1, fn_host_work, NULL, true) != 0) {
		TEST_FAIL("%s: host worker", what);
		return;
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	rc = kid_finish(&k);
	ms = jt_elapsed_ms(&start);
	get_stats(fd, &st);
	printf("    %s: 50 opens and 3 execs outside the jail took %ld ms\n",
	    what, ms);
	ASSERT_MSG(rc == 0, "%s: host worker status %d", what, rc);
	ASSERT_MSG(st.es_events_received == 0,
	    "%s: %ju events of an outside process reached the client", what,
	    (uintmax_t)st.es_events_received);
	/* One held operation alone would cost the whole 3000 ms deadline. */
	ASSERT_MSG(ms < 2500, "%s: outside work took %ld ms", what, ms);
}

static int
fn_idle_descendants_client(void *arg __unused)
{
	int fd;

	fd = test_open_oes();
	if (fd < 0 || test_set_descendants_scope(fd) != 0 ||
	    test_set_mode(fd, OES_MODE_NOTIFY) != 0)
		return (90);
	for (;;)
		pause();
}

static void
test_auth(void)
{
	oes_event_type_t evs[] = { OES_EVENT_AUTH_OPEN, OES_EVENT_AUTH_EXEC };
	struct open_arg oa = { file1, 1, O_RDONLY };
	struct timespec start;
	struct oes_stats st;
	struct kid k, wide;
	test_msg_buf buf;
	oes_response_t resp;
	long ms;
	int fd, rc;
	bool denied;

	TEST_BEGIN("T-AUTH-1 an unanswering AUTH client holds only its jail");
	fd = auth_client(j_a, 3000, evs, 2);
	if (fd < 0)
		return;
	outside_never_waits(fd, "T-AUTH-1");
	if (kid_start(&k, j_a, fn_open, &oa, true) == 0) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		rc = kid_finish(&k);
		ms = jt_elapsed_ms(&start);
		get_stats(fd, &st);
		printf("    one open inside the jail took %ld ms\n", ms);
		ASSERT_MSG(rc == 0, "jailed open status %d (fail-open expected)",
		    rc);
		ASSERT_MSG(ms >= 2500, "jailed open was not held: %ld ms", ms);
		ASSERT_MSG(st.es_events_received == 1 &&
		    st.es_auth_timeouts == 1, "received %ju timeouts %ju",
		    (uintmax_t)st.es_events_received,
		    (uintmax_t)st.es_auth_timeouts);
	}
	close(fd);

	TEST_BEGIN("T-AUTH-2 the same with a client of another scope open");
	if (kid_start(&wide, -1, fn_idle_descendants_client, NULL, false) != 0) {
		TEST_FAIL("idle descendants client");
		return;
	}
	fd = auth_client(j_a, 3000, evs, 2);
	if (fd >= 0) {
		outside_never_waits(fd, "T-AUTH-2");
		close(fd);
	}
	kid_kill(&wide);

	TEST_BEGIN("T-AUTH-3 a jail-scoped client denies inside, not outside");
	fd = auth_client(j_a, 10000, evs, 1);
	if (fd < 0)
		return;
	if (kid_start(&k, -1, fn_open, &oa, false) != 0)
		return;
	rc = kid_finish(&k);
	ASSERT_MSG(rc == 0, "host open status %d", rc);
	if (kid_start(&k, j_a, fn_open, &oa, true) != 0)
		return;
	kid_go(&k);
	denied = false;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (!denied && jt_elapsed_ms(&start) < WAIT_MS) {
		if (test_wait_event(fd, &buf.msg, 100) != 0)
			continue;
		if (buf.msg.em_action != OES_ACTION_AUTH)
			continue;
		memset(&resp, 0, sizeof(resp));
		resp.er_id = buf.msg.em_id;
		resp.er_result = OES_AUTH_ALLOW;
		if (buf.msg.em_process.ep_pid == k.pid &&
		    buf.msg.em_event == OES_EVENT_AUTH_OPEN &&
		    buf.msg.em_event_data.open.file.ef_token.eft_id == ino1) {
			resp.er_result = OES_AUTH_DENY;
			denied = true;
		}
		(void)write(fd, &resp, sizeof(resp));
	}
	rc = jt_reap(k.pid);
	ASSERT_MSG(denied && rc == 50, "jailed open: denied %d status %d",
	    denied, rc);
	get_stats(fd, &st);
	ASSERT_MSG(st.es_events_received == 1, "received %ju",
	    (uintmax_t)st.es_events_received);
	close(fd);
}

/*
 * A reader blocked on a dead-to-be AUTH client whose only event expired
 * unread must get end of file, not trip over the empty queue.
 */
static void
test_dead_auth_reader(void)
{
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	struct open_arg oa = { file1, 1, O_RDONLY };
	struct reader r;
	struct kid k;
	pthread_t th;
	char name[64];
	int fd, jid, rc;

	TEST_BEGIN("T-DEAD-AUTH removal with an expired AUTH event unread");
	jid = scratch_jail("ra", name, sizeof(name), NULL);
	if (jid == -1)
		return;
	fd = auth_client(jid, OES_MIN_DEADLINE_MS, &ev, 1);
	if (fd < 0 || kid_start(&k, jid, fn_open, &oa, false) != 0)
		return;
	rc = kid_finish(&k);		/* Held for the deadline, then allowed. */
	ASSERT_MSG(rc == 0, "jailed open status %d", rc);
	EXPECT_OK(fcntl(fd, F_SETFL, 0), "clear O_NONBLOCK");
	memset(&r, 0, sizeof(r));
	r.fd = fd;
	if (pthread_create(&th, NULL, reader_thread, &r) != 0) {
		TEST_FAIL("pthread_create");
		return;
	}
	usleep(300000);
	ASSERT_MSG(!r.done, "reader returned before the removal: %zd errno %d",
	    r.n, r.error);
	remove_jail(jid);
	if (!reader_wait(&r)) {
		TEST_FAIL("blocked reader not woken by the removal");
		return;
	}
	pthread_join(th, NULL);
	ASSERT_MSG(r.n == 0, "blocked read: %zd errno %d", r.n, r.error);
	close(fd);
}

/* --------------------------------------------------------------- mutes -- */

static int
fn_setuid_nobody(void *arg __unused)
{

	return (setgid(65534) == 0 && setuid(65534) == 0 ? 0 : 95);
}

static void
test_mutes(void)
{
	struct oes_mute_invert_args inv;
	struct oes_mute_uid_args mu;
	struct kid v, v2, outside;
	struct rec recs[2];
	pid_t marker, pid;
	int fd;

	TEST_BEGIN("T-MUTE-1 process mutes: only processes in scope");
	fd = exit_client(j_a, 0);
	if (fd < 0 || kid_start(&v, j_a, fn_pause, NULL, false) != 0 ||
	    kid_start(&outside, j_s, fn_pause, NULL, false) != 0)
		return;
	EXPECT_OK(jt_mute_pid(fd, v.pid), "mute a process in the jail");
	EXPECT_ERRNO(jt_mute_pid(fd, getpid()), EPERM, "mute a host process");
	EXPECT_ERRNO(jt_mute_pid(fd, outside.pid), EPERM,
	    "mute a process in a sibling jail");
	memset(recs, 0, sizeof(recs));
	recs[0].pid = v.pid;
	kid_kill(&v);
	kid_kill(&outside);
	marker = jt_run_true(j_a);
	if (scan(fd, marker, OES_EVENT_NOTIFY_EXIT, recs, 1) != 0)
		TEST_FAIL("marker not delivered");
	ASSERT_MSG(recs[0].exits == 0, "muted process was delivered");
	close(fd);

	TEST_BEGIN("T-MUTE-1b NOCHILDREN: a nested process is out of scope");
	fd = exit_client(j_a, OES_JAIL_SCOPE_NOCHILDREN);
	if (fd < 0 || kid_start(&v, j_b, fn_pause, NULL, false) != 0)
		return;
	EXPECT_ERRNO(jt_mute_pid(fd, v.pid), EPERM, "mute a nested process");
	kid_kill(&v);
	close(fd);

	TEST_BEGIN("T-MUTE-2 inverted process mute selects within the scope");
	fd = exit_client(j_a, 0);
	if (fd < 0 || kid_start(&v, j_a, fn_pause, NULL, false) != 0 ||
	    kid_start(&v2, j_a, fn_pause, NULL, false) != 0)
		return;
	inv.emi_type = OES_MUTE_INVERT_PROCESS;
	inv.emi_invert = 1;
	EXPECT_OK(ioctl(fd, OES_IOC_SET_MUTE_INVERT, &inv), "invert");
	EXPECT_OK(jt_mute_pid(fd, v.pid), "select a process");
	memset(recs, 0, sizeof(recs));
	recs[0].pid = v2.pid;
	pid = v.pid;
	kid_kill(&v2);
	kid_kill(&v);
	if (scan(fd, pid, OES_EVENT_NOTIFY_EXIT, recs, 1) != 0)
		TEST_FAIL("selected process not delivered");
	ASSERT_MSG(recs[0].exits == 0, "unselected process was delivered");
	close(fd);

	TEST_BEGIN("T-MUTE-3 uid mute within the scope");
	fd = exit_client(j_a, 0);
	if (fd < 0)
		return;
	mu.emu_uid = 65534;
	EXPECT_OK(ioctl(fd, OES_IOC_MUTE_UID, &mu), "mute uid");
	if (kid_start(&v, j_a, fn_setuid_nobody, NULL, false) != 0)
		return;
	ASSERT_MSG(kid_finish(&v) == 0, "setuid child");
	memset(recs, 0, sizeof(recs));
	recs[0].pid = v.pid;
	marker = jt_run_true(j_a);
	if (scan(fd, marker, OES_EVENT_NOTIFY_EXIT, recs, 1) != 0)
		TEST_FAIL("marker not delivered");
	ASSERT_MSG(recs[0].exits == 0, "uid-muted process was delivered");
	close(fd);
}

/* T-SELF-1 child: a client inside the jail it watches does not see itself. */
static int
self_mute_child(int ready_fd, int go_fd)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_OPEN;
	struct rec recs[2];
	pid_t other;
	int f, fd;

	fd = test_open_oes();
	if (fd < 0 || jail_attach(j_a) != 0)
		return (1);
	if (set_jail(fd, 0, NULL, 0) != 0 || jt_notify_setup(fd, &ev, 1) != 0)
		return (2);
	f = open(file1, O_RDONLY);
	if (f < 0)
		return (3);
	close(f);
	if (write(ready_fd, "R", 1) != 1)
		return (4);
	if (read(go_fd, &other, sizeof(other)) != sizeof(other))
		return (5);
	memset(recs, 0, sizeof(recs));
	recs[0].pid = getpid();
	recs[1].pid = other;
	/* The other process opened file1 once: that open is the marker. */
	if (scan(fd, other, OES_EVENT_NOTIFY_OPEN, recs, 2) != 0)
		return (6);
	if (recs[0].open1 != 0 || recs[0].other != 0)
		return (7);
	if (recs[1].open1 != 1)
		return (8);
	return (0);
}

static void
test_self_mute(void)
{
	struct open_arg oa = { file1, 1, O_RDONLY };
	int ready[2], go[2], rc;
	struct kid k;
	pid_t child;
	char byte;

	/*
	 * No knob since the no-self-events rule (oes(4), "A client's own
	 * processes"): the case always runs.
	 */
	TEST_BEGIN("T-SELF-1 a client inside the watched jail never sees itself");
	if (pipe(ready) != 0 || pipe(go) != 0)
		return;
	fflush(NULL);
	child = fork();
	if (child == 0) {
		close(ready[0]);
		close(go[1]);
		_exit(self_mute_child(ready[1], go[0]));
	}
	close(ready[1]);
	close(go[0]);
	if (read(ready[0], &byte, 1) != 1) {
		rc = jt_reap(child);
		TEST_FAIL("self-mute child failed at step %d", rc);
	} else if (kid_start(&k, j_a, fn_open, &oa, false) == 0) {
		ASSERT_MSG(kid_finish(&k) == 0, "other opener");
		(void)write(go[1], &k.pid, sizeof(k.pid));
		rc = jt_reap(child);
		ASSERT_MSG(rc == 0, "self-mute child failed at step %d", rc);
	}
	close(ready[0]);
	close(go[1]);
}

/* ---------------------------------------- filter before allocation -- */

static int restore_miss_mode = -1;

static void
restore_knob(void)
{

	if (restore_miss_mode != -1)
		(void)sysctlbyname("security.oes.default_deadline_miss_mode",
		    NULL, NULL, &restore_miss_mode, sizeof(restore_miss_mode));
	restore_miss_mode = -1;
}

struct rename_arg {
	char	from[64];
	char	to[64];
};

static int
fn_rename(void *arg)
{
	struct rename_arg *ra = arg;

	return (rename(ra->from, ra->to) == 0 ? 0 : 96);
}

static int
fn_mprotect(void *arg __unused)
{
	void *p;

	p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
	    -1, 0);
	if (p == MAP_FAILED)
		return (97);
	return (mprotect(p, 4096, PROT_READ) == 0 ? 0 : 98);
}

static uint64_t
filtered(void)
{

	return (sysctl_u64("security.oes.jail_filtered"));
}

static uint64_t
filtered_auth(void)
{

	return (sysctl_u64("security.oes.jail_filtered_auth"));
}

/*
 * These cases need every open client in the guest to be jail-scoped: one
 * global or descendants-scoped client anywhere switches the filter off.
 * They fail, rather than skip, when the counter does not move, so a run in
 * which the filter was never exercised cannot pass.
 */
static void
test_filter(void)
{
	oes_event_type_t evs[] = { OES_EVENT_NOTIFY_OPEN,
	    OES_EVENT_NOTIFY_EXIT, OES_EVENT_NOTIFY_RENAME,
	    OES_EVENT_NOTIFY_MPROTECT };
	struct open_arg host_opens = { file1, 500, O_RDONLY };
	struct open_arg jail_opens = { file1, 5, O_RDONLY };
	struct open_arg few_opens = { file1, 100, O_RDONLY };
	struct rename_arg ra;
	struct rec recs[2];
	struct kid h, j;
	uint64_t a0, a1, a2, c0, c1, c2;
	char name[64];
	int events, exits, fd, jid, mode, rc, tfd;
	test_msg_buf buf;
	bool seen;

	TEST_BEGIN("T-FILT-0 the counters exist");
	c0 = filtered();
	a0 = filtered_auth();
	ASSERT_MSG(c0 != UINT64_MAX && a0 != UINT64_MAX,
	    "security.oes.jail_filtered[_auth] missing");
	usleep(200000);
	ASSERT_MSG(filtered() == c0,
	    "counter moves with no jail-scoped client open");

	TEST_BEGIN("T-FILT-1 outside events are dropped before allocation");
	fd = jclient(j_a, 0, evs, 4);
	if (fd < 0)
		return;
	c0 = filtered();
	a0 = filtered_auth();
	if (kid_start(&h, -1, fn_open, &host_opens, false) != 0 ||
	    kid_finish(&h) != 0) {
		TEST_FAIL("host opener");
		return;
	}
	c1 = filtered();
	a1 = filtered_auth();
	printf("    500 outside opens: filtered +%ju, AUTH filtered +%ju\n",
	    (uintmax_t)(c1 - c0), (uintmax_t)(a1 - a0));
	ASSERT_MSG(c1 - c0 >= 500 && a1 - a0 >= 500,
	    "filter did not run (+%ju, AUTH +%ju): is a client that is not "
	    "jail-scoped open in this guest?", (uintmax_t)(c1 - c0),
	    (uintmax_t)(a1 - a0));
	if (kid_start(&j, j_a, fn_open, &jail_opens, false) != 0 ||
	    kid_finish(&j) != 0) {
		TEST_FAIL("jailed opener");
		return;
	}
	memset(recs, 0, sizeof(recs));
	recs[0].pid = h.pid;
	recs[1].pid = j.pid;
	if (scan(fd, j.pid, OES_EVENT_NOTIFY_EXIT, recs, 2) != 0)
		TEST_FAIL("jailed opener's exit not delivered");
	ASSERT_MSG(recs[1].open1 == 5, "jailed opens delivered: %d",
	    recs[1].open1);
	ASSERT_MSG(recs[0].open1 == 0 && recs[0].exits == 0 &&
	    recs[0].other == 0, "outside process was delivered");

	TEST_BEGIN("T-FILT-3 rename: outside dropped, inside delivered");
	snprintf(ra.from, sizeof(ra.from), "/tmp/oesjs-rn.%d.a", (int)getpid());
	snprintf(ra.to, sizeof(ra.to), "/tmp/oesjs-rn.%d.b", (int)getpid());
	tfd = open(ra.from, O_CREAT | O_WRONLY, 0600);
	if (tfd >= 0)
		close(tfd);
	c0 = filtered_auth();
	rc = kid_start(&h, -1, fn_rename, &ra, false) == 0 ?
	    kid_finish(&h) : -1;
	ASSERT_MSG(rc == 0, "outside rename status %d", rc);
	ASSERT_MSG(filtered_auth() > c0, "outside rename was not filtered");
	{
		struct rename_arg back;

		strlcpy(back.from, ra.to, sizeof(back.from));
		strlcpy(back.to, ra.from, sizeof(back.to));
		rc = kid_start(&j, j_a, fn_rename, &back, false) == 0 ?
		    kid_finish(&j) : -1;
	}
	ASSERT_MSG(rc == 0, "jailed rename status %d", rc);
	seen = false;
	while (jt_collect(fd, j.pid, OES_EVENT_NOTIFY_RENAME, 2000, &buf) ==
	    0) {
		seen = true;
		break;
	}
	ASSERT_MSG(seen, "jailed rename not delivered");
	unlink(ra.from);
	unlink(ra.to);

	TEST_BEGIN("T-FILT-4 mprotect: outside dropped, inside delivered");
	c0 = filtered_auth();
	rc = kid_start(&h, -1, fn_mprotect, NULL, false) == 0 ?
	    kid_finish(&h) : -1;
	ASSERT_MSG(rc == 0, "outside mprotect status %d", rc);
	ASSERT_MSG(filtered_auth() > c0, "outside mprotect was not filtered");
	rc = kid_start(&j, j_a, fn_mprotect, NULL, false) == 0 ?
	    kid_finish(&j) : -1;
	ASSERT_MSG(rc == 0, "jailed mprotect status %d", rc);
	ASSERT_MSG(jt_collect(fd, j.pid, OES_EVENT_NOTIFY_MPROTECT, WAIT_MS,
	    &buf) == 0, "jailed mprotect not delivered");

	/*
	 * A strict policy keeps AUTH events on the normal path.  Of the three
	 * knobs only the default deadline-miss mode can be set safely in a
	 * running guest: it denies nothing by itself, whereas
	 * require_auth_clients and auth_fail_closed deny every operation that
	 * no client answers, the next sysctl(8) included.
	 */
	TEST_BEGIN("T-FILT-5 a strict policy keeps AUTH events unfiltered");
	mode = sysctl_int("security.oes.default_deadline_miss_mode");
	if (mode != OES_DEADLINE_MISS_FAIL_OPEN) {
		TEST_FAIL("default_deadline_miss_mode is %d", mode);
	} else {
		int closed = OES_DEADLINE_MISS_FAIL_CLOSED;

		restore_miss_mode = mode;
		(void)atexit(restore_knob);
		rc = sysctlbyname("security.oes.default_deadline_miss_mode",
		    NULL, NULL, &closed, sizeof(closed));
		a0 = filtered_auth();
		if (rc == 0 && kid_start(&h, -1, fn_open, &few_opens, false) ==
		    0)
			rc = kid_finish(&h);
		a1 = filtered_auth();
		restore_knob();
		ASSERT_MSG(rc == 0, "strict run status %d", rc);
		ASSERT_MSG(a1 == a0, "AUTH events filtered under a strict "
		    "policy: +%ju", (uintmax_t)(a1 - a0));
		a2 = filtered_auth();
		if (kid_start(&h, -1, fn_open, &few_opens, false) == 0)
			(void)kid_finish(&h);
		ASSERT_MSG(filtered_auth() - a2 >= 100,
		    "filter did not resume after the policy was relaxed");
	}
	close(fd);

	TEST_BEGIN("T-FILT-2 a dead scope filters everything");
	jid = scratch_jail("f2", name, sizeof(name), NULL);
	fd = jclient(jid, 0, evs, 2);
	if (jid == -1 || fd < 0)
		return;
	remove_jail(jid);
	rc = read_to_eof(fd, -1, &exits, &events);
	ASSERT_MSG(rc == 0 && events == 0, "dead client: rc %d events %d", rc,
	    events);
	c0 = filtered();
	if (kid_start(&h, -1, fn_open, &few_opens, false) == 0)
		(void)kid_finish(&h);
	c2 = filtered();
	ASSERT_MSG(c2 - c0 >= 100, "dead scope: filtered +%ju",
	    (uintmax_t)(c2 - c0));
	rc = read_to_eof(fd, -1, &exits, &events);
	ASSERT_MSG(rc == 0 && events == 0, "dead client received %d events",
	    events);
	close(fd);
}

/*
 * A decision cached by a jail-scoped client must still be invalidated when
 * a process outside the jail changes the file, although that process's
 * events are otherwise dropped before allocation.
 */
static void
test_cache_invalidation(void)
{
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	struct open_arg oa = { file2, 1, O_RDONLY };
	struct timespec start;
	oes_cache_entry_t entry;
	struct oes_stats st;
	oes_response_t resp;
	test_msg_buf buf;
	struct kid k, h;
	uint64_t c0;
	bool added;
	int fd, rc;

	TEST_BEGIN("T-CACHE-2 an outside writer invalidates the jail's cache");
	fd = auth_client(j_a, 10000, &ev, 1);
	if (fd < 0 || kid_start(&k, j_a, fn_open, &oa, true) != 0)
		return;
	kid_go(&k);
	added = false;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (!added && jt_elapsed_ms(&start) < WAIT_MS) {
		if (test_wait_event(fd, &buf.msg, 100) != 0 ||
		    buf.msg.em_action != OES_ACTION_AUTH)
			continue;
		if (buf.msg.em_process.ep_pid == k.pid &&
		    buf.msg.em_event_data.open.file.ef_token.eft_id == ino2) {
			memset(&entry, 0, sizeof(entry));
			entry.ece_key.eck_event = OES_EVENT_AUTH_OPEN;
			entry.ece_key.eck_flags = OES_CACHE_KEY_PROCESS |
			    OES_CACHE_KEY_FILE;
			entry.ece_key.eck_op_flags =
			    buf.msg.em_event_data.open.access;
			entry.ece_key.eck_process = buf.msg.em_process.ep_token;
			entry.ece_key.eck_exec_id =
			    buf.msg.em_process.ep_exec_id;
			entry.ece_key.eck_file =
			    buf.msg.em_event_data.open.file.ef_token;
			entry.ece_result = OES_AUTH_ALLOW;
			entry.ece_ttl_ms = 60000;
			EXPECT_OK(ioctl(fd, OES_IOC_CACHE_ADD, &entry),
			    "CACHE_ADD");
			added = true;
		}
		memset(&resp, 0, sizeof(resp));
		resp.er_id = buf.msg.em_id;
		resp.er_result = OES_AUTH_ALLOW;
		(void)write(fd, &resp, sizeof(resp));
	}
	rc = jt_reap(k.pid);
	ASSERT_MSG(added && rc == 0, "jailed open: added %d status %d", added,
	    rc);
	get_stats(fd, &st);
	ASSERT_MSG(st.es_cache_entries == 1, "cache entries %u",
	    st.es_cache_entries);
	c0 = sysctl_u64("security.oes.jail_filtered_auth");
	rc = kid_start(&h, -1, fn_append, file2, false) == 0 ?
	    kid_finish(&h) : -1;
	ASSERT_MSG(rc == 0, "outside writer status %d", rc);
	get_stats(fd, &st);
	ASSERT_MSG(st.es_cache_entries == 0,
	    "cache entries after an outside write: %u", st.es_cache_entries);
	/* With the cache empty again, outside writes are dropped early. */
	c0 = sysctl_u64("security.oes.jail_filtered_auth");
	rc = kid_start(&h, -1, fn_append, file2, false) == 0 ?
	    kid_finish(&h) : -1;
	ASSERT_MSG(rc == 0 &&
	    sysctl_u64("security.oes.jail_filtered_auth") > c0,
	    "outside write not filtered once the cache is empty");
	close(fd);
}

static int
fn_append(void *arg)
{
	int fd;

	fd = open((const char *)arg, O_WRONLY | O_APPEND);
	if (fd < 0)
		return (99);
	if (write(fd, "x", 1) != 1)
		return (100);
	close(fd);
	return (0);
}

int
main(void)
{
	struct stat sb;
	int fd;

	TEST_SUITE_BEGIN("jail scope");
	if (geteuid() != 0) {
		TEST_SKIP("requires root");
		return (0);
	}
	(void)atexit(jt_remove_jails);

	fd = mkstemp(file1);
	if (fd < 0 || fstat(fd, &sb) != 0)
		return (1);
	ino1 = sb.st_ino;
	close(fd);
	fd = mkstemp(file2);
	if (fd < 0 || fstat(fd, &sb) != 0)
		return (1);
	ino2 = sb.st_ino;
	close(fd);
	(void)chmod(file1, 0644);
	(void)chmod(file2, 0666);

	jt_name(n_a, sizeof(n_a), "oesjs", "a");
	snprintf(n_b, sizeof(n_b), "%s.b", n_a);
	snprintf(n_c, sizeof(n_c), "%s.c", n_b);
	snprintf(n_d, sizeof(n_d), "%s.d", n_c);
	jt_name(n_s, sizeof(n_s), "oesjs", "s");
	j_a = jt_make_jail(n_a, "oesjs-a", NULL, "8");
	if (j_a != -1)
		j_b = jt_make_jail(n_b, "oesjs-b", NULL, "6");
	if (j_b != -1)
		j_c = jt_make_jail(n_c, "oesjs-c", NULL, "4");
	if (j_c != -1)
		j_d = jt_make_jail(n_d, "oesjs-d", NULL, "2");
	j_s = jt_make_jail(n_s, "oesjs-s", NULL, "2");
	if (j_a == -1 || j_b == -1 || j_c == -1 || j_d == -1 || j_s == -1) {
		TEST_FAIL("cannot create the test jails");
		return (1);
	}

	/* First: needs no other client, of this test or any other, open. */
	test_filter();
	test_cache_invalidation();

	test_arguments();
	test_third_party_ioctls();
	test_membership();
	test_passive();
	test_entering();
	test_multithreaded_attach();
	test_event_kinds();
	test_scopes_together();
	test_rooted_jail();
	test_rename_jail();
	test_linux();
	test_inbound();
	test_jailed_caller();
	test_getter_views();
	test_getter_stress();
	test_mutes();
	test_self_mute();
	test_auth();

	test_dead_blocked_reader();
	test_dead_queued();
	test_dead_poll_select();
	test_dead_under_load();
	test_dead_behind_backlog();
	test_dead_last_exit();
	test_dead_kqueue();
	test_dead_with_process();
	test_dead_auth_reader();
	test_reuse();
	test_dead_relatives();
	test_references();
	test_stress();

	jt_remove_jails();
	unlink(file1);
	unlink(file2);
	if (oes_test_failures == 0)
		TEST_SUITE_END("jail scope");
	return (oes_test_failures != 0);
}
