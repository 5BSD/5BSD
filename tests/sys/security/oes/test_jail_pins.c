/*
 * Behaviour the jail scope must not change: the errnos of the existing
 * scope ioctl, what global and descendants-scoped clients see of jailed
 * processes, and how an idle client reads and polls.  Every case here must
 * pass on a kernel without the jail scope as well as with it.
 */
#include <sys/types.h>

#include "test_jail_common.h"

static char jail_a[64], jail_b[80];
static int jid_a = -1, jid_b = -1;

static int
set_scope(int fd, uint32_t scope, uint32_t reserved)
{
	struct oes_scope_args args;

	args.esa_scope = scope;
	args.esa_reserved = reserved;
	return (ioctl(fd, OES_IOC_SET_SCOPE, &args));
}

static void
expect_errno(const char *what, int rc, int want)
{

	ASSERT_MSG(rc == -1 && errno == want, "%s: rc %d errno %d, want errno %d",
	    what, rc, rc == -1 ? errno : 0, want);
}

static void
test_set_scope_errnos(void)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_EXEC;
	int fd;

	TEST_BEGIN("P1 unknown scope values are EINVAL");
	fd = test_open_oes();
	ASSERT_MSG(fd >= 0, "open: %s", strerror(errno));
	expect_errno("scope 0", set_scope(fd, 0, 0), EINVAL);
	expect_errno("scope 2", set_scope(fd, 2, 0), EINVAL);
	expect_errno("scope 7", set_scope(fd, 7, 0), EINVAL);
	ASSERT_MSG(jt_get_scope(fd) == OES_SCOPE_GLOBAL, "scope changed");

	TEST_BEGIN("P2 reserved field is EINVAL");
	expect_errno("reserved", set_scope(fd, OES_SCOPE_DESCENDANTS, 1),
	    EINVAL);
	ASSERT_MSG(jt_get_scope(fd) == OES_SCOPE_GLOBAL, "scope changed");
	close(fd);

	TEST_BEGIN("P3 scope after mode is EBUSY");
	fd = test_open_oes();
	ASSERT_MSG(test_set_mode(fd, OES_MODE_NOTIFY) == 0, "set mode");
	expect_errno("after mode", set_scope(fd, OES_SCOPE_DESCENDANTS, 0),
	    EBUSY);
	TEST_BEGIN("P5 EINVAL precedes EBUSY");
	expect_errno("scope 2 after mode", set_scope(fd, 2, 0), EINVAL);
	close(fd);

	TEST_BEGIN("P4 scope after subscribe is EBUSY");
	fd = test_open_oes();
	ASSERT_MSG(test_subscribe(fd, &ev, 1, OES_SUB_ADD) == 0,
	    "subscribe: %s", strerror(errno));
	expect_errno("after subscribe", set_scope(fd, OES_SCOPE_DESCENDANTS,
	    0), EBUSY);
	close(fd);
}

/* Runs in a child: selecting the scope relabels the caller's credential. */
static int
child_scope_twice(void)
{
	int fd;

	fd = test_open_oes();
	if (fd < 0)
		return (10);
	if (set_scope(fd, OES_SCOPE_DESCENDANTS, 0) != 0)
		return (11);
	if (set_scope(fd, OES_SCOPE_DESCENDANTS, 0) != 0)
		return (12);
	if (jt_get_scope(fd) != OES_SCOPE_DESCENDANTS)
		return (13);
	return (0);
}

static void
test_global_sees_jailed(void)
{
	oes_event_type_t evs[] = { OES_EVENT_NOTIFY_EXEC,
	    OES_EVENT_NOTIFY_EXIT };
	test_msg_buf buf;
	/*
	 * The exec record's target is filled with the process locked.  The
	 * subject of an event is filled only if its lock can be had at
	 * once, so it is not a reliable place to look for jail details.
	 */
	const oes_process_t *tp = &buf.msg.em_event_data.exec.target;
	pid_t pid;
	int fd;

	fd = test_open_oes();
	ASSERT_MSG(fd >= 0 && jt_notify_setup(fd, evs, 2) == 0, "client");

	TEST_BEGIN("P7 global client sees a jailed process");
	pid = jt_run_true(jid_a);
	ASSERT_MSG(pid > 0, "run in A");
	if (jt_collect(fd, pid, OES_EVENT_NOTIFY_EXEC, 5000, &buf) != 0)
		TEST_FAIL("no EXEC of the jailed process");
	else {
		ASSERT_MSG(tp->ep_jid == jid_a, "ep_jid %d != %d",
		    tp->ep_jid, jid_a);
		ASSERT_MSG((tp->ep_flags & EP_FLAG_JAILED) != 0,
		    "EP_FLAG_JAILED clear");
		ASSERT_MSG(strcmp(oes_msg_string(&buf.msg,
		    tp->ep_jailname_off), "oespin-host-a") == 0,
		    "jailname '%s'", oes_msg_string(&buf.msg,
		    tp->ep_jailname_off));
	}

	TEST_BEGIN("P8 global client sees a nested-jail process");
	pid = jt_run_true(jid_b);
	ASSERT_MSG(pid > 0, "run in A.b");
	if (jt_collect(fd, pid, OES_EVENT_NOTIFY_EXEC, 5000, &buf) != 0)
		TEST_FAIL("no EXEC of the nested process");
	else {
		ASSERT_MSG(tp->ep_jid == jid_b, "ep_jid %d != %d",
		    tp->ep_jid, jid_b);
		ASSERT_MSG((tp->ep_flags & EP_FLAG_JAILED) != 0,
		    "EP_FLAG_JAILED clear");
		ASSERT_MSG(strcmp(oes_msg_string(&buf.msg,
		    tp->ep_jailname_off), "oespin-host-b") == 0,
		    "jailname '%s'", oes_msg_string(&buf.msg,
		    tp->ep_jailname_off));
	}

	TEST_BEGIN("P9 global client sees an unjailed process");
	pid = jt_run_true(-1);
	ASSERT_MSG(pid > 0, "run on host");
	if (jt_collect(fd, pid, OES_EVENT_NOTIFY_EXEC, 5000, &buf) != 0)
		TEST_FAIL("no EXEC of the host process");
	else {
		ASSERT_MSG(tp->ep_jid == 0, "ep_jid %d",
		    tp->ep_jid);
		ASSERT_MSG((tp->ep_flags & EP_FLAG_JAILED) == 0,
		    "EP_FLAG_JAILED set");
		ASSERT_MSG(tp->ep_jailname_off == 0,
		    "jailname offset %u", tp->ep_jailname_off);
	}

	TEST_BEGIN("P12 global client may mute any process");
	ASSERT_MSG(jt_mute_pid(fd, 1) == 0, "mute pid 1: %s", strerror(errno));
	close(fd);
}

/*
 * P10/P11 child: a descendants-scoped client follows its own descendants
 * into a jail and nothing else.  go_fd delivers the pid of a process the
 * parent ran in the same jail, which must not be seen.
 */
static int
child_descendants(int ready_fd, int go_fd)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_EXIT;
	struct jt_watch watch[2];
	test_msg_buf buf;
	pid_t sibling, mine, marker;
	int fd;

	fd = test_open_oes();
	if (fd < 0)
		return (10);
	if (set_scope(fd, OES_SCOPE_DESCENDANTS, 0) != 0)
		return (11);
	if (jt_notify_setup(fd, &ev, 1) != 0)
		return (12);
	/* P11: the parent of this process is outside the subtree. */
	if (jt_mute_pid(fd, getppid()) != -1 || errno != EPERM)
		return (13);
	if (write(ready_fd, "R", 1) != 1)
		return (14);
	if (read(go_fd, &sibling, sizeof(sibling)) != sizeof(sibling))
		return (15);
	mine = jt_run_true(jid_a);
	if (mine <= 0)
		return (16);
	if (jt_collect(fd, mine, OES_EVENT_NOTIFY_EXIT, 5000, &buf) != 0)
		return (17);
	marker = jt_run_true(jid_a);
	if (marker <= 0)
		return (19);
	watch[0].pid = sibling;
	watch[0].seen = 0;
	if (jt_scan(fd, marker, OES_EVENT_NOTIFY_EXIT, 5000, watch, 1) != 0)
		return (20);
	if (watch[0].seen != 0)
		return (21);
	return (0);
}

static void
test_descendants_in_jail(void)
{
	int ready[2], go[2], rc;
	pid_t child, sibling;
	char byte;

	TEST_BEGIN("P10/P11 descendants scope follows ancestry into a jail");
	if (pipe(ready) != 0 || pipe(go) != 0) {
		TEST_FAIL("pipe");
		return;
	}
	fflush(NULL);
	child = fork();
	if (child == 0) {
		close(ready[0]);
		close(go[1]);
		_exit(child_descendants(ready[1], go[0]));
	}
	close(ready[1]);
	close(go[0]);
	if (read(ready[0], &byte, 1) != 1) {
		rc = jt_reap(child);
		TEST_FAIL("descendants child failed early: status %d", rc);
	} else {
		sibling = jt_run_true(jid_a);
		ASSERT_MSG(sibling > 0, "sibling in A");
		(void)write(go[1], &sibling, sizeof(sibling));
		rc = jt_reap(child);
		ASSERT_MSG(rc == 0, "descendants child status %d", rc);
	}
	close(ready[0]);
	close(go[1]);
}

static void
test_idle_read_poll(void)
{
	struct pollfd pfd;
	char buf[sizeof(oes_message_t)];
	ssize_t n;
	int fd;

	TEST_BEGIN("P13 idle client: read EAGAIN, poll quiet");
	fd = test_open_oes();
	ASSERT_MSG(fd >= 0 && test_set_mode(fd, OES_MODE_NOTIFY) == 0,
	    "client");
	n = read(fd, buf, sizeof(buf));
	ASSERT_MSG(n == -1 && errno == EAGAIN, "read: %zd errno %d", n, errno);
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	ASSERT_MSG(poll(&pfd, 1, 0) == 0, "poll revents 0x%x", pfd.revents);
	close(fd);
}

static void
test_jailed_opener(void)
{
	pid_t child;
	int rc;

	TEST_BEGIN("P14 a jailed process cannot open /dev/oes");
	fflush(NULL);
	child = fork();
	if (child == 0) {
		int fd;

		if (jail_attach(jid_a) != 0)
			_exit(101);
		fd = open(OES_DEVICE_PATH, O_RDWR | O_CLOEXEC);
		if (fd >= 0)
			_exit(1);
		_exit(errno == EPERM ? 0 : errno == ENOENT ? 2 : 3);
	}
	rc = jt_reap(child);
	printf("    jailed open status %d (0 = EPERM, 2 = ENOENT)\n", rc);
	ASSERT_MSG(rc == 0 || rc == 2, "jailed open: status %d", rc);
}

/*
 * Records today's behaviour (see the jail-scope design, F.2); not an
 * endorsement: a descriptor opened on the host and carried into a jail stays
 * a global client.
 */
static int
child_carried_fd(int ready_fd, int go_fd)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_EXIT;
	test_msg_buf buf;
	pid_t host;
	int fd;

	fd = test_open_oes();
	if (fd < 0)
		return (10);
	if (jail_attach(jid_a) != 0)
		return (11);
	if (jt_notify_setup(fd, &ev, 1) != 0)
		return (12);
	if (write(ready_fd, "R", 1) != 1)
		return (13);
	if (read(go_fd, &host, sizeof(host)) != sizeof(host))
		return (14);
	if (jt_collect(fd, host, OES_EVENT_NOTIFY_EXIT, 5000, &buf) != 0)
		return (15);
	if (buf.msg.em_process.ep_jid != 0)
		return (16);
	return (0);
}

static void
test_carried_fd(void)
{
	int ready[2], go[2], rc;
	pid_t child, host;
	char byte;

	TEST_BEGIN("P15 a descriptor carried into a jail stays global");
	if (pipe(ready) != 0 || pipe(go) != 0) {
		TEST_FAIL("pipe");
		return;
	}
	fflush(NULL);
	child = fork();
	if (child == 0) {
		close(ready[0]);
		close(go[1]);
		_exit(child_carried_fd(ready[1], go[0]));
	}
	close(ready[1]);
	close(go[0]);
	if (read(ready[0], &byte, 1) != 1) {
		rc = jt_reap(child);
		TEST_FAIL("carried-fd child failed early: status %d", rc);
	} else {
		host = jt_run_true(-1);
		ASSERT_MSG(host > 0, "host process");
		(void)write(go[1], &host, sizeof(host));
		rc = jt_reap(child);
		ASSERT_MSG(rc == 0, "carried-fd child status %d", rc);
	}
	close(ready[0]);
	close(go[1]);
}

int
main(void)
{
	pid_t child;
	int rc;

	TEST_SUITE_BEGIN("jail pins");
	if (geteuid() != 0) {
		TEST_SKIP("requires root");
		return (0);
	}
	(void)atexit(jt_remove_jails);

	test_set_scope_errnos();

	TEST_BEGIN("P6 selecting the descendants scope twice succeeds");
	fflush(NULL);
	child = fork();
	if (child == 0)
		_exit(child_scope_twice());
	rc = jt_reap(child);
	ASSERT_MSG(rc == 0, "status %d", rc);

	test_idle_read_poll();

	jt_name(jail_a, sizeof(jail_a), "oespin", "a");
	snprintf(jail_b, sizeof(jail_b), "%s.b", jail_a);
	jid_a = jt_make_jail(jail_a, "oespin-host-a", NULL, "8");
	if (jid_a != -1)
		jid_b = jt_make_jail(jail_b, "oespin-host-b", NULL, "4");
	if (jid_a == -1 || jid_b == -1) {
		TEST_FAIL("cannot create the test jails");
		return (1);
	}

	test_global_sees_jailed();
	test_descendants_in_jail();
	test_jailed_opener();
	test_carried_fd();

	jt_remove_jails();
	if (oes_test_failures == 0)
		TEST_SUITE_END("jail pins");
	return (oes_test_failures != 0);
}
