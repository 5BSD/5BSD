/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * OES and base exclusion (oes(4) "Excluded processes", cap_process(2)
 * BASE EXCLUSION; oes-core-exemption.md rows O2, O5, O5b, O5c, O14).
 *
 * An excluded process stands in for Capsule, switchboard or a Core unit:
 * each case's child marks itself excluded with the test kernel's
 * debug.mac_capability.test_issuer_exclude_self, so the cases need the
 * stack tier (vm-provider.sh STACK_TIER=1 KERNEL_TIER=test PLANE_OFF=1)
 * and skip elsewhere, saying so.  Clients that leave AUTH unanswered run
 * descendants-scoped (test_common.h).  Every wait is on an event with a
 * deadline the case states; nothing sleeps for time.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define	HELPER_REL	"../../mac_capability/cap_exclusion_helper"
/* The AUTH deadline of the never-answering client. */
#define	AUTH_DEADLINE_MS	200

static void
helper_path(const atf_tc_t *tc, char *buf, size_t len)
{

	snprintf(buf, len, "%s/%s", atf_tc_get_config_var(tc, "srcdir"),
	    HELPER_REL);
}

static int
exclude_self(void)
{
	int one = 1;

	if (sysctlbyname("debug.mac_capability.test_issuer_exclude_self", NULL,
	    NULL, &one, sizeof(one)) != 0)
		return (errno);
	return (0);
}

static void
require_knob(void)
{
	int v;
	size_t len = sizeof(v);

	if (sysctlbyname("debug.mac_capability.test_issuer_exclude_self", &v,
	    &len, NULL, 0) != 0)
		atf_tc_skip("DEFERRED_STACK_TIER: no "
		    "debug.mac_capability.test_issuer_exclude_self: "
		    "needs GENERIC-TEST (vm-provider.sh STACK_TIER=1)");
	len = sizeof(v);
	if (sysctlbyname("kern.mac_capability.test_issuer", &v, &len, NULL,
	    0) != 0 || v != 1)
		atf_tc_skip("DEFERRED_STACK_TIER: test issuers off "
		    "(kern.mac_capability.test_issuer)");
}

static uint64_t
counter(const char *name)
{
	uint64_t v;
	size_t len = sizeof(v);

	ATF_REQUIRE_MSG(sysctlbyname(name, &v, &len, NULL, 0) == 0, "%s: %s",
	    name, strerror(errno));
	return (v);
}

/* Fork a child that runs fn and exits with its result; return its pid. */
static pid_t
spawn(int (*fn)(void *), void *arg)
{
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fn(arg));
	return (pid);
}

static int
reap(pid_t pid)
{
	int status;

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status), "status %#x", status);
	return (WEXITSTATUS(status));
}

static int
open_probe(void *arg)
{
	const char *path = arg;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (errno);
	close(fd);
	return (0);
}

static int
excluded_open_probe(void *arg)
{
	int e;

	if ((e = exclude_self()) != 0)
		return (e);
	for (int i = 0; i < 3; i++)
		if ((e = open_probe(arg)) != 0)
			return (e);
	return (0);
}

ATF_TC(o2_excluded_subject_no_events);
ATF_TC_HEAD(o2_excluded_subject_no_events, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "O2: an excluded process's opens produce no NOTIFY_OPEN; a process that is not excluded is reported; excluded_skipped counts the skips");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(o2_excluded_subject_no_events, tc)
{
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;
	char probe[PATH_MAX], marker[PATH_MAX];
	uint64_t skipped;
	pid_t ex, ctl, mk;
	int fd, ex_events = 0, ctl_events = 0;
	bool marker_seen = false;

	require_knob();
	ATF_REQUIRE(getcwd(probe, sizeof(probe)) != NULL);
	strlcpy(marker, probe, sizeof(marker));
	strlcat(probe, "/probe", sizeof(probe));
	strlcat(marker, "/marker", sizeof(marker));
	ATF_REQUIRE(close(open(probe, O_WRONLY | O_CREAT, 0644)) == 0);
	ATF_REQUIRE(close(open(marker, O_WRONLY | O_CREAT, 0644)) == 0);

	fd = test_open_oes();
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/oes: %s", strerror(errno));
	ATF_REQUIRE(test_set_descendants_scope(fd) == 0);
	ATF_REQUIRE(test_set_mode(fd, OES_MODE_NOTIFY) == 0);
	ATF_REQUIRE(test_subscribe(fd, events, nitems(events),
	    OES_SUB_REPLACE) == 0);
	ATF_REQUIRE(test_mute_self(fd) == 0);

	skipped = counter("security.oes.excluded_skipped");
	ex = spawn(excluded_open_probe, probe);
	ATF_REQUIRE_EQ(reap(ex), 0);
	ctl = spawn(open_probe, probe);
	ATF_REQUIRE_EQ(reap(ctl), 0);
	/* The fence: the last open, by another process that is not excluded. */
	mk = spawn(open_probe, marker);
	ATF_REQUIRE_EQ(reap(mk), 0);

	while (!marker_seen) {
		ATF_REQUIRE_MSG(test_wait_event(fd, msg, OES_TEST_DEADLINE_MS) == 0,
		    "no marker event within %d ms", OES_TEST_DEADLINE_MS);
		if (msg->em_event != OES_EVENT_NOTIFY_OPEN)
			continue;
		if (msg->em_process.ep_pid == ex)
			ex_events++;
		else if (msg->em_process.ep_pid == ctl)
			ctl_events++;
		else if (msg->em_process.ep_pid == mk)
			marker_seen = true;
	}
	ATF_CHECK_EQ_MSG(ex_events, 0, "excluded process reported %d times",
	    ex_events);
	ATF_CHECK_MSG(ctl_events >= 1, "control process not reported");
	ATF_CHECK(counter("security.oes.excluded_skipped") >= skipped + 3);
	close(fd);
}

/* An AUTH client of the test's descendants that answers AUTH_EXEC. */
static int
exec_client(uint32_t miss_mode)
{
	oes_event_type_t events[] = { OES_EVENT_AUTH_EXEC };
	struct oes_mode_args mode;
	struct oes_deadline_miss_mode_args miss;
	int fd;

	fd = test_open_oes();
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/oes: %s", strerror(errno));
	ATF_REQUIRE(test_set_descendants_scope(fd) == 0);
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_default_deadline_ms = AUTH_DEADLINE_MS;
	ATF_REQUIRE(ioctl(fd, OES_IOC_SET_MODE, &mode) == 0);
	memset(&miss, 0, sizeof(miss));
	miss.edma_mode = miss_mode;
	ATF_REQUIRE(ioctl(fd, OES_IOC_SET_DEADLINE_MISS_MODE, &miss) == 0);
	ATF_REQUIRE(test_subscribe(fd, events, nitems(events),
	    OES_SUB_REPLACE) == 0);
	ATF_REQUIRE(test_mute_self(fd) == 0);
	return (fd);
}

struct exec_spec {
	const char	*path;
	bool		 excluded;
	int		 token;		/* -1, or a Core token to install */
};

/* The child: optionally excluded and holding a Core authority, exec. */
static int
exec_child(void *arg)
{
	struct exec_spec *e = arg;
	char *argv[] = { __DECONST(char *, "cap_exclusion_helper"),
	    __DECONST(char *, "report"), NULL };
	int devnull, error;

	if (e->token >= 0 &&
	    syscall(SYS_cap_process, CAP_AUTH_INSTALL, e->token, 0, NULL) != 0)
		return (200);
	if (e->excluded && (error = exclude_self()) != 0)
		return (error);
	devnull = open("/dev/null", O_WRONLY);
	if (devnull >= 0)
		dup2(devnull, STDOUT_FILENO);
	execv(e->path, argv);
	return (errno);
}

/* Read AUTH_EXEC events; answer each from pid with result (0: never). */
static bool
wait_auth_exec(int fd, pid_t pid, uint32_t result, uint32_t *flags)
{
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;
	oes_response_t resp;

	for (;;) {
		if (test_wait_event(fd, msg, OES_TEST_DEADLINE_MS) != 0)
			return (false);
		if (msg->em_event != OES_EVENT_AUTH_EXEC ||
		    msg->em_process.ep_pid != pid)
			continue;
		if (flags != NULL)
			*flags = msg->em_process.ep_flags;
		if (result != 0) {
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = result;
			ATF_REQUIRE(write(fd, &resp, sizeof(resp)) ==
			    sizeof(resp));
		}
		return (true);
	}
}

/* A managed token for helper with roles, from a new issuer; -1 on error. */
static int
role_token(const char *helper, uint32_t roles, int *issuerp)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	struct cap_authority_constraint c;
	int issuer, token, image;

	issuer = syscall(SYS_cap_process, CAP_AUTH_ISSUER_CREATE, -1, 0, NULL);
	if (issuer < 0)
		return (-1);
	token = syscall(SYS_cap_process, CAP_AUTH_ISSUE, issuer, 0, &spec);
	image = open(helper, O_RDONLY | O_CLOEXEC);
	if (token < 0 || image < 0)
		return (-1);
	memset(&c, 0, sizeof(c));
	c.token_fd = token;
	c.flags = roles;
	c.nexec = 1;
	c.executable_fds[0] = image;
	if (syscall(SYS_cap_process, CAP_AUTH_CONSTRAIN, issuer, 0, &c) != 0)
		return (-1);
	close(image);
	*issuerp = issuer;
	return (token);
}

ATF_TC(o5_launcher_exec_fail_open);
ATF_TC_HEAD(o5_launcher_exec_fail_open, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "O5/O5c, owner S1: an excluded launcher's start of a System-bundle unit (CAP_AUTH_ROLE_SYSTEM, image not Core) is reported (AUTH_EXEC) and, unanswered under a fail-closed deadline, runs; exec_fail_open counts it.  The same excluded launcher's exec without a System authority, and a process that is not excluded, are denied (EACCES)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(o5_launcher_exec_fail_open, tc)
{
	struct exec_spec e;
	char helper[PATH_MAX];
	uint64_t fail_open;
	uint32_t flags;
	pid_t pid;
	int fd, token, issuer;

	require_knob();
	helper_path(tc, helper, sizeof(helper));
	token = role_token(helper, CAP_AUTH_ROLE_SYSTEM, &issuer);
	ATF_REQUIRE_MSG(token >= 0, "System token: %s", strerror(errno));
	fd = exec_client(OES_DEADLINE_MISS_FAIL_CLOSED);

	fail_open = counter("security.oes.exec_fail_open");
	e = (struct exec_spec){ .path = helper, .excluded = true,
	    .token = token };
	pid = spawn(exec_child, &e);
	ATF_CHECK_MSG(wait_auth_exec(fd, pid, 0, &flags),
	    "no AUTH_EXEC for the excluded launcher's exec");
	/* Commit 7: the launcher's record says it is excluded. */
	ATF_CHECK((flags & EP_FLAG_CAP_EXCLUDED) != 0);
	ATF_CHECK_EQ_MSG(reap(pid), 0, "excluded launcher's System exec refused");
	/* A global counter: other launches may add to it too. */
	ATF_CHECK(counter("security.oes.exec_fail_open") >= fail_open + 1);
	close(token);
	close(issuer);

	/* S1: without a System authority the excluded launcher is denied. */
	e = (struct exec_spec){ .path = helper, .excluded = true, .token = -1 };
	pid = spawn(exec_child, &e);
	ATF_CHECK(wait_auth_exec(fd, pid, 0, &flags));
	ATF_CHECK((flags & EP_FLAG_CAP_EXCLUDED) != 0);
	ATF_CHECK_EQ_MSG(reap(pid), EACCES,
	    "an excluded launcher's plain exec runs fail-closed");

	e = (struct exec_spec){ .path = helper, .excluded = false, .token = -1 };
	pid = spawn(exec_child, &e);
	ATF_CHECK(wait_auth_exec(fd, pid, 0, &flags));
	ATF_CHECK((flags & (EP_FLAG_CAP_EXCLUDED | EP_FLAG_CAP_MANAGED)) == 0);
	ATF_CHECK_EQ_MSG(reap(pid), EACCES,
	    "a process that is not excluded runs fail-closed");
	close(fd);
}

ATF_TC(o5b_launcher_exec_client_deny);
ATF_TC_HEAD(o5b_launcher_exec_client_deny, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "O5b: a client's explicit DENY of an excluded launcher's exec still refuses it (EACCES)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(o5b_launcher_exec_client_deny, tc)
{
	struct exec_spec e;
	char helper[PATH_MAX];
	pid_t pid;
	int fd;

	require_knob();
	helper_path(tc, helper, sizeof(helper));
	fd = exec_client(OES_DEADLINE_MISS_FAIL_OPEN);
	e = (struct exec_spec){ .path = helper, .excluded = true, .token = -1 };
	pid = spawn(exec_child, &e);
	ATF_CHECK(wait_auth_exec(fd, pid, OES_AUTH_DENY, NULL));
	ATF_CHECK_EQ(reap(pid), EACCES);
	close(fd);
}

ATF_TC(core_exec_no_event);
ATF_TC_HEAD(core_exec_no_event, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Executing a Core image produces no AUTH_EXEC: with a fail-closed client that never answers, the exec runs; a later exec by a process that is not excluded is the first event the client sees");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(core_exec_no_event, tc)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	struct cap_authority_constraint c;
	struct exec_spec e;
	char helper[PATH_MAX];
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;
	pid_t core, ctl;
	int fd, issuer, token, image;

	require_knob();
	helper_path(tc, helper, sizeof(helper));
	issuer = syscall(SYS_cap_process, CAP_AUTH_ISSUER_CREATE, -1, 0, NULL);
	ATF_REQUIRE_MSG(issuer >= 0, "test issuer: %s", strerror(errno));
	token = syscall(SYS_cap_process, CAP_AUTH_ISSUE, issuer, 0, &spec);
	ATF_REQUIRE(token >= 0);
	image = open(helper, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(image >= 0);
	memset(&c, 0, sizeof(c));
	c.token_fd = token;
	c.flags = CAP_AUTH_ROLE_CORE;
	c.nexec = 1;
	c.executable_fds[0] = image;
	ATF_REQUIRE(syscall(SYS_cap_process, CAP_AUTH_CONSTRAIN, issuer, 0,
	    &c) == 0);

	fd = exec_client(OES_DEADLINE_MISS_FAIL_CLOSED);
	e = (struct exec_spec){ .path = helper, .excluded = true,
	    .token = token };
	core = spawn(exec_child, &e);
	ATF_CHECK_EQ_MSG(reap(core), 0, "Core exec refused");

	/* The fence: an unanswered exec that is reported. */
	e = (struct exec_spec){ .path = helper, .excluded = false, .token = -1 };
	ctl = spawn(exec_child, &e);
	for (;;) {
		ATF_REQUIRE(test_wait_event(fd, msg, OES_TEST_DEADLINE_MS) == 0);
		if (msg->em_event != OES_EVENT_AUTH_EXEC)
			continue;
		ATF_CHECK_MSG(msg->em_process.ep_pid != core,
		    "AUTH_EXEC for the Core exec");
		if (msg->em_process.ep_pid == ctl)
			break;
	}
	ATF_CHECK_EQ(reap(ctl), EACCES);
	close(fd);
	close(image);
	close(token);
	close(issuer);
}

/*
 * O16, owner decision S1 (2026-11-20): with require_auth_clients=1 and no
 * client, an excluded launcher's start of a System-bundle unit
 * (CAP_AUTH_ROLE_SYSTEM) fails open, and any other start is denied.  Runs
 * in an excluded child E, so its own sysctl writes and waits are never
 * denied; E restores the knob before it exits.  The window during which
 * the rest of the guest runs with the knob set is E's two launches.
 */
#define	REQUIRE_AUTH	"security.oes.require_auth_clients"

static int
o16_launch(const char *helper, int issuer, uint32_t role)
{
	char *argv[] = { __DECONST(char *, "cap_exclusion_helper"),
	    __DECONST(char *, "report"), NULL };
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	struct cap_authority_constraint c;
	int token = -1, image, status, devnull;
	pid_t pid;

	if (role != 0) {
		token = syscall(SYS_cap_process, CAP_AUTH_ISSUE, issuer, 0,
		    &spec);
		image = open(helper, O_RDONLY | O_CLOEXEC);
		if (token < 0 || image < 0)
			return (-1);
		memset(&c, 0, sizeof(c));
		c.token_fd = token;
		c.flags = role;
		c.nexec = 1;
		c.executable_fds[0] = image;
		if (syscall(SYS_cap_process, CAP_AUTH_CONSTRAIN, issuer, 0,
		    &c) != 0)
			return (-1);
		close(image);
	}
	pid = fork();
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		if (token >= 0 && syscall(SYS_cap_process, CAP_AUTH_INSTALL,
		    token, 0, NULL) != 0)
			_exit(200);
		devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0)
			dup2(devnull, STDOUT_FILENO);
		execv(helper, argv);
		_exit(errno);
	}
	if (token >= 0)
		close(token);
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static int
o16_in_excluded(void *arg)
{
	const char *helper = arg;
	int issuer, one = 1, zero = 0, system_rc, plain_rc;

	if (exclude_self() != 0)
		return (100);
	issuer = syscall(SYS_cap_process, CAP_AUTH_ISSUER_CREATE, -1, 0, NULL);
	if (issuer < 0)
		return (101);
	if (sysctlbyname(REQUIRE_AUTH, NULL, NULL, &one, sizeof(one)) != 0)
		return (102);
	system_rc = o16_launch(helper, issuer, CAP_AUTH_ROLE_SYSTEM);
	plain_rc = o16_launch(helper, issuer, 0);
	if (sysctlbyname(REQUIRE_AUTH, NULL, NULL, &zero, sizeof(zero)) != 0)
		return (103);
	close(issuer);
	if (system_rc != 0)
		return (110);
	if (plain_rc != EACCES)
		return (111);
	return (0);
}

/* Put require_auth_clients back to 0; a write needs no exec. */
static int
o16_restore(void)
{
	int zero = 0;

	return (sysctlbyname(REQUIRE_AUTH, NULL, NULL, &zero, sizeof(zero)));
}

ATF_TC_WITH_CLEANUP(o16_failopen_system_only);
ATF_TC_HEAD(o16_failopen_system_only, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Owner S1: require_auth_clients=1 and no client: an excluded launcher's start of a System-bundle unit fails open; a start without CAP_AUTH_ROLE_SYSTEM is denied (EACCES)");
	atf_tc_set_md_var(tc, "require.user", "root");
	/* The knob is global: no other test may run while it is set. */
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(o16_failopen_system_only, tc)
{
	char helper[PATH_MAX];
	int status, old;
	size_t len = sizeof(old);
	pid_t e;

	require_knob();
	ATF_REQUIRE(sysctlbyname(REQUIRE_AUTH, &old, &len, NULL, 0) == 0);
	ATF_REQUIRE_EQ_MSG(old, 0, "%s is already set", REQUIRE_AUTH);
	helper_path(tc, helper, sizeof(helper));
	e = spawn(o16_in_excluded, helper);
	status = reap(e);
	/*
	 * E restores the knob on every path it returns by; this process
	 * restores it too, before any check can end the body, since while it
	 * is set no unexcluded exec (the cleanup's included) is allowed.
	 */
	ATF_REQUIRE_MSG(o16_restore() == 0, "%s: %s", REQUIRE_AUTH,
	    strerror(errno));
	ATF_CHECK_EQ_MSG(status, 0, "step %d", status);
}
ATF_TC_CLEANUP(o16_failopen_system_only, tc)
{

	/* Last resort, if the body was killed while the knob was set. */
	(void)o16_restore();
}

ATF_TC(o14_idle_no_count);
ATF_TC_HEAD(o14_idle_no_count, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "O14: with no client open, an excluded process's activity leaves security.oes.excluded_skipped unchanged");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(o14_idle_no_count, tc)
{
	char probe[PATH_MAX];
	uint64_t before;

	/*
	 * Exclusive: no other test has a client open.  A client from outside
	 * the test run would make this case meaningless, so check.
	 */
	require_knob();
	{
		u_int n;
		size_t nlen = sizeof(n);

		ATF_REQUIRE(sysctlbyname("security.oes.clients", &n, &nlen,
		    NULL, 0) == 0);
		ATF_REQUIRE_EQ_MSG(n, 0,
		    "%u OES clients are open; this case needs none", n);
	}
	ATF_REQUIRE(getcwd(probe, sizeof(probe)) != NULL);
	strlcat(probe, "/probe", sizeof(probe));
	ATF_REQUIRE(close(open(probe, O_WRONLY | O_CREAT, 0644)) == 0);
	before = counter("security.oes.excluded_skipped");
	ATF_CHECK_EQ(reap(spawn(excluded_open_probe, probe)), 0);
	ATF_CHECK_EQ(counter("security.oes.excluded_skipped"), before);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, o2_excluded_subject_no_events);
	ATF_TP_ADD_TC(tp, o5_launcher_exec_fail_open);
	ATF_TP_ADD_TC(tp, o5b_launcher_exec_client_deny);
	ATF_TP_ADD_TC(tp, core_exec_no_event);
	ATF_TP_ADD_TC(tp, o14_idle_no_count);
	ATF_TP_ADD_TC(tp, o16_failopen_system_only);
	return (atf_no_error());
}
