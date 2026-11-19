/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Who may create an authority issuer (cap_process(2) CAP_AUTH_ISSUER_CREATE),
 * and what the issuer operations answer to a descriptor that is not an
 * issuer.  Only PID 1 creates the boot trust anchor.  A GENERIC-TEST kernel
 * booted with kern.mac_capability.test_issuer=1 also lets an unjailed root
 * process create a test issuer until PID 1 anchors the boot
 * (options MAC_CAPABILITY_TEST_PERMISSIVE; mac_capability(4)).
 *
 * The oracle is the kernel itself: kern.mac_capability.test_issuer and
 * test_issuer_state exist only on a kernel built with the option.  No case
 * skips: every kernel has an expectation.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/cap_authority.h>
#include <sys/jail.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
op(int cmd, int fd, void *data)
{

	return (syscall(SYS_cap_process, cmd, fd, 0, data));
}

/* The kernel's switch: present, its value and its state. */
struct test_switch {
	bool	present;
	int	enabled;
	char	state[16];
};

static void
test_switch(struct test_switch *sw)
{
	size_t len;

	memset(sw, 0, sizeof(*sw));
	len = sizeof(sw->enabled);
	if (sysctlbyname("kern.mac_capability.test_issuer", &sw->enabled, &len,
	    NULL, 0) != 0) {
		ATF_REQUIRE_EQ_MSG(errno, ENOENT,
		    "kern.mac_capability.test_issuer: %s", strerror(errno));
		return;
	}
	sw->present = true;
	len = sizeof(sw->state) - 1;
	ATF_REQUIRE_MSG(sysctlbyname("kern.mac_capability.test_issuer_state",
	    sw->state, &len, NULL, 0) == 0,
	    "a test kernel without kern.mac_capability.test_issuer_state: %s",
	    strerror(errno));
	printf("test kernel: test_issuer=%d state=%s\n", sw->enabled,
	    sw->state);
}

/* True where an unjailed root process may create a test issuer. */
static bool
relaxed(void)
{
	struct test_switch sw;

	test_switch(&sw);
	if (!sw.present) {
		printf("kernel without MAC_CAPABILITY_TEST_PERMISSIVE\n");
		return (false);
	}
	return (sw.enabled == 1 && strcmp(sw.state, "anchored") != 0);
}

/* Run fn in a child; the child's exit status is its errno, 0 on success. */
static int
in_child(int (*fn)(void))
{
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fn());
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status), "child status %#x", status);
	return (WEXITSTATUS(status));
}

static int
create_errno(void)
{
	int fd;

	fd = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	if (fd >= 0) {
		close(fd);
		return (0);
	}
	return (errno);
}

ATF_TC(create_refused);
ATF_TC_HEAD(create_refused, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A root process other than PID 1 creates an issuer only on a relaxed test kernel");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(create_refused, tc)
{
	int error;

	ATF_REQUIRE(getpid() != 1);
	error = create_errno();
	if (relaxed())
		ATF_CHECK_EQ_MSG(error, 0, "relaxed create: %s",
		    strerror(error));
	else
		ATF_CHECK_EQ_MSG(error, EPERM, "create: %s", strerror(error));
	/* Data must be NULL whatever the caller. */
	ATF_CHECK_ERRNO(EINVAL, op(CAP_AUTH_ISSUER_CREATE, -1, &error) == -1);
}

static int
create_in_jail(void)
{
	struct jail j = {
		.version = JAIL_API_VERSION,
		.path = __DECONST(char *, "/"),
		.hostname = __DECONST(char *, "authority-test-issuer"),
		.jailname = NULL,
	};

	if (jail(&j) < 0)
		return (100);
	return (create_errno());
}

ATF_TC(create_refused_jailed);
ATF_TC_HEAD(create_refused_jailed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A jailed process never creates an issuer, on any kernel");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(create_refused_jailed, tc)
{
	int error;

	error = in_child(create_in_jail);
	ATF_REQUIRE_MSG(error != 100, "cannot create a jail");
	ATF_CHECK_EQ_MSG(error, EPERM, "jailed create: %s", strerror(error));
}

/*
 * Each issuer operation, given a descriptor that is not an issuer: a closed
 * one (EBADF) and an open file of another kind (EINVAL).  The request data
 * is valid, so the descriptor is what is refused.
 */
static int
issuer_op_errno(int cmd, int fd)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	struct cap_authority_constraint constraint = {
		.token_fd = -1, .nexec = 1,
	};
	struct cap_authority_lease_create lease = { .seconds = 1 };
	struct cap_authority_bind bind = { .token_fd = -1, .capability_fd = -1 };
	struct cap_authority_application app = { .token_fd = -1 };
	struct cap_authority_libdirs libdirs = { .token_fd = -1, .count = 1 };
	struct cap_authority_revoke revoke = { .token_fd = -1 };
	void *data;

	constraint.executable_fds[0] = -1;
	libdirs.directory_fds[0] = -1;
	switch (cmd) {
	case CAP_AUTH_ISSUE:		data = &spec; break;
	case CAP_AUTH_CONSTRAIN:	data = &constraint; break;
	case CAP_AUTH_LEASE_CREATE:	data = &lease; break;
	case CAP_AUTH_BIND:		data = &bind; break;
	case CAP_AUTH_REGISTER_APP:	data = &app; break;
	case CAP_AUTH_SET_LIBDIRS:	data = &libdirs; break;
	case CAP_AUTH_REVOKE:		data = &revoke; break;
	default:			atf_tc_fail("op %d", cmd);
	}
	if (op(cmd, fd, data) == 0)
		return (0);
	return (errno);
}

ATF_TC(issuer_ops_need_an_issuer);
ATF_TC_HEAD(issuer_ops_need_an_issuer, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ISSUE, CONSTRAIN, LEASE_CREATE, BIND, REGISTER_APP, SET_LIBDIRS and REVOKE refuse a non-issuer descriptor");
}
ATF_TC_BODY(issuer_ops_need_an_issuer, tc)
{
	static const struct { int cmd; const char *name; } ops[] = {
		{ CAP_AUTH_ISSUE, "ISSUE" },
		{ CAP_AUTH_CONSTRAIN, "CONSTRAIN" },
		{ CAP_AUTH_LEASE_CREATE, "LEASE_CREATE" },
		{ CAP_AUTH_BIND, "BIND" },
		{ CAP_AUTH_REGISTER_APP, "REGISTER_APP" },
		{ CAP_AUTH_SET_LIBDIRS, "SET_LIBDIRS" },
		{ CAP_AUTH_REVOKE, "REVOKE" },
	};
	int devnull, error;

	devnull = open("/dev/null", O_RDWR);
	ATF_REQUIRE(devnull >= 0);
	for (size_t i = 0; i < nitems(ops); i++) {
		error = issuer_op_errno(ops[i].cmd, -1);
		ATF_CHECK_EQ_MSG(error, EBADF, "%s on -1: %s", ops[i].name,
		    strerror(error));
		error = issuer_op_errno(ops[i].cmd, devnull);
		ATF_CHECK_EQ_MSG(error, EINVAL, "%s on /dev/null: %s",
		    ops[i].name, strerror(error));
	}
	close(devnull);
}

ATF_TC(test_sysctls);
ATF_TC_HEAD(test_sysctls, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The test-issuer sysctls exist only on a kernel built with the option, and cannot be written there");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(test_sysctls, tc)
{
	static const char *const names[] = {
		"kern.mac_capability.test_issuer",
		"kern.mac_capability.test_issuers",
		"kern.mac_capability.test_issuers_live",
		"kern.mac_capability.test_issuer_state",
	};
	struct test_switch sw;
	char buf[64];
	size_t len;
	int one = 1, zero = 0;

	test_switch(&sw);
	for (size_t i = 0; i < nitems(names); i++) {
		len = sizeof(buf);
		if (!sw.present) {
			ATF_CHECK_ERRNO(ENOENT,
			    sysctlbyname(names[i], buf, &len, NULL, 0) == -1);
			continue;
		}
		ATF_CHECK_MSG(sysctlbyname(names[i], buf, &len, NULL, 0) == 0,
		    "%s: %s", names[i], strerror(errno));
	}
	if (!sw.present)
		return;
	/* Fixed for the boot: root cannot turn it on or off. */
	ATF_CHECK(sw.enabled == 0 || sw.enabled == 1);
	ATF_CHECK(sysctlbyname("kern.mac_capability.test_issuer", NULL, NULL,
	    &one, sizeof(one)) == -1);
	ATF_CHECK(sysctlbyname("kern.mac_capability.test_issuer", NULL, NULL,
	    &zero, sizeof(zero)) == -1);
	ATF_CHECK(strcmp(sw.state, "none") == 0 ||
	    strcmp(sw.state, "test") == 0 || strcmp(sw.state, "anchored") == 0);
}

static int
create_in_capmode(void)
{

	if (cap_enter() != 0)
		return (100);
	return (create_errno());
}

static int
create_unprivileged(void)
{

	if (setgid(65534) != 0 || setuid(65534) != 0)
		return (100);
	return (create_errno());
}

ATF_TC(create_refused_capmode_unprivileged);
ATF_TC_HEAD(create_refused_capmode_unprivileged, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Capability mode and a non-root credential never create an issuer, on any kernel");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(create_refused_capmode_unprivileged, tc)
{
	int error;

	(void)relaxed();
	error = in_child(create_in_capmode);
	ATF_REQUIRE_MSG(error != 100, "cap_enter failed");
	ATF_CHECK_EQ_MSG(error, EPERM, "capability mode: %s", strerror(error));
	error = in_child(create_unprivileged);
	ATF_REQUIRE_MSG(error != 100, "cannot become nobody");
	ATF_CHECK_EQ_MSG(error, EPERM, "uid 65534: %s", strerror(error));
}

static u_long
test_issuers(void)
{
	u_long value;
	size_t len = sizeof(value);

	ATF_REQUIRE(sysctlbyname("kern.mac_capability.test_issuers", &value,
	    &len, NULL, 0) == 0);
	return (value);
}

static u_int
test_issuers_live(void)
{
	u_int value;
	size_t len = sizeof(value);

	ATF_REQUIRE(sysctlbyname("kern.mac_capability.test_issuers_live",
	    &value, &len, NULL, 0) == 0);
	return (value);
}

ATF_TC(relaxed_issuer);
ATF_TC_HEAD(relaxed_issuer, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "On a relaxed test kernel a test issuer issues authority and is counted until freed; elsewhere none is created");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(relaxed_issuer, tc)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	struct cap_authority_info info;
	struct test_switch sw;
	u_long created;
	u_int live;
	int issuer, token;

	if (!relaxed()) {
		ATF_CHECK_ERRNO(EPERM,
		    op(CAP_AUTH_ISSUER_CREATE, -1, NULL) == -1);
		return;
	}
	created = test_issuers();
	live = test_issuers_live();
	issuer = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	ATF_REQUIRE_MSG(issuer >= 0, "relaxed create: %s", strerror(errno));
	ATF_CHECK_EQ(test_issuers(), created + 1);
	ATF_CHECK_EQ(test_issuers_live(), live + 1);
	test_switch(&sw);
	ATF_CHECK_STREQ(sw.state, "test");
	token = op(CAP_AUTH_ISSUE, issuer, &spec);
	ATF_REQUIRE_MSG(token >= 0, "issue: %s", strerror(errno));
	ATF_REQUIRE(op(CAP_AUTH_TOKEN_INFO, token, &info) == 0);
	ATF_CHECK(info.issuer != 0 && info.identity != 0);
	ATF_CHECK_EQ(info.revoked, 0);
	/* The token keeps the issuer; closing both frees it, asynchronously. */
	ATF_REQUIRE(close(issuer) == 0);
	ATF_REQUIRE(op(CAP_AUTH_TOKEN_INFO, token, &info) == 0);
	ATF_CHECK_EQ_MSG(info.revoked, 1, "closing the issuer revokes its grants");
	ATF_REQUIRE(close(token) == 0);
	for (int i = 0; i < 50 && test_issuers_live() != live; i++)
		usleep(100000);
	ATF_CHECK_EQ(test_issuers_live(), live);
}

/*
 * Capsule holds the next SwitchBoard start's issuer unused (usr.sbin/capsule
 * bootstrap.c).  Pin that holding a second issuer changes nothing for the
 * first: grants record the issuer that made them, closing the first revokes
 * its grants while the second is held, closing the held one revokes none of
 * the first's, and the held one issues normally once used.
 */
ATF_TC(held_issuer_independent);
ATF_TC_HEAD(held_issuer_independent, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A held second issuer neither keeps nor revokes the first issuer's grants");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(held_issuer_independent, tc)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	struct cap_authority_info a_info, b_info, info;
	int a, b, a_token, a_token2, b_token;

	if (!relaxed())
		atf_tc_skip("DEFERRED_STACK_TIER: needs a relaxed test kernel "
		    "(kern.mac_capability.test_issuer=1, boot not anchored) to "
		    "create issuers off PID 1");
	a = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	ATF_REQUIRE_MSG(a >= 0, "create a: %s", strerror(errno));
	b = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	ATF_REQUIRE_MSG(b >= 0, "create b: %s", strerror(errno));

	/* Closing the held issuer revokes none of the running one's grants. */
	a_token = op(CAP_AUTH_ISSUE, a, &spec);
	ATF_REQUIRE_MSG(a_token >= 0, "issue a: %s", strerror(errno));
	ATF_REQUIRE(op(CAP_AUTH_TOKEN_INFO, a_token, &a_info) == 0);
	ATF_REQUIRE(close(b) == 0);
	ATF_REQUIRE(op(CAP_AUTH_TOKEN_INFO, a_token, &info) == 0);
	ATF_CHECK_EQ_MSG(info.revoked, 0, "closing a held issuer revoked "
	    "another issuer's grant");

	/* With a second issuer held, closing the first still revokes its own. */
	b = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	ATF_REQUIRE_MSG(b >= 0, "create b again: %s", strerror(errno));
	a_token2 = op(CAP_AUTH_ISSUE, a, &spec);
	ATF_REQUIRE_MSG(a_token2 >= 0, "issue a again: %s", strerror(errno));
	ATF_REQUIRE(close(a) == 0);
	ATF_REQUIRE(op(CAP_AUTH_TOKEN_INFO, a_token, &info) == 0);
	ATF_CHECK_EQ_MSG(info.revoked, 1, "a held issuer kept the closed "
	    "issuer's grant alive");
	ATF_REQUIRE(op(CAP_AUTH_TOKEN_INFO, a_token2, &info) == 0);
	ATF_CHECK_EQ(info.revoked, 1);

	/* The held issuer issues normally once used, under its own identity. */
	b_token = op(CAP_AUTH_ISSUE, b, &spec);
	ATF_REQUIRE_MSG(b_token >= 0, "issue b: %s", strerror(errno));
	ATF_REQUIRE(op(CAP_AUTH_TOKEN_INFO, b_token, &b_info) == 0);
	ATF_CHECK_EQ(b_info.revoked, 0);
	ATF_CHECK(b_info.issuer != a_info.issuer);
	ATF_REQUIRE(close(b) == 0);
	ATF_REQUIRE(op(CAP_AUTH_TOKEN_INFO, b_token, &info) == 0);
	ATF_CHECK_EQ(info.revoked, 1);
	(void)close(a_token);
	(void)close(a_token2);
	(void)close(b_token);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, create_refused);
	ATF_TP_ADD_TC(tp, create_refused_jailed);
	ATF_TP_ADD_TC(tp, issuer_ops_need_an_issuer);
	ATF_TP_ADD_TC(tp, test_sysctls);
	ATF_TP_ADD_TC(tp, create_refused_capmode_unprivileged);
	ATF_TP_ADD_TC(tp, relaxed_issuer);
	ATF_TP_ADD_TC(tp, held_issuer_independent);
	return (atf_no_error());
}
