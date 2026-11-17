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

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, create_refused);
	ATF_TP_ADD_TC(tp, create_refused_jailed);
	ATF_TP_ADD_TC(tp, issuer_ops_need_an_issuer);
	ATF_TP_ADD_TC(tp, test_sysctls);
	return (atf_no_error());
}
