/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The argument contract of mac_capability:::issuer-decision, which every
 * kernel carries: (identity, outcome, reason, latency_ns, errno), one firing
 * for each CAP_AUTH_ISSUER_CREATE.  The creates here run in children of the
 * test, off PID 1, so the expected reason follows from the kernel and the
 * boot: NOT_INIT without the test-issuer switch (every production kernel),
 * TEST on a test-issuer kernel with the switch on and the boot not anchored,
 * ANCHORED once it is; JAILED in a jail on every kernel, CAPMODE in
 * capability mode where a test issuer could otherwise be created.  The
 * REVOKE outcome is checked by authority_test_issuer_anchor_test.
 *
 * dtrace(1) needs its providers preloaded (dtraceall_load="YES"): a late
 * kldload is refused with the plane on.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <sys/jail.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authority_probe.h"

enum where { PLAIN, JAILED, CAPMODE };

/* What a create off PID 1 is refused or allowed with on this boot. */
static int
expected_reason(enum where where)
{
	char state[32];
	size_t len = sizeof(state) - 1;
	int on = 0;
	size_t onlen = sizeof(on);

	if (where == JAILED)
		return (CAP_AUTH_ISSUER_R_JAILED);
	if (sysctlbyname("kern.mac_capability.test_issuer", &on, &onlen,
	    NULL, 0) != 0 || on != 1)
		return (CAP_AUTH_ISSUER_R_NOT_INIT);
	if (where == CAPMODE)
		return (CAP_AUTH_ISSUER_R_CAPMODE);
	memset(state, 0, sizeof(state));
	ATF_REQUIRE(sysctlbyname("kern.mac_capability.test_issuer_state",
	    state, &len, NULL, 0) == 0);
	if (strcmp(state, "anchored") == 0)
		return (CAP_AUTH_ISSUER_R_ANCHORED);
	return (CAP_AUTH_ISSUER_R_TEST);
}

/* Create an issuer in a child; returns the errno it got (0: created). */
static int
create_in_child(enum where where)
{
	struct jail j = {
		.version = JAIL_API_VERSION, .path = __DECONST(char *, "/"),
		.hostname = __DECONST(char *, "issuer-probe"),
		.jailname = NULL,
	};
	int status;
	pid_t child;

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (where == JAILED && jail(&j) < 0)
			_exit(200);
		if (where == CAPMODE && cap_enter() != 0)
			_exit(201);
		if (syscall(SYS_cap_process, CAP_AUTH_ISSUER_CREATE, -1, 0,
		    NULL) >= 0)
			_exit(0);
		_exit(errno > 0 && errno < 200 ? errno : 199);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) < 199,
	    "child status %#x", status);
	return (WEXITSTATUS(status));
}

static void
check_decision(enum where where)
{
	struct probe p;
	char predicate[64], *out, *line, *next;
	uintmax_t identity, latency;
	int error, reason, outcome, preason, perrno, firings = 0;

	reason = expected_reason(where);
	snprintf(predicate, sizeof(predicate), "progenyof(%d)", (int)getpid());
	probe_start(&p, predicate);
	error = create_in_child(where);
	out = probe_stop(&p);
	printf("expected reason %d, create errno %d\n%s", reason, error, out);
	ATF_CHECK_EQ(error, reason == CAP_AUTH_ISSUER_R_TEST ? 0 : EPERM);
	for (line = out; line != NULL && *line != '\0'; line = next) {
		next = strchr(line, '\n');
		if (next != NULL)
			*next++ = '\0';
		if (line[0] != 'D')
			continue;
		ATF_REQUIRE_MSG(sscanf(line, "D %ju %d %d %ju %d", &identity,
		    &outcome, &preason, &latency, &perrno) == 5,
		    "unparsed firing: %s", line);
		firings++;
		ATF_CHECK_EQ(preason, reason);
		ATF_CHECK_EQ(latency, 0);
		ATF_CHECK_EQ(perrno, error);
		if (error == 0) {
			ATF_CHECK_EQ(outcome, CAP_AUTH_ISSUER_O_ALLOW);
			ATF_CHECK_MSG(identity != 0, "allowed with identity 0");
		} else {
			ATF_CHECK_EQ(outcome, CAP_AUTH_ISSUER_O_DENY);
			ATF_CHECK_EQ(identity, 0);
		}
	}
	ATF_CHECK_EQ_MSG(firings, 1, "%d firings for one create", firings);
	free(out);
}

#define	PROBE_TC(name, where, descr)					\
ATF_TC(name);								\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "require.user", "root");			\
	atf_tc_set_md_var(tc, "require.progs", "/usr/sbin/dtrace");	\
	atf_tc_set_md_var(tc, "timeout", "180");			\
}									\
ATF_TC_BODY(name, tc)							\
{									\
	check_decision(where);						\
}

PROBE_TC(create, PLAIN,
    "A create off PID 1 fires once: NOT_INIT, TEST or ANCHORED")
PROBE_TC(jailed, JAILED, "A jailed create fires DENY JAILED EPERM")
PROBE_TC(capmode, CAPMODE,
    "A create in capability mode fires DENY CAPMODE (NOT_INIT without the switch)")

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, create);
	ATF_TP_ADD_TC(tp, jailed);
	ATF_TP_ADD_TC(tp, capmode);
	return (atf_no_error());
}
