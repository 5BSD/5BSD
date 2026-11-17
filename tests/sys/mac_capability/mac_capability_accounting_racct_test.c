/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Resource accounting cannot be turned off in 5BSD.  A kernel booted with
 * the old kern.racct.enable=0 tunable ignores it with a console notice:
 * kern.racct.enable reads 1, every process has racct state, and the
 * accounting service works as on any other boot.  The cases need such a
 * boot (loader.conf kern.racct.enable=0); without the tunable they skip.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/kenv.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <kenv.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_accounting_proto.h"

#ifndef RACCT_MEMLOCK
#define	RACCT_MEMLOCK	5
#endif
#ifndef RACCT_NOFILE
#define	RACCT_NOFILE	7
#endif

static void
require_tunable_zero(void)
{
	char value[16];

	if (kenv(KENV_GET, "kern.racct.enable", value, sizeof(value)) < 0 ||
	    strcmp(value, "0") != 0)
		atf_tc_skip("needs a boot with kern.racct.enable=0");
}

static int
acct_call(int fd, const void *req, size_t reqlen, void *reply,
    size_t replylen)
{
	struct mac_capability_call_args ca;

	memset(&ca, 0, sizeof(ca));
	ca.req = req;
	ca.req_len = reqlen;
	ca.reply = reply;
	ca.reply_len = replylen;
	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
}

ATF_TC(tunable_zero_ignored);
ATF_TC_HEAD(tunable_zero_ignored, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "kern.racct.enable=0 at boot leaves resource accounting on");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(tunable_zero_ignored, tc)
{
	char out[4096], filter[32];
	size_t len;
	bool enabled;

	require_tunable_zero();
	ATF_REQUIRE(feature_present("racct"));
	enabled = false;
	len = sizeof(enabled);
	ATF_REQUIRE_MSG(sysctlbyname("kern.racct.enable", &enabled, &len,
	    NULL, 0) == 0, "kern.racct.enable: %s", strerror(errno));
	ATF_CHECK_MSG(enabled, "kern.racct.enable reads 0");
	/* This process has racct state: rctl answers for it. */
	snprintf(filter, sizeof(filter), "process:%d", (int)getpid());
	ATF_CHECK_MSG(rctl_get_racct(filter, strlen(filter) + 1, out,
	    sizeof(out)) == 0, "rctl_get_racct: %s", strerror(errno));
}

ATF_TC(accounting_works);
ATF_TC_HEAD(accounting_works, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "after kern.racct.enable=0 the accounting service charges, "
	    "releases, sets and manages rules");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(accounting_works, tc)
{
	struct acct_charge_request creq;
	struct acct_rule_request rreq;
	struct acct_get_rules_request greq;
	struct acct_rules_reply rules;
	struct acct_reply reply;
	int64_t before;
	int fd;

	require_tunable_zero();
	fd = mac_capability_connect("accounting");
	ATF_REQUIRE_MSG(fd >= 0, "connect accounting: %s", strerror(errno));
	before = racct_usage(getpid(), "memorylocked");

	memset(&creq, 0, sizeof(creq));
	creq.op = ACCT_OP_CHARGE;
	creq.resource = RACCT_MEMLOCK;
	creq.amount = 4096;
	ATF_REQUIRE_MSG(acct_call(fd, &creq, sizeof(creq), &reply,
	    sizeof(reply)) == 0, "CHARGE: %s", strerror(errno));
	ATF_CHECK_EQ(ACCT_STATUS_OK, reply.status);
	ATF_CHECK_EQ(before + 4096, racct_usage(getpid(), "memorylocked"));

	creq.op = ACCT_OP_RELEASE;
	ATF_REQUIRE_MSG(acct_call(fd, &creq, sizeof(creq), &reply,
	    sizeof(reply)) == 0, "RELEASE: %s", strerror(errno));
	ATF_CHECK_EQ(ACCT_STATUS_OK, reply.status);
	ATF_CHECK_EQ(before, racct_usage(getpid(), "memorylocked"));

	creq.op = ACCT_OP_SET;
	creq.amount = 8192;
	ATF_REQUIRE_MSG(acct_call(fd, &creq, sizeof(creq), &reply,
	    sizeof(reply)) == 0, "SET: %s", strerror(errno));
	ATF_CHECK_EQ(ACCT_STATUS_OK, reply.status);
	ATF_CHECK_EQ(8192, racct_usage(getpid(), "memorylocked"));

	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_ADD_RULE;
	rreq.resource = RACCT_NOFILE;
	rreq.action = ACCT_RULE_LOG;
	rreq.limit = 123456;
	ATF_REQUIRE_MSG(acct_call(fd, &rreq, sizeof(rreq), &reply,
	    sizeof(reply)) == 0, "ADD_RULE: %s", strerror(errno));
	ATF_CHECK_EQ(ACCT_STATUS_OK, reply.status);

	memset(&greq, 0, sizeof(greq));
	greq.op = ACCT_OP_GET_RULES;
	ATF_REQUIRE_MSG(acct_call(fd, &greq, sizeof(greq), &rules,
	    sizeof(rules)) == 0, "GET_RULES: %s", strerror(errno));
	ATF_CHECK_EQ(ACCT_STATUS_OK, rules.status);
	ATF_CHECK(rules.nrules >= 1);

	rreq.op = ACCT_OP_REMOVE_RULE;
	ATF_REQUIRE_MSG(acct_call(fd, &rreq, sizeof(rreq), &reply,
	    sizeof(reply)) == 0, "REMOVE_RULE: %s", strerror(errno));
	ATF_CHECK_EQ(ACCT_STATUS_OK, reply.status);
	close(fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, tunable_zero_ignored);
	ATF_TP_ADD_TC(tp, accounting_works);
	return (atf_no_error());
}
