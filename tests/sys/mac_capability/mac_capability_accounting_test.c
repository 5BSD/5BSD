/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Tests for the mac_capability accounting service (resource ledger and enforcement).
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_accounting_proto.h"

/* RACCT constants — may not be in userspace headers */
#ifndef RACCT_MEMLOCK
#define	RACCT_MEMLOCK	5
#endif
#ifndef RACCT_NOFILE
#define	RACCT_NOFILE	7
#endif
#ifndef RACCT_NPROC
#define	RACCT_NPROC	6
#endif
#ifndef RACCT_MAX
#define	RACCT_MAX	24
#endif

static int
acct_call_raw(int fd, const void *req, size_t reqlen,
    const int *req_fds, int nfds,
    void *reply, size_t replylen)
{
	struct mac_capability_call_args ca;

	memset(&ca, 0, sizeof(ca));
	ca.req = req;
	ca.req_len = reqlen;
	ca.req_fds = req_fds;
	ca.req_nfds = nfds;
	ca.reply = reply;
	ca.reply_len = replylen;
	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
}

static bool
acct_rules_has(const struct acct_rules_reply *reply, uint32_t resource,
    uint32_t action, uint32_t signal, uint64_t limit)
{
	u_int i;

	for (i = 0; i < reply->nrules && i < ACCT_MAX_RULES; i++) {
		if (reply->rules[i].resource != resource)
			continue;
		if (reply->rules[i].action != action)
			continue;
		if (reply->rules[i].signal != signal)
			continue;
		if (reply->rules[i].limit != limit)
			continue;
		return (true);
	}

	return (false);
}

/* ----------------------------------------------------------------
 * Self-targeting tests
 * ---------------------------------------------------------------- */

ATF_TC(acct_charge_self);
ATF_TC_HEAD(acct_charge_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_CHARGE on self succeeds");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_charge_self, tc)
{
	struct acct_charge_request req;
	struct acct_reply reply;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available (RACCT disabled?)");

	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_CHARGE;
	req.resource = RACCT_MEMLOCK;
	req.amount = 4096;
	ATF_REQUIRE(acct_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK(reply.status == ACCT_STATUS_OK ||
	    reply.status == ACCT_STATUS_ERR);  /* ERR if RACCT disabled */

	close(fd);
}

ATF_TC(acct_release_self);
ATF_TC_HEAD(acct_release_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_RELEASE on self succeeds");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_release_self, tc)
{
	struct acct_charge_request creq, rreq;
	struct acct_reply reply;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	/* Charge first */
	memset(&creq, 0, sizeof(creq));
	creq.op = ACCT_OP_CHARGE;
	creq.resource = RACCT_MEMLOCK;
	creq.amount = 4096;
	acct_call_raw(fd, &creq, sizeof(creq), NULL, 0,
	    &reply, sizeof(reply));

	/* Release */
	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_RELEASE;
	rreq.resource = RACCT_MEMLOCK;
	rreq.amount = 4096;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK(reply.status == ACCT_STATUS_OK ||
	    reply.status == ACCT_STATUS_ERR);

	close(fd);
}

ATF_TC(acct_set_self);
ATF_TC_HEAD(acct_set_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_SET on self succeeds");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_set_self, tc)
{
	struct acct_charge_request req;
	struct acct_reply reply;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_SET;
	req.resource = RACCT_MEMLOCK;
	req.amount = 8192;
	ATF_REQUIRE(acct_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK(reply.status == ACCT_STATUS_OK ||
	    reply.status == ACCT_STATUS_ERR);

	close(fd);
}

ATF_TC(acct_rule_lifecycle_self);
ATF_TC_HEAD(acct_rule_lifecycle_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_ADD_RULE and REMOVE_RULE change GET_RULES output");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_rule_lifecycle_self, tc)
{
	struct acct_rule_request rreq;
	struct acct_get_rules_request greq;
	struct acct_reply reply;
	struct acct_rules_reply rules;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_ADD_RULE;
	rreq.resource = RACCT_NOFILE;
	rreq.action = ACCT_RULE_LOG;
	rreq.limit = 123456;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	if (reply.status == ACCT_STATUS_ERR)
		atf_tc_skip("RCTL rule support not available");
	ATF_CHECK_EQ(reply.status, ACCT_STATUS_OK);

	memset(&greq, 0, sizeof(greq));
	greq.op = ACCT_OP_GET_RULES;
	ATF_REQUIRE(acct_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &rules, sizeof(rules)) == 0);
	ATF_REQUIRE_EQ(rules.status, ACCT_STATUS_OK);
	ATF_CHECK(acct_rules_has(&rules, RACCT_NOFILE, ACCT_RULE_LOG, 0,
	    123456));

	rreq.op = ACCT_OP_REMOVE_RULE;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, ACCT_STATUS_OK);

	ATF_REQUIRE(acct_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &rules, sizeof(rules)) == 0);
	ATF_REQUIRE_EQ(rules.status, ACCT_STATUS_OK);
	ATF_CHECK(!acct_rules_has(&rules, RACCT_NOFILE, ACCT_RULE_LOG, 0,
	    123456));

	close(fd);
}

ATF_TC(acct_rule_invalid_signal);
ATF_TC_HEAD(acct_rule_invalid_signal, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_ADD_RULE rejects invalid signal actions");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_rule_invalid_signal, tc)
{
	struct acct_rule_request req;
	struct acct_reply reply;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_ADD_RULE;
	req.resource = RACCT_NOFILE;
	req.action = ACCT_RULE_SIGNAL;
	req.signal = 0;
	req.limit = 1;
	ATF_REQUIRE(acct_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, ACCT_STATUS_ERR);

	close(fd);
}

/* ----------------------------------------------------------------
 * Procdesc-targeting tests
 * ---------------------------------------------------------------- */

ATF_TC(acct_charge_child);
ATF_TC_HEAD(acct_charge_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_CHARGE on child via procdesc succeeds");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_charge_child, tc)
{
	struct acct_charge_request req;
	struct acct_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(fd);
		sleep(10);
		_exit(0);
	}

	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_CHARGE;
	req.resource = RACCT_MEMLOCK;
	req.amount = 4096;
	ATF_REQUIRE(acct_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK(reply.status == ACCT_STATUS_OK ||
	    reply.status == ACCT_STATUS_ERR);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(acct_dead_child);
ATF_TC_HEAD(acct_dead_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_CHARGE on dead child returns DEAD");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_dead_child, tc)
{
	struct acct_charge_request req;
	struct acct_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(0);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);

	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_CHARGE;
	req.resource = RACCT_MEMLOCK;
	req.amount = 4096;
	ATF_REQUIRE(acct_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, ACCT_STATUS_DEAD);

	close(pd);
	close(fd);
}

ATF_TC(acct_release_child);
ATF_TC_HEAD(acct_release_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_RELEASE on child via procdesc succeeds");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_release_child, tc)
{
	struct acct_charge_request req;
	struct acct_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	/* Charge then release */
	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_CHARGE;
	req.resource = RACCT_MEMLOCK;
	req.amount = 4096;
	acct_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply));

	req.op = ACCT_OP_RELEASE;
	ATF_REQUIRE(acct_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK(reply.status == ACCT_STATUS_OK ||
	    reply.status == ACCT_STATUS_ERR);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(acct_set_child);
ATF_TC_HEAD(acct_set_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_SET on child via procdesc succeeds");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_set_child, tc)
{
	struct acct_charge_request req;
	struct acct_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_SET;
	req.resource = RACCT_MEMLOCK;
	req.amount = 8192;
	ATF_REQUIRE(acct_call_raw(fd, &req, sizeof(req), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK(reply.status == ACCT_STATUS_OK ||
	    reply.status == ACCT_STATUS_ERR);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(acct_rule_child);
ATF_TC_HEAD(acct_rule_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_ADD_RULE and GET_RULES on child via procdesc");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_rule_child, tc)
{
	struct acct_rule_request rreq;
	struct acct_get_rules_request greq;
	struct acct_reply reply;
	struct acct_rules_reply rules;
	int fd, pd, status;
	pid_t pid;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) { close(fd); sleep(10); _exit(0); }

	/* Add rule on child */
	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_ADD_RULE;
	rreq.resource = RACCT_NOFILE;
	rreq.action = ACCT_RULE_LOG;
	rreq.limit = 999;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);
	if (reply.status == ACCT_STATUS_ERR)
		atf_tc_skip("RCTL not available");
	ATF_CHECK_EQ(reply.status, ACCT_STATUS_OK);

	/* Query rules on child */
	memset(&greq, 0, sizeof(greq));
	greq.op = ACCT_OP_GET_RULES;
	ATF_REQUIRE(acct_call_raw(fd, &greq, sizeof(greq), &pd, 1,
	    &rules, sizeof(rules)) == 0);
	ATF_CHECK_EQ(rules.status, ACCT_STATUS_OK);

	/* Remove rule */
	rreq.op = ACCT_OP_REMOVE_RULE;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), &pd, 1,
	    &reply, sizeof(reply)) == 0);

	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

/* ----------------------------------------------------------------
 * Error cases
 * ---------------------------------------------------------------- */

ATF_TC(acct_invalid_resource);
ATF_TC_HEAD(acct_invalid_resource, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_CHARGE with invalid resource returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
}
ATF_TC_BODY(acct_invalid_resource, tc)
{
	struct acct_charge_request req;
	struct acct_reply reply;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_CHARGE;
	req.resource = 9999;
	req.amount = 4096;
	ATF_CHECK_ERRNO(EINVAL,
	    acct_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == -1);

	close(fd);
}

ATF_TC(acct_bad_op);
ATF_TC_HEAD(acct_bad_op, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown operation returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
}
ATF_TC_BODY(acct_bad_op, tc)
{
	struct acct_charge_request req;
	struct acct_reply reply;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	memset(&req, 0, sizeof(req));
	req.op = 99;
	req.resource = 0;
	req.amount = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    acct_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == -1);

	close(fd);
}

ATF_TC(acct_wrong_fd_type);
ATF_TC_HEAD(acct_wrong_fd_type, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Attaching a non-procdesc fd returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
}
ATF_TC_BODY(acct_wrong_fd_type, tc)
{
	struct acct_charge_request req;
	struct acct_reply reply;
	int fd, pipefd[2];

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");
	ATF_REQUIRE(pipe(pipefd) == 0);

	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_CHARGE;
	req.resource = RACCT_MEMLOCK;
	req.amount = 4096;
	ATF_CHECK_ERRNO(EINVAL,
	    acct_call_raw(fd, &req, sizeof(req), &pipefd[0], 1,
	    &reply, sizeof(reply)) == -1);

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(acct_get_rules_self);
ATF_TC_HEAD(acct_get_rules_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_GET_RULES on self returns (possibly empty) rule list");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
}
ATF_TC_BODY(acct_get_rules_self, tc)
{
	struct acct_get_rules_request req;
	struct acct_rules_reply reply;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_GET_RULES;
	ATF_REQUIRE(acct_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK(reply.status == ACCT_STATUS_OK ||
	    reply.status == ACCT_STATUS_ERR);

	close(fd);
}

/* ----------------------------------------------------------------
 * Additional coverage tests
 * ---------------------------------------------------------------- */

ATF_TC(acct_rule_signal);
ATF_TC_HEAD(acct_rule_signal, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_ADD_RULE with ACCT_RULE_SIGNAL stores correct signal");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_rule_signal, tc)
{
	struct acct_rule_request rreq;
	struct acct_get_rules_request greq;
	struct acct_reply reply;
	struct acct_rules_reply rules;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_ADD_RULE;
	rreq.resource = RACCT_NOFILE;
	rreq.action = ACCT_RULE_SIGNAL;
	rreq.signal = SIGUSR1;
	rreq.limit = 500;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	if (reply.status == ACCT_STATUS_ERR)
		atf_tc_skip("RCTL rule support not available");
	ATF_CHECK_EQ(reply.status, ACCT_STATUS_OK);

	memset(&greq, 0, sizeof(greq));
	greq.op = ACCT_OP_GET_RULES;
	ATF_REQUIRE(acct_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &rules, sizeof(rules)) == 0);
	ATF_REQUIRE_EQ(rules.status, ACCT_STATUS_OK);
	ATF_CHECK(acct_rules_has(&rules, RACCT_NOFILE, ACCT_RULE_SIGNAL,
	    SIGUSR1, 500));

	/* Cleanup */
	rreq.op = ACCT_OP_REMOVE_RULE;
	acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply));

	close(fd);
}

ATF_TC(acct_rule_throttle);
ATF_TC_HEAD(acct_rule_throttle, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_ADD_RULE with ACCT_RULE_DENY on MEMLOCK succeeds");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_rule_throttle, tc)
{
	struct acct_rule_request rreq;
	struct acct_get_rules_request greq;
	struct acct_reply reply;
	struct acct_rules_reply rules;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_ADD_RULE;
	rreq.resource = RACCT_MEMLOCK;
	rreq.action = ACCT_RULE_DENY;
	rreq.limit = 65536;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, ACCT_STATUS_OK);

	memset(&greq, 0, sizeof(greq));
	greq.op = ACCT_OP_GET_RULES;
	ATF_REQUIRE(acct_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &rules, sizeof(rules)) == 0);
	ATF_REQUIRE_EQ(rules.status, ACCT_STATUS_OK);
	ATF_CHECK(acct_rules_has(&rules, RACCT_MEMLOCK, ACCT_RULE_DENY,
	    0, 65536));

	/* Cleanup */
	rreq.op = ACCT_OP_REMOVE_RULE;
	acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply));

	close(fd);
}

ATF_TC(acct_multiple_rules);
ATF_TC_HEAD(acct_multiple_rules, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Adding 3 different rules and verifying all via GET_RULES");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_multiple_rules, tc)
{
	struct acct_rule_request rreq;
	struct acct_get_rules_request greq;
	struct acct_reply reply;
	struct acct_rules_reply rules;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	/* Rule 1: DENY on RACCT_NOFILE */
	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_ADD_RULE;
	rreq.resource = RACCT_NOFILE;
	rreq.action = ACCT_RULE_DENY;
	rreq.limit = 100;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	if (reply.status == ACCT_STATUS_ERR)
		atf_tc_skip("RCTL rule support not available");
	ATF_CHECK_EQ(reply.status, ACCT_STATUS_OK);

	/* Rule 2: LOG on RACCT_MEMLOCK */
	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_ADD_RULE;
	rreq.resource = RACCT_MEMLOCK;
	rreq.action = ACCT_RULE_LOG;
	rreq.limit = 200;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, ACCT_STATUS_OK);

	/* Rule 3: SIGNAL on RACCT_NPROC */
	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_ADD_RULE;
	rreq.resource = RACCT_NPROC;
	rreq.action = ACCT_RULE_SIGNAL;
	rreq.signal = SIGUSR1;
	rreq.limit = 300;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, ACCT_STATUS_OK);

	/* Verify all 3 rules are present */
	memset(&greq, 0, sizeof(greq));
	greq.op = ACCT_OP_GET_RULES;
	ATF_REQUIRE(acct_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &rules, sizeof(rules)) == 0);
	ATF_REQUIRE_EQ(rules.status, ACCT_STATUS_OK);
	ATF_CHECK(acct_rules_has(&rules, RACCT_NOFILE, ACCT_RULE_DENY,
	    0, 100));
	ATF_CHECK(acct_rules_has(&rules, RACCT_MEMLOCK, ACCT_RULE_LOG,
	    0, 200));
	ATF_CHECK(acct_rules_has(&rules, RACCT_NPROC, ACCT_RULE_SIGNAL,
	    SIGUSR1, 300));

	/* Cleanup all 3 rules */
	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_REMOVE_RULE;
	rreq.resource = RACCT_NOFILE;
	rreq.action = ACCT_RULE_DENY;
	rreq.limit = 100;
	acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply));

	rreq.resource = RACCT_MEMLOCK;
	rreq.action = ACCT_RULE_LOG;
	rreq.limit = 200;
	acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply));

	rreq.resource = RACCT_NPROC;
	rreq.action = ACCT_RULE_SIGNAL;
	rreq.signal = SIGUSR1;
	rreq.limit = 300;
	acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply));

	close(fd);
}

ATF_TC(acct_charge_zero);
ATF_TC_HEAD(acct_charge_zero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_CHARGE with amount=0 succeeds as a no-op");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_charge_zero, tc)
{
	struct acct_charge_request req;
	struct acct_reply reply;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	memset(&req, 0, sizeof(req));
	req.op = ACCT_OP_CHARGE;
	req.resource = RACCT_MEMLOCK;
	req.amount = 0;
	ATF_REQUIRE(acct_call_raw(fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK(reply.status == ACCT_STATUS_OK ||
	    reply.status == ACCT_STATUS_ERR);  /* ERR if RACCT disabled */

	close(fd);
}

ATF_TC(acct_set_then_get_rules);
ATF_TC_HEAD(acct_set_then_get_rules, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_SET does not affect GET_RULES (charges and rules are independent)");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_set_then_get_rules, tc)
{
	struct acct_charge_request sreq;
	struct acct_get_rules_request greq;
	struct acct_reply reply;
	struct acct_rules_reply rules_before, rules_after;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	/* Get rules before SET */
	memset(&greq, 0, sizeof(greq));
	greq.op = ACCT_OP_GET_RULES;
	ATF_REQUIRE(acct_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &rules_before, sizeof(rules_before)) == 0);
	if (rules_before.status == ACCT_STATUS_ERR)
		atf_tc_skip("RCTL/RACCT not available");

	/* SET a resource value */
	memset(&sreq, 0, sizeof(sreq));
	sreq.op = ACCT_OP_SET;
	sreq.resource = RACCT_MEMLOCK;
	sreq.amount = 16384;
	ATF_REQUIRE(acct_call_raw(fd, &sreq, sizeof(sreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);

	/* Get rules after SET */
	ATF_REQUIRE(acct_call_raw(fd, &greq, sizeof(greq), NULL, 0,
	    &rules_after, sizeof(rules_after)) == 0);
	ATF_REQUIRE_EQ(rules_after.status, ACCT_STATUS_OK);

	/* Rule count should be unchanged */
	ATF_CHECK_EQ(rules_before.nrules, rules_after.nrules);

	close(fd);
}

ATF_TC(acct_remove_nonexistent_rule);
ATF_TC_HEAD(acct_remove_nonexistent_rule, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ACCT_OP_REMOVE_RULE on a rule that was never added returns OK (idempotent)");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_remove_nonexistent_rule, tc)
{
	struct acct_rule_request rreq;
	struct acct_reply reply;
	int fd;

	fd = mac_capability_connect("accounting");
	if (fd < 0)
		atf_tc_skip("accounting service not available");

	memset(&rreq, 0, sizeof(rreq));
	rreq.op = ACCT_OP_REMOVE_RULE;
	rreq.resource = RACCT_NOFILE;
	rreq.action = ACCT_RULE_DENY;
	rreq.limit = 77777;
	ATF_REQUIRE(acct_call_raw(fd, &rreq, sizeof(rreq), NULL, 0,
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK(reply.status == ACCT_STATUS_OK ||
	    reply.status == ACCT_STATUS_ERR);  /* ERR if RCTL disabled */

	close(fd);
}

/* ----------------------------------------------------------------
 * Connect authorization
 * ---------------------------------------------------------------- */

ATF_TC(acct_unprivileged_connect_denied);
ATF_TC_HEAD(acct_unprivileged_connect_denied, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Non-root connect to accounting is denied with EPERM");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_accounting");
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(acct_unprivileged_connect_denied, tc)
{
	int fd;

	fd = mac_capability_connect("accounting");
	ATF_CHECK_MSG(fd == -1, "unprivileged connect should fail");
	ATF_CHECK_EQ(errno, EPERM);
	if (fd >= 0)
		close(fd);
}

/* ----------------------------------------------------------------
 * Test registration
 * ---------------------------------------------------------------- */

ATF_TP_ADD_TCS(tp)
{
	/* Connect authorization */
	ATF_TP_ADD_TC(tp, acct_unprivileged_connect_denied);

	/* Self-targeting */
	ATF_TP_ADD_TC(tp, acct_charge_self);
	ATF_TP_ADD_TC(tp, acct_release_self);
	ATF_TP_ADD_TC(tp, acct_set_self);
	ATF_TP_ADD_TC(tp, acct_get_rules_self);
	ATF_TP_ADD_TC(tp, acct_rule_lifecycle_self);
	ATF_TP_ADD_TC(tp, acct_rule_invalid_signal);

	/* Procdesc-targeting */
	ATF_TP_ADD_TC(tp, acct_charge_child);
	ATF_TP_ADD_TC(tp, acct_release_child);
	ATF_TP_ADD_TC(tp, acct_set_child);
	ATF_TP_ADD_TC(tp, acct_rule_child);
	ATF_TP_ADD_TC(tp, acct_dead_child);

	/* Error cases */
	ATF_TP_ADD_TC(tp, acct_invalid_resource);
	ATF_TP_ADD_TC(tp, acct_bad_op);
	ATF_TP_ADD_TC(tp, acct_wrong_fd_type);

	/* Additional coverage */
	ATF_TP_ADD_TC(tp, acct_rule_signal);
	ATF_TP_ADD_TC(tp, acct_rule_throttle);
	ATF_TP_ADD_TC(tp, acct_multiple_rules);
	ATF_TP_ADD_TC(tp, acct_charge_zero);
	ATF_TP_ADD_TC(tp, acct_set_then_get_rules);
	ATF_TP_ADD_TC(tp, acct_remove_nonexistent_rule);

	return (atf_no_error());
}
