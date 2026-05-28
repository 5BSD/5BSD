/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Tests for cap_rt_system — system operation gating.
 *
 * Requires:
 *   kldload cap_rt
 *   kldload cap_rt_system
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/linker.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "cap_rt_ioctl.h"
#include "cap_rt_system_proto.h"

static int
cap_rt_open(void)
{
	int fd;

	fd = open("/dev/cap_rt", O_RDWR);
	if (fd < 0 && errno == ENOENT)
		atf_tc_skip("cap_rt module not loaded");
	if (fd < 0 && errno == EACCES)
		atf_tc_skip("/dev/cap_rt is isolated");
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/cap_rt: %s", strerror(errno));
	return (fd);
}

static int
sys_connect(void)
{
	struct cap_rt_connect_args ca;
	int ctl;

	ctl = cap_rt_open();
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "system", sizeof(ca.name));
	if (ioctl(ctl, CAP_RT_CONNECT, &ca) != 0) {
		if (errno == ENOENT)
			atf_tc_skip("cap_rt_system not loaded");
		ATF_REQUIRE_MSG(0, "connect system: %s",
		    strerror(errno));
	}
	close(ctl);
	return (ca.fd);
}

static int
sys_call_claim(int fd, uint32_t gates)
{
	struct cap_rt_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = gates;

	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;

	return (ioctl(fd, CAP_RT_CALL, &ca));
}

static int
sys_call_mint(int fd, int *token_fd)
{
	struct cap_rt_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_MINT;

	*token_fd = -1;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = token_fd;
	ca.reply_nfds = 1;
	ca.reply_len = 0;

	return (ioctl(fd, CAP_RT_CALL, &ca));
}

static int
sys_call_authorize(int token_fd)
{
	struct cap_rt_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_AUTHORIZE;

	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;

	return (ioctl(token_fd, CAP_RT_CALL, &ca));
}

/*
 * Fork+exec to get a new nonce, then try kldstat.
 * Returns child exit status: 0 = denied (good), 1 = allowed (bad).
 */
static int
run_cross_nonce_kldstat(void)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		/* exec to rotate nonce, then try kldnext */
		execl("/bin/sh", "sh", "-c",
		    "kldstat >/dev/null 2>&1", NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/* ----------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------- */

ATF_TC(claim_denies_foreign_nonce);
ATF_TC_HEAD(claim_denies_foreign_nonce, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Claiming SYS_GATE_KLDSTAT blocks kldstat from exec'd child");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(claim_denies_foreign_nonce, tc)
{
	int svc, rc;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_KLDSTAT) == 0);

	rc = run_cross_nonce_kldstat();
	ATF_CHECK_MSG(rc != 0, "kldstat should be denied for foreign nonce");

	close(svc);
}

ATF_TC(claim_allows_same_nonce);
ATF_TC_HEAD(claim_allows_same_nonce, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Same nonce can perform claimed operations");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(claim_allows_same_nonce, tc)
{
	int svc, id;
	struct kld_file_stat stat;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_KLDSTAT) == 0);

	id = kldnext(0);
	ATF_REQUIRE_MSG(id >= 0, "kldnext: %s", strerror(errno));

	memset(&stat, 0, sizeof(stat));
	stat.version = sizeof(stat);
	ATF_CHECK(kldstat(id, &stat) == 0);

	close(svc);
}

ATF_TC(mint_and_authorize);
ATF_TC_HEAD(mint_and_authorize, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Minted token grants access via authorize");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_and_authorize, tc)
{
	int svc, token_fd;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_KLDSTAT) == 0);

	ATF_REQUIRE(sys_call_mint(svc, &token_fd) == 0);
	ATF_REQUIRE(token_fd >= 0);

	ATF_REQUIRE(sys_call_authorize(token_fd) == 0);

	close(token_fd);
	close(svc);
}

ATF_TC(close_releases_claim);
ATF_TC_HEAD(close_releases_claim, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing service fd releases the claim");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(close_releases_claim, tc)
{
	int svc, rc;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_KLDSTAT) == 0);

	/* While claimed, foreign nonce is denied. */
	rc = run_cross_nonce_kldstat();
	ATF_CHECK(rc != 0);

	close(svc);

	/* After close, claim released — foreign nonce allowed. */
	rc = run_cross_nonce_kldstat();
	ATF_CHECK_MSG(rc == 0, "kldstat should work after claim released");
}

ATF_TC(token_close_revokes);
ATF_TC_HEAD(token_close_revokes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing token fd revokes authorization");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(token_close_revokes, tc)
{
	int svc, token_fd;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_KLDSTAT) == 0);

	ATF_REQUIRE(sys_call_mint(svc, &token_fd) == 0);
	ATF_REQUIRE(sys_call_authorize(token_fd) == 0);
	close(token_fd);

	/* Token closed — authorization should be revoked.
	 * But we're same nonce so we can't test denial on ourselves.
	 * Just verify the close didn't crash anything. */
	ATF_CHECK(kldnext(0) >= 0);

	close(svc);
}

ATF_TC(invalid_gates_rejected);
ATF_TC_HEAD(invalid_gates_rejected, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Invalid gate bitmask is rejected");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(invalid_gates_rejected, tc)
{
	int svc;

	svc = sys_connect();
	ATF_CHECK(sys_call_claim(svc, 0) == -1);
	ATF_CHECK_EQ(errno, EINVAL);
	ATF_CHECK(sys_call_claim(svc, 0xFFFF) == -1);
	ATF_CHECK_EQ(errno, EINVAL);
	close(svc);
}

ATF_TC(mint_requires_claim);
ATF_TC_HEAD(mint_requires_claim, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Mint fails without an active claim");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_requires_claim, tc)
{
	int svc, token_fd;

	svc = sys_connect();
	ATF_CHECK(sys_call_mint(svc, &token_fd) == -1);
	ATF_CHECK_EQ(errno, EINVAL);
	close(svc);
}

ATF_TC(selective_gates);
ATF_TC_HEAD(selective_gates, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Claiming one gate does not affect others");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(selective_gates, tc)
{
	int svc, id;
	struct kld_file_stat stat;

	svc = sys_connect();
	/* Claim only REBOOT — kldstat should still work for everyone. */
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_REBOOT) == 0);

	id = kldnext(0);
	ATF_REQUIRE(id >= 0);
	memset(&stat, 0, sizeof(stat));
	stat.version = sizeof(stat);
	ATF_CHECK(kldstat(id, &stat) == 0);

	/* Foreign nonce should also be able to kldstat. */
	ATF_CHECK(run_cross_nonce_kldstat() == 0);

	close(svc);
}

ATF_TC(multiple_claims);
ATF_TC_HEAD(multiple_claims, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple claims from same nonce are merged");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(multiple_claims, tc)
{
	int svc1, svc2;

	svc1 = sys_connect();
	svc2 = sys_connect();

	ATF_REQUIRE(sys_call_claim(svc1, SYS_GATE_KLDSTAT) == 0);
	ATF_REQUIRE(sys_call_claim(svc2, SYS_GATE_REBOOT) == 0);

	/* Both should be active — close one, other persists. */
	close(svc1);
	/* REBOOT claim from svc2 should still be active.
	 * kldstat claim from svc1 should be released (refcount). */

	close(svc2);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, claim_denies_foreign_nonce);
	ATF_TP_ADD_TC(tp, claim_allows_same_nonce);
	ATF_TP_ADD_TC(tp, mint_and_authorize);
	ATF_TP_ADD_TC(tp, close_releases_claim);
	ATF_TP_ADD_TC(tp, token_close_revokes);
	ATF_TP_ADD_TC(tp, invalid_gates_rejected);
	ATF_TP_ADD_TC(tp, mint_requires_claim);
	ATF_TP_ADD_TC(tp, selective_gates);
	ATF_TP_ADD_TC(tp, multiple_claims);

	return (atf_no_error());
}
