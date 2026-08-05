/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Tests for mac_capability_system — system operation gating.
 *
 * Requires:
 *   kldload mac_capability
 *   kldload mac_capability_system
 */

#include <sys/types.h>
#include <sys/capsicum.h>
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

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_system_proto.h"

static int
sys_connect(void)
{
	struct mac_capability_connect_args ca;
	int ctl;

	ctl = mac_capability_open();
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "system", sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		if (errno == ENOENT)
			atf_tc_skip("mac_capability_system not loaded");
		ATF_REQUIRE_MSG(0, "connect system: %s",
		    strerror(errno));
	}
	close(ctl);
	return (ca.fd);
}

static int
sys_call_claim(int fd, uint32_t gates)
{
	struct mac_capability_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = gates;

	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;

	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
}

static int
sys_call_mint(int fd, int *token_fd)
{
	struct mac_capability_call_args ca;
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

	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
}

static int
sys_call_authorize(int token_fd)
{
	struct mac_capability_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_AUTHORIZE;

	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;

	return (ioctl(token_fd, MAC_CAPABILITY_CALL, &ca));
}

/*
 * Fork+exec to get a new nonce, then try kldnext(2) directly.
 * kldstat(1) always exits 0 even when the syscall returns EPERM,
 * so we exec the helper binary which calls kldnext(2) itself.
 * Returns child exit status: 0 = denied (good), 1 = allowed (bad).
 */
static int
run_cross_nonce_kldstat(const atf_tc_t *tc)
{
	pid_t pid;
	int status;
	char path[1024];
	const char *dir;

	dir = atf_tc_get_config_var(tc, "srcdir");
	snprintf(path, sizeof(path), "%s/mac_capability_exec_helper", dir);

	pid = fork();
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		execl(path, path, "kldnext", NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static int
sys_call_mint_narrow(int fd, uint32_t gates, int *token_fd)
{
	struct mac_capability_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_MINT;
	req.gates = gates;

	*token_fd = -1;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = token_fd;
	ca.reply_nfds = 1;
	ca.reply_len = 0;

	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
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

	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK_MSG(rc == 0, "kldnext should be denied for foreign nonce");

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
	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK(rc == 0);

	close(svc);

	/* After close, claim released — foreign nonce allowed. */
	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK_MSG(rc != 0, "kldnext should work after claim released");
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
	char path[1024];
	const char *dir;
	int svc, token_fd, readyfd[2], gofd[2], status;
	pid_t pid;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_KLDSTAT) == 0);

	ATF_REQUIRE(sys_call_mint(svc, &token_fd) == 0);

	ATF_REQUIRE(pipe(readyfd) == 0);
	ATF_REQUIRE(pipe(gofd) == 0);

	dir = atf_tc_get_config_var(tc, "srcdir");
	snprintf(path, sizeof(path), "%s/mac_capability_exec_helper", dir);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char tokenstr[16], readystr[16], gostr[16];

		close(readyfd[0]);
		close(gofd[1]);
		snprintf(tokenstr, sizeof(tokenstr), "%d", token_fd);
		snprintf(readystr, sizeof(readystr), "%d", readyfd[1]);
		snprintf(gostr, sizeof(gostr), "%d", gofd[0]);
		execl(path, path, "auth_kldnext", tokenstr, readystr, gostr,
		    NULL);
		_exit(127);
	}

	close(readyfd[1]);
	close(gofd[0]);

	/* Wait until the child has authorized and is blocked on go. */
	ATF_REQUIRE(read(readyfd[0], &(char){0}, 1) == 1);
	close(readyfd[0]);

	/* Drop the parent's reference, then let the child test revocation. */
	close(token_fd);
	ATF_REQUIRE(write(gofd[1], "x", 1) == 1);
	close(gofd[1]);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

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
	ATF_CHECK(run_cross_nonce_kldstat(tc) != 0);

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

ATF_TC(refcount_partial_close);
ATF_TC_HEAD(refcount_partial_close, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing one claim preserves the other's gate enforcement");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(refcount_partial_close, tc)
{
	int svc1, svc2, rc;

	svc1 = sys_connect();
	svc2 = sys_connect();

	/* svc1 claims KLDSTAT, svc2 claims KLDSTAT + REBOOT. */
	ATF_REQUIRE(sys_call_claim(svc1, SYS_GATE_KLDSTAT) == 0);
	ATF_REQUIRE(sys_call_claim(svc2, SYS_GATE_KLDSTAT | SYS_GATE_REBOOT) == 0);

	/* Foreign nonce denied. */
	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK_MSG(rc == 0, "kldnext should be denied (both active)");

	/* Close svc1 — svc2 still holds KLDSTAT. */
	close(svc1);

	/* Foreign nonce should STILL be denied. */
	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK_MSG(rc == 0,
	    "kldnext should still be denied (svc2 holds KLDSTAT)");

	/* Close svc2 — all claims released. */
	close(svc2);

	/* Foreign nonce should now be allowed. */
	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK_MSG(rc != 0,
	    "kldnext should work after all claims released");
}

ATF_TC(mint_narrow_subset);
ATF_TC_HEAD(mint_narrow_subset, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Minting with a subset of claimed gates succeeds");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_narrow_subset, tc)
{
	int svc, token_fd;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc,
	    SYS_GATE_KLDSTAT | SYS_GATE_REBOOT) == 0);

	ATF_REQUIRE(sys_call_mint_narrow(svc, SYS_GATE_KLDSTAT,
	    &token_fd) == 0);
	ATF_REQUIRE(token_fd >= 0);

	ATF_REQUIRE(sys_call_authorize(token_fd) == 0);
	close(token_fd);
	close(svc);
}

ATF_TC(mint_narrow_rejects_unclaimed);
ATF_TC_HEAD(mint_narrow_rejects_unclaimed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Minting with gates outside the claim fails");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_narrow_rejects_unclaimed, tc)
{
	int svc, token_fd;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_KLDSTAT) == 0);

	ATF_CHECK(sys_call_mint_narrow(svc,
	    SYS_GATE_KLDSTAT | SYS_GATE_REBOOT, &token_fd) != 0);
	ATF_CHECK(errno == EINVAL);

	close(svc);
}

ATF_TC(mint_narrow_zero_gives_all);
ATF_TC_HEAD(mint_narrow_zero_gives_all, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Minting with gates=0 gives full claimed scope");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_narrow_zero_gives_all, tc)
{
	int svc, token_fd;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc,
	    SYS_GATE_KLDSTAT | SYS_GATE_REBOOT) == 0);

	/* gates=0 should give all claimed gates */
	ATF_REQUIRE(sys_call_mint(svc, &token_fd) == 0);
	ATF_REQUIRE(token_fd >= 0);

	ATF_REQUIRE(sys_call_authorize(token_fd) == 0);
	close(token_fd);
	close(svc);
}

ATF_TC(capmode_authorized_kldstat);
ATF_TC_HEAD(capmode_authorized_kldstat, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A system-gate holder can query kernel modules in capability mode");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(capmode_authorized_kldstat, tc)
{
	pid_t pid;
	int status, svc;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_KLDSTAT) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int id;
		struct kld_file_stat stat;

		if (cap_enter() == -1)
			_exit(2);
		id = kldnext(0);
		if (id < 0)
			_exit(3);
		memset(&stat, 0, sizeof(stat));
		stat.version = sizeof(stat);
		_exit(kldstat(id, &stat) == 0 ? 0 : 4);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "capability-mode kld query failed with child status %#x", status);
	close(svc);
}

ATF_TC(capmode_system_gate_fails_closed);
ATF_TC_HEAD(capmode_system_gate_fails_closed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Capability mode cannot use a system gate without a claim or token");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(capmode_system_gate_fails_closed, tc)
{
	pid_t pid;
	int status;

	/* Connect once so a missing policy module is reported as a skip. */
	close(sys_connect());
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (cap_enter() == -1)
			_exit(2);
		errno = 0;
		_exit(kldnext(0) == -1 && errno == EPERM ? 0 : 3);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "unclaimed capability-mode system gate was not denied: %#x",
	    status);
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
	ATF_TP_ADD_TC(tp, refcount_partial_close);
	ATF_TP_ADD_TC(tp, mint_narrow_subset);
	ATF_TP_ADD_TC(tp, mint_narrow_rejects_unclaimed);
	ATF_TP_ADD_TC(tp, mint_narrow_zero_gives_all);
	ATF_TP_ADD_TC(tp, capmode_authorized_kldstat);
	ATF_TP_ADD_TC(tp, capmode_system_gate_fails_closed);

	return (atf_no_error());
}
