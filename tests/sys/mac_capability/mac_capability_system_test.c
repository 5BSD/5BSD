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
 * Returns child exit status: 0 = denied, 1 = allowed.
 *
 * NOTE: module enumeration is deliberately UNGATED (read-only kld
 * queries are required by libdtrace/observability), so the expected
 * result under the current contract is 1 (allowed) no matter which
 * system gates are claimed.
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

/*
 * Regression test of the enumeration contract: there is no enumeration
 * gate.  Even while the module-management gates (KLDLOAD/KLDUNLOAD) are
 * claimed, read-only kld queries from a foreign nonce keep working —
 * gating them broke dtrace(1) kernel-CTF loading under a production boot,
 * so the kernel deliberately does not hook kld_check_stat.
 */
ATF_TC(kld_enumeration_is_ungated);
ATF_TC_HEAD(kld_enumeration_is_ungated, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "kldstat from an exec'd foreign nonce returns the module list "
	    "even while the module-management gates are claimed");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kld_enumeration_is_ungated, tc)
{
	int svc, rc, id;
	struct kld_file_stat stat;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc,
	    SYS_GATE_KLDLOAD | SYS_GATE_KLDUNLOAD) == 0);

	/* Foreign nonce must be able to enumerate modules. */
	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK_MSG(rc == 1,
	    "kldnext must succeed for a foreign nonce while the "
	    "module-management gates are claimed (enumeration is ungated)");

	/* The owner nonce enumerates too, and gets a real module list. */
	id = kldnext(0);
	ATF_REQUIRE_MSG(id >= 0, "kldnext: %s", strerror(errno));
	memset(&stat, 0, sizeof(stat));
	stat.version = sizeof(stat);
	ATF_CHECK(kldstat(id, &stat) == 0);

	close(svc);

	/* And, trivially, after the claim is released. */
	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK_MSG(rc == 1,
	    "kldnext must succeed after the claim is released");
}

/*
 * The retired enumeration gate bit (0x0004) is no longer a known gate:
 * a claim carrying it must be rejected as an unknown bit, fail-closed.
 */
ATF_TC(retired_gate_bit_rejected);
ATF_TC_HEAD(retired_gate_bit_rejected, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Claiming the retired 0x0004 enumeration bit fails with EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(retired_gate_bit_rejected, tc)
{
	int svc;

	svc = sys_connect();
	ATF_CHECK(sys_call_claim(svc, 0x0004) == -1);
	ATF_CHECK_EQ(errno, EINVAL);
	/* Also rejected when mixed with valid gates. */
	ATF_CHECK(sys_call_claim(svc, SYS_GATE_KLDLOAD | 0x0004) == -1);
	ATF_CHECK_EQ(errno, EINVAL);
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
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_REBOOT) == 0);

	ATF_REQUIRE(sys_call_mint(svc, &token_fd) == 0);
	ATF_REQUIRE(token_fd >= 0);

	ATF_REQUIRE(sys_call_authorize(token_fd) == 0);

	close(token_fd);
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

	ATF_REQUIRE(sys_call_claim(svc1, SYS_GATE_SWAPON) == 0);
	ATF_REQUIRE(sys_call_claim(svc2, SYS_GATE_REBOOT) == 0);

	/* Both should be active — close one, other persists. */
	close(svc1);
	/* REBOOT claim from svc2 should still be active.
	 * swapon claim from svc1 should be released (refcount). */

	close(svc2);
}

/*
 * Regression test: refcounted, overlapping module-management claims never
 * disturb enumeration at any stage — no combination of claims may ever
 * block a foreign nonce from a read-only kld query.
 */
ATF_TC(refcount_partial_close);
ATF_TC_HEAD(refcount_partial_close, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Overlapping module-management claims never block enumeration, "
	    "at any refcount stage");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(refcount_partial_close, tc)
{
	int svc1, svc2, rc;

	svc1 = sys_connect();
	svc2 = sys_connect();

	/* svc1 claims KLDLOAD, svc2 claims KLDLOAD + KLDUNLOAD. */
	ATF_REQUIRE(sys_call_claim(svc1, SYS_GATE_KLDLOAD) == 0);
	ATF_REQUIRE(sys_call_claim(svc2,
	    SYS_GATE_KLDLOAD | SYS_GATE_KLDUNLOAD) == 0);

	/* Foreign nonce enumerates even with both claims active. */
	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK_MSG(rc == 1, "kldnext must work (both claims active)");

	/* Close svc1 — svc2 still holds KLDLOAD. */
	close(svc1);

	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK_MSG(rc == 1,
	    "kldnext must work (svc2 still holds KLDLOAD)");

	/* Close svc2 — all claims released. */
	close(svc2);

	rc = run_cross_nonce_kldstat(tc);
	ATF_CHECK_MSG(rc == 1,
	    "kldnext must work after all claims released");
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
	    SYS_GATE_SWAPON | SYS_GATE_REBOOT) == 0);

	ATF_REQUIRE(sys_call_mint_narrow(svc, SYS_GATE_SWAPON,
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
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_SWAPON) == 0);

	ATF_CHECK(sys_call_mint_narrow(svc,
	    SYS_GATE_SWAPON | SYS_GATE_REBOOT, &token_fd) != 0);
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
	    SYS_GATE_SWAPON | SYS_GATE_REBOOT) == 0);

	/* gates=0 should give all claimed gates */
	ATF_REQUIRE(sys_call_mint(svc, &token_fd) == 0);
	ATF_REQUIRE(token_fd >= 0);

	ATF_REQUIRE(sys_call_authorize(token_fd) == 0);
	close(token_fd);
	close(svc);
}

/*
 * Regression test of the capability-mode side of the enumeration
 * contract: capmode callers fail closed on capability-enabled system
 * gates, but module enumeration is not such a gate — a sandboxed
 * process with no claim and no token can still walk the module list
 * (traced/observability clients depend on this), even while another
 * nonce holds the module-management gates.
 */
ATF_TC(capmode_kld_enumeration_open);
ATF_TC_HEAD(capmode_kld_enumeration_open, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Capability mode can enumerate modules without any claim or "
	    "token, even with module-management gates claimed");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(capmode_kld_enumeration_open, tc)
{
	pid_t pid;
	int status, svc;

	/* Claim the module-management gates; also skips if unloaded. */
	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc,
	    SYS_GATE_KLDLOAD | SYS_GATE_KLDUNLOAD) == 0);
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
	    "capability-mode kld enumeration was denied: %#x", status);
	close(svc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, kld_enumeration_is_ungated);
	ATF_TP_ADD_TC(tp, retired_gate_bit_rejected);
	ATF_TP_ADD_TC(tp, mint_and_authorize);
	ATF_TP_ADD_TC(tp, invalid_gates_rejected);
	ATF_TP_ADD_TC(tp, mint_requires_claim);
	ATF_TP_ADD_TC(tp, selective_gates);
	ATF_TP_ADD_TC(tp, multiple_claims);
	ATF_TP_ADD_TC(tp, refcount_partial_close);
	ATF_TP_ADD_TC(tp, mint_narrow_subset);
	ATF_TP_ADD_TC(tp, mint_narrow_rejects_unclaimed);
	ATF_TP_ADD_TC(tp, mint_narrow_zero_gives_all);
	ATF_TP_ADD_TC(tp, capmode_kld_enumeration_open);

	return (atf_no_error());
}
