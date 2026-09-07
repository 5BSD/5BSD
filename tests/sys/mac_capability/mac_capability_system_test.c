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
#include <sys/kenv.h>
#include <sys/linker.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_identity_proto.h"
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

/*
 * Fork+exec the helper under a fresh nonce and have it attempt a gated
 * kenv(KENV_SET) with no claim and no authorization.  Returns the child exit
 * status: 0 = denied (EPERM from the gate), 1 = allowed.
 */
static int
run_kenv_set(const atf_tc_t *tc)
{
	char path[1024];
	const char *dir;
	pid_t pid;
	int status;

	dir = atf_tc_get_config_var(tc, "srcdir");
	snprintf(path, sizeof(path), "%s/mac_capability_exec_helper", dir);

	pid = fork();
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		execl(path, path, "kenv_set", NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/*
 * Read the caller's own program nonce via the identity service
 * (IDENTITY_OP_SELF).  Returns 0 and stores the nonce, or -1 if the identity
 * service is not registered / the call fails.
 */
static int
read_identity_self_nonce(uint64_t *out)
{
	struct mac_capability_call_args ca;
	struct identity_request req;
	struct identity_reply reply;
	int fd;

	fd = mac_capability_connect("identity");
	if (fd < 0)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;
	memset(&reply, 0, sizeof(reply));
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply = &reply;
	ca.reply_len = sizeof(reply);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0) {
		(void)close(fd);
		return (-1);
	}
	(void)close(fd);
	if (reply.status != IDENTITY_STATUS_OK)
		return (-1);
	*out = reply.nonce;
	return (0);
}

/*
 * Fork+exec the helper's "self_nonce" mode under a fresh (exec-rotated) nonce;
 * it reports its own nonce back over a pipe.  Returns 0 and stores the nonce,
 * or -1 on any failure (including the identity service being unavailable in
 * the child, which exits non-zero).
 */
static int
exec_child_nonce(const atf_tc_t *tc, uint64_t *out)
{
	char path[1024], arg[16];
	const char *dir;
	int pfd[2], status;
	pid_t pid;
	uint64_t nonce;

	dir = atf_tc_get_config_var(tc, "srcdir");
	snprintf(path, sizeof(path), "%s/mac_capability_exec_helper", dir);
	if (pipe(pfd) != 0)
		return (-1);

	pid = fork();
	if (pid < 0) {
		(void)close(pfd[0]);
		(void)close(pfd[1]);
		return (-1);
	}
	if (pid == 0) {
		snprintf(arg, sizeof(arg), "%d", pfd[1]);
		(void)close(pfd[0]);
		execl(path, path, "self_nonce", arg, NULL);
		_exit(127);
	}
	(void)close(pfd[1]);
	if (read(pfd[0], &nonce, sizeof(nonce)) != (ssize_t)sizeof(nonce)) {
		(void)close(pfd[0]);
		(void)waitpid(pid, &status, 0);
		return (-1);
	}
	(void)close(pfd[0]);
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return (-1);
	*out = nonce;
	return (0);
}

/*
 * Two benign, reversible RW integer sysctls used to probe per-OID isolation:
 * each is read and written back to its own value, so an allowed write mutates
 * nothing.  X is the isolated OID under test; Y is a different privileged OID
 * used to prove isolation is per-OID (Y must stay directly writable while only
 * X is isolated).
 */
#define	SYSCTL_OID_X	"kern.maxfiles"
#define	SYSCTL_OID_Y	"kern.maxfilesperproc"

/*
 * Build and issue a SYS_OP_CLAIM / SYS_OP_RELEASE carrying a SYSCTL OID set,
 * resolving each name to its MIB via sysctlnametomib(3).  op selects claim
 * (additive union) vs release (subtractive).  Returns the ioctl result.
 */
static int
sysctl_oids_call(int fd, uint32_t op, const char * const *names, u_int nnames)
{
	struct mac_capability_call_args ca;
	struct sys_request *req;
	struct sys_sysctl_oidset *oset;
	unsigned char *buf;
	size_t len;
	u_int i, j;
	int rc;

	len = sizeof(struct sys_request) + sizeof(uint32_t) +
	    (size_t)nnames * sizeof(struct sys_sysctl_oid);
	buf = malloc(len);
	if (buf == NULL)
		return (-1);
	memset(buf, 0, len);
	req = (struct sys_request *)buf;
	req->op = op;
	req->gates = SYS_GATE_SYSCTL;
	oset = (struct sys_sysctl_oidset *)(buf + sizeof(struct sys_request));
	oset->noids = nnames;
	for (i = 0; i < nnames; i++) {
		int mib[CTL_MAXNAME];
		size_t depth = CTL_MAXNAME;

		if (sysctlnametomib(names[i], mib, &depth) != 0) {
			free(buf);
			return (-1);
		}
		oset->oids[i].depth = (uint32_t)depth;
		for (j = 0; j < depth; j++)
			oset->oids[i].mib[j] = mib[j];
	}
	memset(&ca, 0, sizeof(ca));
	ca.req = buf;
	ca.req_len = len;
	ca.reply_len = 0;
	rc = ioctl(fd, MAC_CAPABILITY_CALL, &ca);
	free(buf);
	return (rc);
}

/*
 * Fork+exec the helper under a fresh (foreign) nonce to read+write-back the
 * named integer sysctl.  Returns the child exit status: 0 = write denied
 * (isolated), 1 = write allowed, 5 = name resolution/read was gated (a bug),
 * -1 on harness failure.
 */
static int
run_foreign_sysctl_write(const atf_tc_t *tc, const char *name)
{
	char path[1024];
	const char *dir;
	pid_t pid;
	int status;

	dir = atf_tc_get_config_var(tc, "srcdir");
	snprintf(path, sizeof(path), "%s/mac_capability_exec_helper", dir);
	pid = fork();
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		execl(path, path, "sysctl_named", name, NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
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

/* A short, reversible kenv variable used only to probe the KENV gate. */
#define	KENV_PROBE_NAME	"mac_cap_gate_probe"

/*
 * Fork+exec the helper so it runs under a fresh nonce, claims SYS_GATE_KENV,
 * and blocks holding that claim.  Because SYS_OP_CLAIM inserts at the head of
 * the claim list, the child's claim is enumerated BEFORE the parent's — the
 * exact ordering that once made sys_check_gate wrongly deny the parent.
 * Returns the child pid via *pidp and the "release" write-end via *releasep;
 * the caller must write one byte to *releasep and waitpid(*pidp) to clean up.
 */
static void
plant_foreign_kenv_claim(const atf_tc_t *tc, pid_t *pidp, int *releasep)
{
	char path[1024], readyarg[16], goarg[16];
	const char *dir;
	int ready[2], go[2];
	pid_t pid;
	char b;

	dir = atf_tc_get_config_var(tc, "srcdir");
	snprintf(path, sizeof(path), "%s/mac_capability_exec_helper", dir);
	ATF_REQUIRE(pipe(ready) == 0);
	ATF_REQUIRE(pipe(go) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		snprintf(readyarg, sizeof(readyarg), "%d", ready[1]);
		snprintf(goarg, sizeof(goarg), "%d", go[0]);
		(void)close(ready[0]);
		(void)close(go[1]);
		execl(path, path, "claim_hold", "0x80" /* SYS_GATE_KENV */,
		    readyarg, goarg, NULL);
		_exit(127);
	}
	(void)close(ready[1]);
	(void)close(go[0]);
	/* Wait until the child has actually claimed the gate. */
	ATF_REQUIRE_MSG(read(ready[0], &b, 1) == 1,
	    "foreign claim helper never reported ready");
	(void)close(ready[0]);
	*pidp = pid;
	*releasep = go[1];
}

/*
 * Regression for the sys_check_gate first-match early-deny bug: a caller that
 * owns its OWN covering claim must be allowed even when a DIFFERENT nonce's
 * claim on the same gate is enumerated first.  The parent claims KENV, a
 * foreign nonce then claims KENV (landing at the list head), and the parent's
 * own kenv(KENV_SET) must still succeed — before the fix it returned EPERM
 * because the loop decided on the foreign head claim and never reached the
 * parent's.
 */
ATF_TC(own_claim_not_shadowed_by_foreign);
ATF_TC_HEAD(own_claim_not_shadowed_by_foreign, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a nonce that owns a covering claim is allowed even when another "
	    "nonce's claim on the same gate is enumerated first");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(own_claim_not_shadowed_by_foreign, tc)
{
	char value[] = "1";
	int svc, rel, status;
	pid_t pid;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_KENV) == 0);

	/* A foreign nonce claims the same gate, ahead of ours in the list. */
	plant_foreign_kenv_claim(tc, &pid, &rel);

	/* Our own claim must still admit our kenv write. */
	errno = 0;
	ATF_CHECK_MSG(kenv(KENV_SET, KENV_PROBE_NAME, value,
	    (int)sizeof(value)) == 0,
	    "own KENV claim was shadowed by a foreign claim: %s",
	    strerror(errno));

	/* Release the helper and clean up the probe variable. */
	ATF_REQUIRE(write(rel, "g", 1) == 1);
	(void)close(rel);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	(void)kenv(KENV_UNSET, KENV_PROBE_NAME, NULL, 0);
	close(svc);
}

/*
 * Positive enforcement: while a gate is claimed, a foreign nonce holding
 * neither a claim nor an authorization is DENIED the gated operation.  Proves
 * sys_check_gate actually enforces (not merely fails open) — the companion to
 * the shadowing regression above.
 */
ATF_TC(unclaimed_foreign_nonce_denied);
ATF_TC_HEAD(unclaimed_foreign_nonce_denied, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a foreign nonce with no claim and no authorization is denied a "
	    "gated kenv write while the gate is claimed");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unclaimed_foreign_nonce_denied, tc)
{
	char path[1024];
	const char *dir;
	int svc, status;
	pid_t pid;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_KENV) == 0);

	dir = atf_tc_get_config_var(tc, "srcdir");
	snprintf(path, sizeof(path), "%s/mac_capability_exec_helper", dir);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "kenv_set", NULL);
		_exit(127);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "unclaimed foreign nonce was NOT denied the gated kenv write "
	    "(status %#x)", status);
	/* In case the write slipped through, do not leave the probe behind. */
	(void)kenv(KENV_UNSET, KENV_PROBE_NAME, NULL, 0);
	close(svc);
}

/*
 * Claim cleanup on claimant death: a foreign nonce that is DENIED a gated
 * kenv write while another nonce holds the KENV claim must become ALLOWED once
 * that claimant dies and its claim fd is closed (the claim is reclaimed by the
 * revoke path, reverting the gate to the unclaimed — allow — state).
 */
ATF_TC(claim_reverts_on_claimant_death);
ATF_TC_HEAD(claim_reverts_on_claimant_death, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a gate denied while a foreign nonce holds the claim becomes "
	    "allowed once that claimant exits and its claim fd closes");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(claim_reverts_on_claimant_death, tc)
{
	int svc, rel, status;
	pid_t pid;

	/* Connect (skips if the system service is not loaded); we hold no
	 * claim ourselves — only the planted child claims KENV. */
	svc = sys_connect();

	/* A foreign, exec'd nonce claims KENV and blocks holding it. */
	plant_foreign_kenv_claim(tc, &pid, &rel);

	/* While the claim is live, another foreign nonce is denied the write. */
	ATF_CHECK_MSG(run_kenv_set(tc) == 0,
	    "a foreign nonce must be denied the gated kenv write while the "
	    "KENV claim is held");

	/* Kill the claimant: release it so it exits, closing its claim fd. */
	ATF_REQUIRE(write(rel, "g", 1) == 1);
	(void)close(rel);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);

	/* The claim is now reclaimed — the same op must be allowed again. */
	ATF_CHECK_MSG(run_kenv_set(tc) == 1,
	    "the gate must revert to allow once the claimant dies and its "
	    "claim fd is closed");

	/* Do not leave the probe variable behind. */
	(void)kenv(KENV_UNSET, KENV_PROBE_NAME, NULL, 0);
	close(svc);
}

/*
 * Capability-mode fail-closed on a REAL gated op.  A capmode caller with no
 * token is denied a gated sysctl write; the same caller holding an authorized
 * token is allowed.  Uses the SYSCTL gate because __sysctl(2) is
 * SYF_CAPENABLED and thus reaches the MAC hook inside capability mode — kenv(2)
 * is NOT capability-enabled and would return ECAPMODE before the gate runs.
 * The sysctl hook only gates writes, so the probe writes kern.maxfiles back to
 * its own value (a no-op mutation) purely to exercise the write path.
 */
/*
 * The SYSCTL gate scopes real WRITES but must not gate sysctl NAME resolution.
 * sysctlbyname(3)/sysctlnametomib(3) resolve a name through the CTL_SYSCTL
 * NAME2OID magic node, which is CTLFLAG_RD yet passes the name to resolve via
 * the "new" buffer; gating it as a write breaks sysctl name lookup for every
 * foreign nonce whenever SYS_GATE_SYSCTL is claimed.  With the parent holding
 * the claim, a foreign nonce must still resolve+read a sysctl by name, yet be
 * denied a real write to it.  (Deliberately NOT a capmode test: a capmode
 * sysctl write is independently blocked by capsicum unless the OID is
 * CTLFLAG_CAPWR, which would confound the gate result.)
 */
ATF_TC(sysctl_gate_scopes_writes_not_name_lookup);
ATF_TC_HEAD(sysctl_gate_scopes_writes_not_name_lookup, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "while SYS_GATE_SYSCTL is claimed a foreign nonce can still resolve "
	    "and read a sysctl by name, but is denied a real write");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sysctl_gate_scopes_writes_not_name_lookup, tc)
{
	char path[1024];
	const char *dir;
	int svc, status;
	pid_t pid;

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_SYSCTL) == 0);

	dir = atf_tc_get_config_var(tc, "srcdir");
	snprintf(path, sizeof(path), "%s/mac_capability_exec_helper", dir);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(path, path, "sysctl_probe", NULL);
		_exit(127);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status), "helper did not exit (status %#x)",
	    status);
	ATF_CHECK_MSG(WEXITSTATUS(status) != 5,
	    "foreign-nonce sysctl NAME resolution was gated under a SYSCTL "
	    "claim (the NAME2OID magic node must not be treated as a write)");
	ATF_CHECK_MSG(WEXITSTATUS(status) == 0,
	    "foreign-nonce sysctl WRITE was not denied under a SYSCTL claim "
	    "(exit %d; 1 = wrongly allowed)", WEXITSTATUS(status));

	close(svc);
}

/*
 * Nonce identity: fork PRESERVES the program nonce while exec ROTATES it, and
 * two independently exec'd children get DISTINCT nonces.  Read directly via the
 * identity service (IDENTITY_OP_SELF); skips if that service is not loaded.
 */
ATF_TC(nonce_identity_fork_preserve_exec_rotate);
ATF_TC_HEAD(nonce_identity_fork_preserve_exec_rotate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "fork preserves the program nonce, exec rotates it, and two "
	    "independently exec'd children get distinct nonces");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nonce_identity_fork_preserve_exec_rotate, tc)
{
	uint64_t parent_nonce, fork_nonce, exec_a, exec_b;
	int pfd[2], status;
	pid_t pid;

	/* Parent's own nonce (skips if the identity service is unavailable). */
	if (read_identity_self_nonce(&parent_nonce) != 0)
		atf_tc_skip("mac_capability_identity not loaded");
	ATF_CHECK(parent_nonce != 0);

	/* fork WITHOUT exec: the child must observe the SAME nonce. */
	ATF_REQUIRE(pipe(pfd) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		uint64_t n = 0;

		(void)close(pfd[0]);
		if (read_identity_self_nonce(&n) != 0)
			_exit(3);
		if (write(pfd[1], &n, sizeof(n)) != (ssize_t)sizeof(n))
			_exit(4);
		_exit(0);
	}
	(void)close(pfd[1]);
	ATF_REQUIRE(read(pfd[0], &fork_nonce, sizeof(fork_nonce)) ==
	    (ssize_t)sizeof(fork_nonce));
	(void)close(pfd[0]);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "fork child failed to read its nonce (status %#x)", status);
	ATF_CHECK_MSG(fork_nonce == parent_nonce,
	    "fork must preserve the nonce (parent 0x%jx, child 0x%jx)",
	    (uintmax_t)parent_nonce, (uintmax_t)fork_nonce);

	/* Two independent fork+exec children: each nonce is rotated (differs
	 * from the parent) and distinct from the other. */
	ATF_REQUIRE(exec_child_nonce(tc, &exec_a) == 0);
	ATF_REQUIRE(exec_child_nonce(tc, &exec_b) == 0);
	ATF_CHECK(exec_a != 0);
	ATF_CHECK(exec_b != 0);
	ATF_CHECK_MSG(exec_a != parent_nonce,
	    "exec must rotate the nonce (parent 0x%jx, child 0x%jx)",
	    (uintmax_t)parent_nonce, (uintmax_t)exec_a);
	ATF_CHECK_MSG(exec_b != parent_nonce,
	    "exec must rotate the nonce (parent 0x%jx, child 0x%jx)",
	    (uintmax_t)parent_nonce, (uintmax_t)exec_b);
	ATF_CHECK_MSG(exec_a != exec_b,
	    "two exec'd children must get distinct nonces (0x%jx, 0x%jx)",
	    (uintmax_t)exec_a, (uintmax_t)exec_b);
}

/*
 * The authorization table is bounded by a GLOBAL cap (kern.mac_capability_
 * system.max_auth), not merely per-accessor: an attacker rotating its nonce
 * cheaply must not be able to grow sys_auths without bound.  Set a low cap two
 * above the current count, then authorize three distinct minted tokens under
 * one nonce; the first two fit and the third overflows with ENOSPC.  (One
 * nonce authorizing three distinct token instances suffices to reach the total
 * cap, which is exactly what a per-accessor-only limit would fail to bound.)
 */
ATF_TC(auth_entries_globally_capped);
ATF_TC_HEAD(auth_entries_globally_capped, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "the authorization table enforces a global (total) entry cap, not "
	    "just a per-accessor one");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(auth_entries_globally_capped, tc)
{
	unsigned saved_max, cur, newmax;
	size_t sz;
	int svc, t[3], i, rc;

	sz = sizeof(saved_max);
	if (sysctlbyname("kern.mac_capability_system.max_auth", &saved_max,
	    &sz, NULL, 0) != 0)
		atf_tc_skip("mac_capability_system not loaded");
	sz = sizeof(cur);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_system.auth_count", &cur,
	    &sz, NULL, 0) == 0);
	newmax = cur + 2;
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_system.max_auth", NULL,
	    NULL, &newmax, sizeof(newmax)) == 0);

	svc = sys_connect();
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_REBOOT) == 0);
	for (i = 0; i < 3; i++) {
		ATF_REQUIRE(sys_call_mint(svc, &t[i]) == 0);
		ATF_REQUIRE(t[i] >= 0);
	}

	ATF_CHECK_EQ_MSG(0, sys_call_authorize(t[0]),
	    "authorization 1 should fit under the cap");
	ATF_CHECK_EQ_MSG(0, sys_call_authorize(t[1]),
	    "authorization 2 should fit under the cap");
	rc = sys_call_authorize(t[2]);
	ATF_CHECK_MSG(rc == -1 && errno == ENOSPC,
	    "authorization 3 must hit the global cap (rc=%d errno=%d)",
	    rc, errno);

	/* Restore the cap and release the tokens (revoke decrements the count). */
	(void)sysctlbyname("kern.mac_capability_system.max_auth", NULL, NULL,
	    &saved_max, sizeof(saved_max));
	for (i = 0; i < 3; i++)
		close(t[i]);
	close(svc);
}

/*
 * Per-OID isolation: a SYSCTL claim listing ONLY OID X isolates exactly X.  A
 * foreign nonce is DENIED a direct write to X but ALLOWED a write to a
 * different privileged OID Y — the coarse gate would have denied both.  Name
 * resolution stays ungated (the helper reports 5 if resolving/reading the OID
 * failed, which must not happen).
 */
ATF_TC(sysctl_isolation_scopes_to_listed_oid);
ATF_TC_HEAD(sysctl_isolation_scopes_to_listed_oid, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a scoped SYSCTL claim listing only OID X denies a foreign write "
	    "to X but allows a foreign write to a different privileged OID Y");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sysctl_isolation_scopes_to_listed_oid, tc)
{
	const char *only_x[] = { SYSCTL_OID_X };
	int svc, rc;

	svc = sys_connect();
	ATF_REQUIRE_MSG(sysctl_oids_call(svc, SYS_OP_CLAIM, only_x, 1) == 0,
	    "scoped SYSCTL claim of %s failed: %s", SYSCTL_OID_X,
	    strerror(errno));

	rc = run_foreign_sysctl_write(tc, SYSCTL_OID_X);
	ATF_CHECK_MSG(rc != 5,
	    "name resolution of the isolated OID %s was gated", SYSCTL_OID_X);
	ATF_CHECK_MSG(rc == 0,
	    "foreign write to the isolated OID %s must be denied (rc=%d)",
	    SYSCTL_OID_X, rc);

	rc = run_foreign_sysctl_write(tc, SYSCTL_OID_Y);
	ATF_CHECK_MSG(rc == 1,
	    "foreign write to the non-isolated OID %s must be allowed (rc=%d)",
	    SYSCTL_OID_Y, rc);

	close(svc);
}

/*
 * Back-compat regression: an EMPTY-set (coarse) SYSCTL claim still gates a
 * foreign write to ANY privileged OID — an empty set isolates everything,
 * exactly as the old all-or-nothing gate did.  Both X and Y are denied.
 */
ATF_TC(sysctl_coarse_claim_gates_all_oids);
ATF_TC_HEAD(sysctl_coarse_claim_gates_all_oids, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "an empty-set (coarse) SYSCTL claim gates a foreign write to every "
	    "privileged OID, preserving the historical all-or-nothing behavior");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sysctl_coarse_claim_gates_all_oids, tc)
{
	int svc, rc;

	svc = sys_connect();
	/* No OID payload => coarse: isolate all privileged sysctl writes. */
	ATF_REQUIRE(sys_call_claim(svc, SYS_GATE_SYSCTL) == 0);

	rc = run_foreign_sysctl_write(tc, SYSCTL_OID_X);
	ATF_CHECK_MSG(rc == 0,
	    "coarse claim must deny foreign write to %s (rc=%d)",
	    SYSCTL_OID_X, rc);
	rc = run_foreign_sysctl_write(tc, SYSCTL_OID_Y);
	ATF_CHECK_MSG(rc == 0,
	    "coarse claim must deny foreign write to %s (rc=%d)",
	    SYSCTL_OID_Y, rc);

	close(svc);
}

/*
 * Runtime-editable set: two additive CLAIM calls (same fd) each add a
 * different OID; both end up isolated.  A subtractive RELEASE of one OID then
 * leaves the other still isolated (the removed OID becomes directly writable
 * again).
 */
ATF_TC(sysctl_isolation_union_and_subtract);
ATF_TC_HEAD(sysctl_isolation_union_and_subtract, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "additive CLAIMs union OIDs into the isolated set and a subtractive "
	    "RELEASE removes one, leaving the other isolated");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sysctl_isolation_union_and_subtract, tc)
{
	const char *only_x[] = { SYSCTL_OID_X };
	const char *only_y[] = { SYSCTL_OID_Y };
	int svc, rc;

	svc = sys_connect();

	/* Add X, then add Y — additive union grows the isolated set. */
	ATF_REQUIRE(sysctl_oids_call(svc, SYS_OP_CLAIM, only_x, 1) == 0);
	ATF_REQUIRE(sysctl_oids_call(svc, SYS_OP_CLAIM, only_y, 1) == 0);

	/* Both are now isolated: foreign writes to X and Y are denied. */
	rc = run_foreign_sysctl_write(tc, SYSCTL_OID_X);
	ATF_CHECK_MSG(rc == 0, "X must be isolated after union (rc=%d)", rc);
	rc = run_foreign_sysctl_write(tc, SYSCTL_OID_Y);
	ATF_CHECK_MSG(rc == 0, "Y must be isolated after union (rc=%d)", rc);

	/* Subtract X — it becomes directly writable again; Y stays isolated. */
	ATF_REQUIRE(sysctl_oids_call(svc, SYS_OP_RELEASE, only_x, 1) == 0);
	rc = run_foreign_sysctl_write(tc, SYSCTL_OID_X);
	ATF_CHECK_MSG(rc == 1,
	    "X must be writable again after subtractive release (rc=%d)", rc);
	rc = run_foreign_sysctl_write(tc, SYSCTL_OID_Y);
	ATF_CHECK_MSG(rc == 0,
	    "Y must remain isolated after X is released (rc=%d)", rc);

	close(svc);
}

/*
 * Fail-closed parsing: a SYSCTL claim whose OID-set payload is malformed
 * (here, noids larger than the cap) is rejected with EINVAL and creates no
 * claim.  A well-formed single-OID claim then succeeds on the same fd.
 */
ATF_TC(sysctl_malformed_oidset_rejected);
ATF_TC_HEAD(sysctl_malformed_oidset_rejected, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a malformed SYSCTL OID-set payload is rejected with EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sysctl_malformed_oidset_rejected, tc)
{
	struct mac_capability_call_args ca;
	struct sys_request *req;
	struct sys_sysctl_oidset *oset;
	unsigned char buf[sizeof(struct sys_request) + sizeof(uint32_t)];
	int svc;

	svc = sys_connect();

	/* noids claims a value but no OID entries follow (length mismatch). */
	memset(buf, 0, sizeof(buf));
	req = (struct sys_request *)buf;
	req->op = SYS_OP_CLAIM;
	req->gates = SYS_GATE_SYSCTL;
	oset = (struct sys_sysctl_oidset *)(buf + sizeof(struct sys_request));
	oset->noids = SYS_SYSCTL_MAXOIDS + 1;	/* over cap */
	memset(&ca, 0, sizeof(ca));
	ca.req = buf;
	ca.req_len = sizeof(buf);
	ca.reply_len = 0;
	ATF_CHECK(ioctl(svc, MAC_CAPABILITY_CALL, &ca) == -1);
	ATF_CHECK_EQ(errno, EINVAL);

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
	ATF_TP_ADD_TC(tp, own_claim_not_shadowed_by_foreign);
	ATF_TP_ADD_TC(tp, unclaimed_foreign_nonce_denied);
	ATF_TP_ADD_TC(tp, claim_reverts_on_claimant_death);
	ATF_TP_ADD_TC(tp, sysctl_gate_scopes_writes_not_name_lookup);
	ATF_TP_ADD_TC(tp, auth_entries_globally_capped);
	ATF_TP_ADD_TC(tp, nonce_identity_fork_preserve_exec_rotate);
	ATF_TP_ADD_TC(tp, sysctl_isolation_scopes_to_listed_oid);
	ATF_TP_ADD_TC(tp, sysctl_coarse_claim_gates_all_oids);
	ATF_TP_ADD_TC(tp, sysctl_isolation_union_and_subtract);
	ATF_TP_ADD_TC(tp, sysctl_malformed_oidset_rejected);

	return (atf_no_error());
}
