/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * T0a pins (kernel-identity-and-coalitions.md, section 2.4): what the
 * capability plane's identities mean, asserted only through what a program
 * can observe, so the same cases pass on dev (the capability credential
 * nonce, p_cap_identity, p_cap_execution) and after T1 (cr_imageid,
 * p_uniqueid):
 *
 *  - an isolation claim and a System gate belong to the image that made
 *    them: a fork child shares them (also after a credential change without
 *    exec), a new execution does not, nor does any of a run of executions
 *    that follow one another (a predictable next value buys nothing);
 *  - a claim follows the acting credential, not the credential a
 *    descriptor was opened with;
 *  - an invocation binding admits the bound process only: not its fork
 *    child, not its next execution, and nobody but an issuer can make one;
 *  - the authority debug rule admits the holder's own execution only.
 *
 * Tiers (docs/book/src/develop/testing.md): the identity answers (QUERY,
 * CLAIM, RELEASE, AUTHORIZE, gated kenv) run in every tier; the access
 * answers need kern.mac_capability_isolation.enforce=1 (PLANE_OFF=1) and
 * skip elsewhere with DEFERRED_ENFORCED_TIER after the identity answers
 * have been checked; the binding and debug cases need a test issuer and
 * skip elsewhere with DEFERRED_STACK_TIER.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/kenv.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "channel.h"
#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_isolation_proto.h"
#include "mac_capability_system_proto.h"
#include "identity_semantics.h"

#define	HELPER_NAME	"identity_semantics_helper"
/* Executions in a row that must each be a stranger to the claim/gate. */
#define	SEQUENTIAL_EXECS	8

static char helper_path[MAXPATHLEN];
static char file_a[MAXPATHLEN], file_b[MAXPATHLEN];

/* ----------------------------------------------------------------
 * Harness
 * ---------------------------------------------------------------- */

static void
paths_init(const atf_tc_t *tc)
{
	char cwd[MAXPATHLEN];
	int fd;

	snprintf(helper_path, sizeof(helper_path), "%s/%s",
	    atf_tc_get_config_var(tc, "srcdir"), HELPER_NAME);
	ATF_REQUIRE_MSG(access(helper_path, X_OK) == 0, "%s: %s",
	    helper_path, strerror(errno));
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(file_a, sizeof(file_a), "%s/claimed.a", cwd);
	snprintf(file_b, sizeof(file_b), "%s/claimed.b", cwd);
	fd = open(file_a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0 && write(fd, "a", 1) == 1);
	close(fd);
	fd = open(file_b, O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0 && write(fd, "b", 1) == 1);
	close(fd);
}

/*
 * Run the helper (a new execution) with argv after its name, keeping
 * descriptor keep (or -1) open across the exec; return its exit status.
 */
static int
run_helper(int keep, ...)
{
	char *argv[8];
	va_list ap;
	pid_t pid;
	int argc, status;

	argc = 0;
	argv[argc++] = helper_path;
	va_start(ap, keep);
	while ((argv[argc] = va_arg(ap, char *)) != NULL) {
		argc++;
		ATF_REQUIRE(argc < (int)nitems(argv));
	}
	va_end(ap);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (keep >= 0 && fcntl(keep, F_SETFD, 0) != 0)
			_exit(HELPER_BROKEN);
		execv(helper_path, argv);
		_exit(HELPER_BROKEN);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status), "helper status %#x", status);
	ATF_REQUIRE_MSG(WEXITSTATUS(status) != HELPER_BROKEN,
	    "helper %s failed to run its command", argv[1]);
	return (WEXITSTATUS(status));
}

static const char *
fdstr(int fd)
{
	static char buf[4][16];
	static int next;
	char *s;

	s = buf[next++ % nitems(buf)];
	snprintf(s, sizeof(buf[0]), "%d", fd);
	return (s);
}

/* Fork; the child's exit status is fn()'s result. */
static int
in_child(int (*fn)(void *), void *arg)
{
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fn(arg));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status), "child status %#x", status);
	return (WEXITSTATUS(status));
}

static int
connect_service(const char *name)
{
	struct mac_capability_connect_args ca;
	int ctl;

	ctl = mac_capability_open();
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, name, sizeof(ca.name));
	ATF_REQUIRE_MSG(ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) == 0,
	    "connect %s: %s", name, strerror(errno));
	close(ctl);
	return (ca.fd);
}

/* An isolation call; 0 or errno; *flags gets QUERY's flags. */
static int
fi_op(int svc, uint32_t op, int target, uint64_t actions, uint32_t *flags,
    int *reply_fd)
{
	struct mac_capability_call_args ca;
	struct fi_request req;
	struct fi_reply rpl;

	memset(&req, 0, sizeof(req));
	req.op = op;
	req.actions = actions;
	memset(&rpl, 0, sizeof(rpl));
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (target >= 0) {
		ca.req_fds = &target;
		ca.req_nfds = 1;
	}
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	if (reply_fd != NULL) {
		*reply_fd = -1;
		ca.reply_fds = reply_fd;
		ca.reply_nfds = 1;
	}
	if (ioctl(svc, MAC_CAPABILITY_CALL, &ca) != 0)
		return (errno);
	if (flags != NULL)
		*flags = rpl.flags;
	return (0);
}

static uint32_t
fi_query(int svc, int target)
{
	uint32_t flags;

	ATF_REQUIRE_EQ(0, fi_op(svc, FI_OP_QUERY, target, FI_FS_ALL, &flags,
	    NULL));
	return (flags);
}

static int
sys_op(int fd, uint32_t op, uint32_t gates, int *reply_fd)
{
	struct mac_capability_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = op;
	req.gates = gates;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (reply_fd != NULL) {
		*reply_fd = -1;
		ca.reply_fds = reply_fd;
		ca.reply_nfds = 1;
	}
	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0 ? 0 : errno);
}

static int
kenv_set_errno(void)
{
	char value[] = "1";

	if (kenv(KENV_SET, IDS_KENV_PROBE, value, (int)sizeof(value)) == 0)
		return (0);
	return (errno);
}

static int
cap_op(int cmd, int fd, void *data)
{

	return (syscall(SYS_cap_process, cmd, fd, 0, data));
}

static bool
isolation_enforced(void)
{
	size_t len;
	int enforce;

	len = sizeof(enforce);
	ATF_REQUIRE_MSG(sysctlbyname("kern.mac_capability_isolation.enforce",
	    &enforce, &len, NULL, 0) == 0,
	    "kern.mac_capability_isolation.enforce: %s", strerror(errno));
	return (enforce != 0);
}

/* The test issuer of the stack tier, or a DEFERRED_STACK_TIER skip. */
static int
require_test_issuer(void)
{
	size_t len;
	int enabled, issuer;

	len = sizeof(enabled);
	if (sysctlbyname("kern.mac_capability.test_issuer", &enabled, &len,
	    NULL, 0) != 0 || enabled != 1 ||
	    (issuer = cap_op(CAP_AUTH_ISSUER_CREATE, -1, NULL)) < 0)
		atf_tc_skip("DEFERRED_STACK_TIER: no test issuer: needs "
		    "GENERIC-TEST with kern.mac_capability.test_issuer=1, boot "
		    "not anchored (vm-provider.sh STACK_TIER=1)");
	return (issuer);
}

/* A managed authority from issuer, unconstrained: it survives exec. */
static int
managed_token(int issuer)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	int token;

	token = cap_op(CAP_AUTH_ISSUE, issuer, &spec);
	ATF_REQUIRE_MSG(token >= 0, "issue: %s", strerror(errno));
	return (token);
}

static void
write_full(int fd, const void *buf, size_t len)
{
	ATF_REQUIRE_EQ((ssize_t)len, write(fd, buf, len));
}

static void
read_full(int fd, void *buf, size_t len)
{
	ATF_REQUIRE_EQ_MSG((ssize_t)len, read(fd, buf, len),
	    "short read of %zu bytes", len);
}

/* ----------------------------------------------------------------
 * Isolation claims (V1)
 * ---------------------------------------------------------------- */

struct fork_claim_arg {
	int	svc;		/* the parent's instance, inherited */
	int	target_a;
	int	target_b;
};

/*
 * In a fork child: the parent's claim on a is the child's own, also after a
 * credential change without exec; a claim the child makes on b through the
 * parent's instance is the family's.
 */
static int
fork_claim_child(void *argp)
{
	struct fork_claim_arg *arg = argp;
	uint32_t flags;
	int svc;

	svc = connect_service("isolation");
	if (fi_op(svc, FI_OP_QUERY, arg->target_a, FI_FS_ALL, &flags,
	    NULL) != 0 || flags != (FI_QF_CLAIMED | FI_QF_MINE))
		return (1);
	if (setuid(getuid()) != 0)
		return (2);
	if (fi_op(svc, FI_OP_QUERY, arg->target_a, FI_FS_ALL, &flags,
	    NULL) != 0 || flags != (FI_QF_CLAIMED | FI_QF_MINE))
		return (3);
	if (fi_op(arg->svc, FI_OP_CLAIM, arg->target_b, 0, NULL, NULL) != 0)
		return (4);
	return (0);
}

static int
open_child(void *arg)
{
	int fd;

	fd = open(arg, O_RDONLY);
	if (fd < 0)
		return (errno);
	close(fd);
	return (0);
}

ATF_TC_WITH_CLEANUP(isolation_fork_shares_claim);
ATF_TC_HEAD(isolation_fork_shares_claim, tc)
{
	atf_tc_set_md_var(tc, "descr", "A fork child shares its parent's "
	    "isolation claims, also after a credential change without exec, "
	    "and a claim it makes belongs to the parent too; with the policy "
	    "enforcing it opens the claimed file and a new execution cannot");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(isolation_fork_shares_claim, tc)
{
	struct fork_claim_arg arg;
	int svc, a, b;

	paths_init(tc);
	svc = connect_service("isolation");
	a = open(file_a, O_RDONLY);
	b = open(file_b, O_RDONLY);
	ATF_REQUIRE(a >= 0 && b >= 0);
	ATF_REQUIRE_EQ(0, fi_op(svc, FI_OP_CLAIM, a, 0, NULL, NULL));

	arg.svc = svc;
	arg.target_a = a;
	arg.target_b = b;
	ATF_CHECK_EQ_MSG(0, in_child(fork_claim_child, &arg),
	    "fork child: see fork_claim_child() for the failed step");
	/* The child's claim on b is the parent's: QUERY and RELEASE agree. */
	ATF_CHECK_EQ(FI_QF_CLAIMED | FI_QF_MINE, fi_query(svc, b));
	ATF_CHECK_EQ(0, fi_op(svc, FI_OP_RELEASE, b, 0, NULL, NULL));

	/* What the claim refuses, only an enforcing policy shows. */
	require_isolation_enforced();
	ATF_CHECK_EQ(0, in_child(open_child, file_a));
	ATF_CHECK_EQ(EACCES, run_helper(-1, "open", file_a, NULL));
	close(a);
	close(b);
	close(svc);
}
ATF_TC_CLEANUP(isolation_fork_shares_claim, tc)
{
}

static int
failed_exec_child(void *arg)
{
	struct fork_claim_arg *a = arg;
	char *argv[] = { file_b, NULL };
	char *envp[] = { NULL };
	uint32_t flags;
	int svc;

	/* The kernel refuses this image: nothing about the process changes. */
	if (syscall(SYS_execve, file_b, argv, envp) != -1 || errno != ENOEXEC)
		return (1);
	svc = connect_service("isolation");
	if (fi_op(svc, FI_OP_QUERY, a->target_a, FI_FS_ALL, &flags, NULL) != 0)
		return (2);
	return (flags == (FI_QF_CLAIMED | FI_QF_MINE) ? 0 : 3);
}

ATF_TC_WITH_CLEANUP(isolation_exec_loses_claim);
ATF_TC_HEAD(isolation_exec_loses_claim, tc)
{
	atf_tc_set_md_var(tc, "descr", "A new execution is a stranger to "
	    "the claim its process made before exec (QUERY not ours, RELEASE "
	    "EACCES, CLAIM EBUSY), and so is each of a run of executions in "
	    "a row; a refused execve (ENOEXEC) changes nothing");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(isolation_exec_loses_claim, tc)
{
	struct fork_claim_arg arg;
	int svc, a, b, i;

	paths_init(tc);
	/* An executable file the kernel cannot activate. */
	b = open(file_b, O_WRONLY | O_TRUNC);
	ATF_REQUIRE(b >= 0 && write(b, "not an image\n", 13) == 13);
	close(b);
	ATF_REQUIRE_EQ(0, chmod(file_b, 0755));

	svc = connect_service("isolation");
	a = open(file_a, O_RDONLY);
	ATF_REQUIRE(a >= 0);
	ATF_REQUIRE_EQ(0, fi_op(svc, FI_OP_CLAIM, a, 0, NULL, NULL));

	arg.target_a = a;
	ATF_CHECK_EQ_MSG(0, in_child(failed_exec_child, &arg),
	    "a refused execve changed the claim's answer");

	/* Each execution in turn: claimed, not ours, not releasable. */
	for (i = 0; i < SEQUENTIAL_EXECS; i++) {
		ATF_CHECK_EQ(FI_QF_CLAIMED, run_helper(a, "iso-query",
		    fdstr(a), NULL));
		ATF_CHECK_EQ(EACCES, run_helper(a, "iso-release", fdstr(a),
		    NULL));
		ATF_CHECK_EQ(EBUSY, run_helper(a, "iso-claim", fdstr(a),
		    NULL));
	}
	/* None of them took it away from its owner. */
	ATF_CHECK_EQ(FI_QF_CLAIMED | FI_QF_MINE, fi_query(svc, a));

	require_isolation_enforced();
	ATF_CHECK_EQ(EACCES, run_helper(-1, "open", file_a, NULL));
	ATF_CHECK_EQ(EACCES, run_helper(a, "pread", fdstr(a), NULL));
	close(a);
	close(svc);
}
ATF_TC_CLEANUP(isolation_exec_loses_claim, tc)
{
}

static int
recv_fd(int sock)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} control;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	char byte;
	int fd;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);
	ATF_REQUIRE_EQ(1, recvmsg(sock, &msg, 0));
	cmsg = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cmsg != NULL && cmsg->cmsg_type == SCM_RIGHTS);
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return (fd);
}

static int
owner_ask(int sock, char cmd)
{
	int answer;

	write_full(sock, &cmd, 1);
	read_full(sock, &answer, sizeof(answer));
	return (answer);
}

ATF_TC_WITH_CLEANUP(isolation_file_cred_owner);
ATF_TC_HEAD(isolation_file_cred_owner, tc)
{
	atf_tc_set_md_var(tc, "descr", "A claim made through a descriptor "
	    "that another execution opened belongs to the caller, not to the "
	    "credential the descriptor was opened with: the caller's answers "
	    "through it are the owner's, the opener's through its own "
	    "descriptor are a stranger's");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(isolation_file_cred_owner, tc)
{
	char byte;
	int fd, sv[2], svc, status;
	pid_t pid;

	paths_init(tc);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(sv[0]);
		execl(helper_path, helper_path, "file-owner", fdstr(sv[1]),
		    file_a, (char *)NULL);
		_exit(HELPER_BROKEN);
	}
	close(sv[1]);
	/* The descriptor's credential is the helper's execution. */
	fd = recv_fd(sv[0]);
	svc = connect_service("isolation");
	ATF_REQUIRE_EQ(0, fi_op(svc, FI_OP_CLAIM, fd, 0, NULL, NULL));
	ATF_CHECK_EQ(FI_QF_CLAIMED | FI_QF_MINE, fi_query(svc, fd));
	ATF_CHECK_EQ((int)FI_QF_CLAIMED, owner_ask(sv[0], 'q'));
	ATF_CHECK_EQ(EACCES, run_helper(fd, "iso-release", fdstr(fd), NULL));

	if (isolation_enforced()) {
		/* The acting credential decides, both ways. */
		ATF_CHECK_EQ(1, pread(fd, &byte, 1, 0));
		ATF_CHECK_EQ(EACCES, owner_ask(sv[0], 'r'));
	}
	byte = 'x';
	write_full(sv[0], &byte, 1);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(0, fi_op(svc, FI_OP_RELEASE, fd, 0, NULL, NULL));
	close(fd);
	close(svc);
	close(sv[0]);
	/* Without enforcement the access half did not run: not a pass. */
	require_isolation_enforced();
}
ATF_TC_CLEANUP(isolation_file_cred_owner, tc)
{
}

/* ----------------------------------------------------------------
 * System gates (V1)
 * ---------------------------------------------------------------- */

static int
kenv_child(void *arg __unused)
{

	return (kenv_set_errno());
}

ATF_TC_WITH_CLEANUP(system_gate_fork_shares);
ATF_TC_HEAD(system_gate_fork_shares, tc)
{
	atf_tc_set_md_var(tc, "descr", "A fork child of a gate's owner "
	    "passes the gate; a new execution, and each of a run of them, is "
	    "refused EPERM");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(system_gate_fork_shares, tc)
{
	int i, svc;

	paths_init(tc);
	svc = connect_service("system");
	ATF_REQUIRE_EQ(0, sys_op(svc, SYS_OP_CLAIM, SYS_GATE_KENV, NULL));
	ATF_CHECK_EQ(0, in_child(kenv_child, NULL));
	for (i = 0; i < SEQUENTIAL_EXECS; i++)
		ATF_CHECK_EQ(EPERM, run_helper(-1, "kenv-set", NULL));
	ATF_CHECK_EQ(0, sys_op(svc, SYS_OP_RELEASE, SYS_GATE_KENV, NULL));
	close(svc);
}
ATF_TC_CLEANUP(system_gate_fork_shares, tc)
{
	(void)kenv(KENV_UNSET, IDS_KENV_PROBE, NULL, 0);
}

ATF_TC_WITH_CLEANUP(system_gate_exec_drops);
ATF_TC_HEAD(system_gate_exec_drops, tc)
{
	atf_tc_set_md_var(tc, "descr", "An execution authorized on a gate "
	    "token passes the gate, and so does its fork child; its next "
	    "execution is refused EPERM");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(system_gate_exec_drops, tc)
{
	int svc, token;

	paths_init(tc);
	svc = connect_service("system");
	ATF_REQUIRE_EQ(0, sys_op(svc, SYS_OP_CLAIM, SYS_GATE_KENV, NULL));
	ATF_REQUIRE_EQ(0, sys_op(svc, SYS_OP_MINT, SYS_GATE_KENV, &token));
	ATF_REQUIRE(token >= 0);
	/* Unauthorized, the helper is refused: the token is what admits it. */
	ATF_CHECK_EQ(EPERM, run_helper(-1, "kenv-set", NULL));
	ATF_CHECK_EQ(EPERM, run_helper(token, "sys-authorize-exec",
	    fdstr(token), NULL));
	close(token);
	ATF_CHECK_EQ(0, sys_op(svc, SYS_OP_RELEASE, SYS_GATE_KENV, NULL));
	close(svc);
}
ATF_TC_CLEANUP(system_gate_exec_drops, tc)
{
	(void)kenv(KENV_UNSET, IDS_KENV_PROBE, NULL, 0);
}

/* ----------------------------------------------------------------
 * Invocation bindings (V1 + V2)
 * ---------------------------------------------------------------- */

enum bind_mode { BIND_SAME, BIND_FORK, BIND_EXEC, BIND_GUESS };

struct bind_values {
	uint64_t	identity;
	uint64_t	nonce;
};

/* The bound process: install, announce itself, then act per mode. */
static int
bind_child(enum bind_mode mode, int authority, int token, int spare,
    int announce, int gate, int result)
{
	struct mac_capability_sendmsg_args tx;
	struct cap_authority_bind_invocation inv;
	struct bind_values v;
	int answer[2], status;
	pid_t pid;
	char byte = 'r';

	if (cap_op(CAP_AUTH_INSTALL, authority, NULL) != 0)
		return (HELPER_BROKEN);
	memset(&tx, 0, sizeof(tx));
	tx.payload = &byte;
	tx.payload_len = sizeof(byte);
	if (ioctl(announce, MAC_CAPABILITY_SENDMSG, &tx) != 0)
		return (HELPER_BROKEN);
	if (read(gate, &v, sizeof(v)) != sizeof(v))
		return (HELPER_BROKEN);
	switch (mode) {
	case BIND_SAME:
		return (fi_op(token, FI_OP_AUTHORIZE, -1, 0, NULL, NULL));
	case BIND_FORK:
		pid = fork();
		if (pid < 0)
			return (HELPER_BROKEN);
		if (pid == 0)
			_exit(fi_op(token, FI_OP_AUTHORIZE, -1, 0, NULL, NULL));
		if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
			return (HELPER_BROKEN);
		/* The child's refusal leaves the bound process admitted. */
		if (fi_op(token, FI_OP_AUTHORIZE, -1, 0, NULL, NULL) != 0)
			return (IDS_EXIT_AUTH_STEP);
		return (WEXITSTATUS(status));
	case BIND_EXEC:
		if (fcntl(token, F_SETFD, 0) != 0)
			return (HELPER_BROKEN);
		execl(helper_path, helper_path, "iso-authorize", fdstr(token),
		    (char *)NULL);
		return (HELPER_BROKEN);
	case BIND_GUESS:
		/*
		 * Knowing its own exact values, a process that is not an
		 * issuer cannot bind: not with its authority, not with a
		 * capability, as the issuer descriptor.
		 */
		memset(&inv, 0, sizeof(inv));
		inv.token_fd = authority;
		inv.capability_fd = spare;
		inv.process_identity = v.identity;
		inv.execution_nonce = v.nonce;
		answer[0] = cap_op(CAP_AUTH_BIND_INVOCATION, authority,
		    &inv) == 0 ? 0 : errno;
		answer[1] = cap_op(CAP_AUTH_BIND_INVOCATION, spare,
		    &inv) == 0 ? 0 : errno;
		if (write(result, answer, sizeof(answer)) != sizeof(answer))
			return (HELPER_BROKEN);
		/* The spare capability is still unbound, so still usable. */
		return (0);
	}
	return (HELPER_BROKEN);
}

/*
 * Issue a managed authority, claim file a and mint an isolation token for
 * it, start the bound process in mode, observe it on a channel and bind
 * the token to what the kernel stamped; return the bound process's exit
 * status (its result).
 */
static int
bind_case(const atf_tc_t *tc, enum bind_mode mode, int *guess)
{
	struct mac_capability_recvmsg_v3_args rx;
	struct cap_authority_bind_invocation inv;
	struct bind_values v;
	int authority, ch[2], gate[2], issuer, res[2], spare, svc, target;
	int token, status;
	pid_t pid;
	char byte;

	paths_init(tc);
	issuer = require_test_issuer();
	authority = managed_token(issuer);
	svc = connect_service("isolation");
	target = open(file_a, O_RDONLY);
	ATF_REQUIRE(target >= 0);
	ATF_REQUIRE_EQ(0, fi_op(svc, FI_OP_CLAIM, target, 0, NULL, NULL));
	ATF_REQUIRE_EQ(0, fi_op(svc, FI_OP_MINT, target, FI_FS_READ, NULL,
	    &token));
	ATF_REQUIRE_EQ(0, fi_op(svc, FI_OP_MINT, target, FI_FS_READ, NULL,
	    &spare));
	ATF_REQUIRE(token >= 0 && spare >= 0);
	ATF_REQUIRE_EQ_MSG(0, mac_capability_channel_create(ch),
	    "channel: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, pipe(gate));
	ATF_REQUIRE_EQ(0, pipe(res));

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ch[1]);
		close(gate[1]);
		close(res[0]);
		close(issuer);
		_exit(bind_child(mode, authority, token, spare, ch[0],
		    gate[0], res[1]));
	}
	close(ch[0]);
	close(gate[0]);
	close(res[1]);

	/* The kernel's stamp of the sender, as an issuer receives it. */
	memset(&rx, 0, sizeof(rx));
	rx.message.payload = &byte;
	rx.message.payload_len = sizeof(byte);
	rx.message.flags = MAC_CAPABILITY_RECV_F_WAIT;
	rx.message._reserved[0] = MAC_CAPABILITY_RECV_WAIT_FOREVER;
	ATF_REQUIRE_MSG(ioctl(ch[1], MAC_CAPABILITY_RECVMSG_V3, &rx) == 0,
	    "receive: %s", strerror(errno));
	ATF_REQUIRE_EQ(pid, rx.process.pid);
	v.identity = rx.process.identity;
	v.nonce = rx.message.trailer.nonce;
	ATF_REQUIRE(v.identity != 0 && v.nonce != 0);

	memset(&inv, 0, sizeof(inv));
	inv.token_fd = authority;
	inv.capability_fd = token;
	/* Zero values name no process (the zero guards). */
	inv.process_identity = v.identity;
	inv.execution_nonce = 0;
	ATF_CHECK_ERRNO(EINVAL, cap_op(CAP_AUTH_BIND_INVOCATION, issuer,
	    &inv) == -1);
	inv.process_identity = 0;
	inv.execution_nonce = v.nonce;
	ATF_CHECK_ERRNO(EINVAL, cap_op(CAP_AUTH_BIND_INVOCATION, issuer,
	    &inv) == -1);
	inv.process_identity = v.identity;
	ATF_REQUIRE_MSG(cap_op(CAP_AUTH_BIND_INVOCATION, issuer, &inv) == 0,
	    "bind: %s", strerror(errno));

	write_full(gate[1], &v, sizeof(v));
	if (mode == BIND_GUESS)
		read_full(res[0], guess, 2 * sizeof(*guess));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status), "bound process status %#x",
	    status);
	ATF_REQUIRE_MSG(WEXITSTATUS(status) != HELPER_BROKEN,
	    "bound process harness failed");

	ATF_CHECK_EQ(0, fi_op(svc, FI_OP_RELEASE, target, 0, NULL, NULL));
	close(gate[1]);
	close(res[0]);
	close(ch[1]);
	close(spare);
	close(token);
	close(target);
	close(svc);
	close(authority);
	close(issuer);
	return (WEXITSTATUS(status));
}

ATF_TC(binding_same_process_allowed);
ATF_TC_HEAD(binding_same_process_allowed, tc)
{
	atf_tc_set_md_var(tc, "descr", "A capability bound to an observed "
	    "invocation admits that process; a binding naming a zero "
	    "identity or execution is refused EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(binding_same_process_allowed, tc)
{

	ATF_CHECK_EQ(0, bind_case(tc, BIND_SAME, NULL));
}

ATF_TC(binding_fork_child_refused);
ATF_TC_HEAD(binding_fork_child_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "A fork child of the bound process "
	    "is refused the bound capability (EPERM) and its refusal leaves "
	    "the bound process admitted");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(binding_fork_child_refused, tc)
{
	int r;

	r = bind_case(tc, BIND_FORK, NULL);
	ATF_CHECK_MSG(r != IDS_EXIT_AUTH_STEP,
	    "the bound process lost its admission to its child's attempt");
	ATF_CHECK_EQ(EPERM, r);
}

ATF_TC(binding_exec_refused);
ATF_TC_HEAD(binding_exec_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "The next execution of the bound "
	    "process, same pid and authority, is refused the bound capability "
	    "(EPERM)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(binding_exec_refused, tc)
{

	ATF_CHECK_EQ(EPERM, bind_case(tc, BIND_EXEC, NULL));
}

ATF_TC(guess_binding_needs_issuer);
ATF_TC_HEAD(guess_binding_needs_issuer, tc)
{
	atf_tc_set_md_var(tc, "descr", "A process that knows its own exact "
	    "identity values cannot make a binding with them: only an issuer "
	    "descriptor binds (EINVAL for an authority or a capability)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(guess_binding_needs_issuer, tc)
{
	int guess[2];

	ATF_CHECK_EQ(0, bind_case(tc, BIND_GUESS, guess));
	ATF_CHECK_EQ(EINVAL, guess[0]);
	ATF_CHECK_EQ(EINVAL, guess[1]);
}

/* ----------------------------------------------------------------
 * Authority debug family (V3)
 * ---------------------------------------------------------------- */

/* PT_ATTACH pid, wait for its stop, detach; 0 or the attach errno. */
static int
attach_detach(pid_t pid)
{
	int status;

	if (ptrace(PT_ATTACH, pid, NULL, 0) != 0)
		return (errno);
	if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status))
		return (HELPER_BROKEN);
	if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) != 0)
		return (HELPER_BROKEN);
	return (0);
}

/* Read fd until end of file; a debugger's stop may interrupt a read. */
static void
drain(int fd)
{
	char byte;
	ssize_t n;

	for (;;) {
		n = read(fd, &byte, 1);
		if (n == 1 || (n == -1 && errno == EINTR))
			continue;
		return;
	}
}

/*
 * A process that waits until fd reaches end of file.  It keeps only fd
 * (moved to WAITER_FD) and the standard descriptors: an inherited write end
 * of its own pipe, or of another process's command pipe, would keep that
 * end of file from ever coming.
 */
#define	WAITER_FD	(STDERR_FILENO + 1)
static pid_t
waiter(int fd)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		if (fd != WAITER_FD && dup2(fd, WAITER_FD) != WAITER_FD)
			_exit(HELPER_BROKEN);
		closefrom(WAITER_FD + 1);
		drain(WAITER_FD);
		_exit(0);
	}
	return (pid);
}

/* In a fork of the caller: attach_detach(target); its result. */
static int
attach_from_fork(pid_t target)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return (HELPER_BROKEN);
	if (pid == 0)
		_exit(attach_detach(target));
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (HELPER_BROKEN);
	return (WEXITSTATUS(status));
}

/* What the holder process reports to the test. */
struct debug_report {
	int	install;	/* CAP_AUTH_INSTALL errno */
	int	r[4];		/* per-case answers */
};

/*
 * Start the holder: a fork of the test that runs fn(token, report) and
 * sends the report; while it waits on *release the test may act on it.
 */
static pid_t
start_holder(void (*fn)(int, struct debug_report *, int), int token,
    struct debug_report *report, int *release)
{
	int rep[2], go[2];
	pid_t pid;

	ATF_REQUIRE_EQ(0, pipe(rep));
	ATF_REQUIRE_EQ(0, pipe(go));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct debug_report r;

		close(rep[0]);
		close(go[1]);
		memset(&r, 0, sizeof(r));
		fn(token, &r, go[0]);
		if (write(rep[1], &r, sizeof(r)) != sizeof(r))
			_exit(HELPER_BROKEN);
		drain(go[0]);
		_exit(0);
	}
	close(rep[1]);
	close(go[0]);
	read_full(rep[0], report, sizeof(*report));
	close(rep[0]);
	*release = go[1];
	return (pid);
}

static void
stop_holder(pid_t pid, int release)
{
	int status;

	close(release);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "holder status %#x", status);
}

static void
same_image_holder(int token, struct debug_report *r, int go __unused)
{
	int tgt[2];
	pid_t c;

	r->install = cap_op(CAP_AUTH_INSTALL, token, NULL) == 0 ? 0 : errno;
	if (pipe(tgt) != 0)
		_exit(HELPER_BROKEN);
	c = waiter(tgt[0]);
	/* Two fork children of the holder: one family. */
	r->r[0] = attach_from_fork(c);
	/* The holder itself and its child. */
	r->r[1] = attach_detach(c);
	close(tgt[1]);
	(void)waitpid(c, NULL, 0);
}

ATF_TC(debug_family_same_image);
ATF_TC_HEAD(debug_family_same_image, tc)
{
	atf_tc_set_md_var(tc, "descr", "Processes of one execution holding "
	    "one managed authority may debug each other; a process without "
	    "it is refused the holder (EPERM)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_family_same_image, tc)
{
	struct debug_report r;
	int issuer, release, token;
	pid_t holder;

	paths_init(tc);
	issuer = require_test_issuer();
	token = managed_token(issuer);
	holder = start_holder(same_image_holder, token, &r, &release);
	ATF_REQUIRE_EQ_MSG(0, r.install, "install: %s", strerror(r.install));
	ATF_CHECK_EQ(0, r.r[0]);
	ATF_CHECK_EQ(0, r.r[1]);
	/* The test holds no authority: Unix would allow root, the rule not. */
	ATF_CHECK_EQ(EPERM, attach_from_fork(holder));
	stop_holder(holder, release);
	close(token);
	close(issuer);
}

static void
after_exec_holder(int token, struct debug_report *r, int go __unused)
{
	struct kevent ev;
	int kq, start[2], tgt[2];
	pid_t c;
	char byte;

	r->install = cap_op(CAP_AUTH_INSTALL, token, NULL) == 0 ? 0 : errno;
	if (pipe(tgt) != 0 || pipe(start) != 0 || (kq = kqueue()) < 0)
		_exit(HELPER_BROKEN);
	c = fork();
	if (c < 0)
		_exit(HELPER_BROKEN);
	if (c == 0) {
		close(tgt[1]);
		close(start[1]);
		if (read(start[0], &byte, 1) != 1)
			_exit(HELPER_BROKEN);
		if (fcntl(tgt[0], F_SETFD, 0) != 0)
			_exit(HELPER_BROKEN);
		execl(helper_path, helper_path, "wait-fd", fdstr(tgt[0]),
		    (char *)NULL);
		_exit(HELPER_BROKEN);
	}
	close(start[0]);
	/* Control: before its exec the child is of the holder's family. */
	r->r[0] = attach_from_fork(c);
	EV_SET(&ev, c, EVFILT_PROC, EV_ADD, NOTE_EXEC, 0, NULL);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) != 0)
		_exit(HELPER_BROKEN);
	if (write(start[1], "x", 1) != 1)
		_exit(HELPER_BROKEN);
	/* Wait for the exec itself, not for time. */
	if (kevent(kq, NULL, 0, &ev, 1, NULL) != 1 ||
	    (ev.fflags & NOTE_EXEC) == 0)
		_exit(HELPER_BROKEN);
	/* Same authority (managed survives exec), another execution. */
	r->r[1] = attach_from_fork(c);
	r->r[2] = attach_detach(c);
	close(tgt[1]);
	(void)waitpid(c, NULL, 0);
	close(kq);
}

ATF_TC(debug_family_after_exec);
ATF_TC_HEAD(debug_family_after_exec, tc)
{
	atf_tc_set_md_var(tc, "descr", "Once a holder's child executes a new "
	    "image it keeps the managed authority but leaves the family: the "
	    "holder and its other children are refused it (EPERM)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_family_after_exec, tc)
{
	struct debug_report r;
	int issuer, release, token;
	pid_t holder;

	paths_init(tc);
	issuer = require_test_issuer();
	token = managed_token(issuer);
	holder = start_holder(after_exec_holder, token, &r, &release);
	ATF_REQUIRE_EQ_MSG(0, r.install, "install: %s", strerror(r.install));
	ATF_CHECK_EQ_MSG(0, r.r[0], "before exec: %d", r.r[0]);
	ATF_CHECK_EQ_MSG(EPERM, r.r[1], "sibling after exec: %d", r.r[1]);
	ATF_CHECK_EQ_MSG(EPERM, r.r[2], "holder after exec: %d", r.r[2]);
	stop_holder(holder, release);
	close(token);
	close(issuer);
}

/*
 * The pre-install child B takes attach requests on cmd and answers on res:
 * it holds no authority, the holder does after B was forked.
 */
static void
install_after_fork_holder(int token, struct debug_report *r, int go __unused)
{
	int cmd[2], res[2], tgt[2], answer;
	pid_t b, c, target;

	if (pipe(cmd) != 0 || pipe(res) != 0 || pipe(tgt) != 0)
		_exit(HELPER_BROKEN);
	b = fork();
	if (b < 0)
		_exit(HELPER_BROKEN);
	if (b == 0) {
		close(cmd[1]);
		close(res[0]);
		close(tgt[1]);
		while (read(cmd[0], &target, sizeof(target)) ==
		    sizeof(target)) {
			answer = attach_detach(target);
			if (write(res[1], &answer, sizeof(answer)) !=
			    sizeof(answer))
				_exit(HELPER_BROKEN);
		}
		_exit(0);
	}
	close(cmd[0]);
	close(res[1]);
	r->install = cap_op(CAP_AUTH_INSTALL, token, NULL) == 0 ? 0 : errno;
	c = waiter(tgt[0]);
#define	B_ATTACH(pid, slot) do {					\
	target = (pid);							\
	if (write(cmd[1], &target, sizeof(target)) != sizeof(target) ||\
	    read(res[0], &r->r[slot], sizeof(int)) != sizeof(int))	\
		_exit(HELPER_BROKEN);					\
} while (0)
	/* B, forked before the install, is outside the family. */
	B_ATTACH(getpid(), 0);
	B_ATTACH(c, 1);
#undef	B_ATTACH
	/* C, forked after it, is in it. */
	r->r[2] = attach_from_fork(c);
	/* B holds no authority: the holder debugs it by the Unix rules. */
	r->r[3] = attach_detach(b);
	close(cmd[1]);
	close(tgt[1]);
	(void)waitpid(b, NULL, 0);
	(void)waitpid(c, NULL, 0);
}

ATF_TC(debug_family_install_after_fork);
ATF_TC_HEAD(debug_family_install_after_fork, tc)
{
	atf_tc_set_md_var(tc, "descr", "A child forked before its parent "
	    "installs an authority is refused the parent and the parent's "
	    "later children (EPERM); a child forked after the install is in "
	    "the family; the holder may debug the earlier child");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(debug_family_install_after_fork, tc)
{
	struct debug_report r;
	int issuer, release, token;
	pid_t holder;

	paths_init(tc);
	issuer = require_test_issuer();
	token = managed_token(issuer);
	holder = start_holder(install_after_fork_holder, token, &r,
	    &release);
	ATF_REQUIRE_EQ_MSG(0, r.install, "install: %s", strerror(r.install));
	ATF_CHECK_EQ_MSG(EPERM, r.r[0], "earlier child -> holder: %d", r.r[0]);
	ATF_CHECK_EQ_MSG(EPERM, r.r[1], "earlier child -> later: %d", r.r[1]);
	ATF_CHECK_EQ_MSG(0, r.r[2], "later sibling -> later: %d", r.r[2]);
	ATF_CHECK_EQ_MSG(0, r.r[3], "holder -> earlier child: %d", r.r[3]);
	stop_holder(holder, release);
	close(token);
	close(issuer);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, isolation_fork_shares_claim);
	ATF_TP_ADD_TC(tp, isolation_exec_loses_claim);
	ATF_TP_ADD_TC(tp, isolation_file_cred_owner);
	ATF_TP_ADD_TC(tp, system_gate_fork_shares);
	ATF_TP_ADD_TC(tp, system_gate_exec_drops);
	ATF_TP_ADD_TC(tp, binding_same_process_allowed);
	ATF_TP_ADD_TC(tp, binding_fork_child_refused);
	ATF_TP_ADD_TC(tp, binding_exec_refused);
	ATF_TP_ADD_TC(tp, guess_binding_needs_issuer);
	ATF_TP_ADD_TC(tp, debug_family_same_image);
	ATF_TP_ADD_TC(tp, debug_family_after_exec);
	ATF_TP_ADD_TC(tp, debug_family_install_after_fork);

	return (atf_no_error());
}
