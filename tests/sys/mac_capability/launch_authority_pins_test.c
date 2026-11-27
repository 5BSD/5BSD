/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * LA0 (launch-authority-reshape.md rev 1.2, section 3): pins on dev of what
 * the authority objects do today, so that the reshape (LA1-LA3) can prove
 * it kept every property it means to keep, and deletes only what the design
 * deletes.  Every case passes on dev; each row is marked with the slice
 * that owns its future:
 *
 *   kept by LA1                the property survives the reshape unchanged
 *   rewritten by LA1 (1.7)     the mint shape or a refusal changes in LA1
 *   deleted by LA2             image-less grants go with the wire identity
 *   deleted by LA1 (lease)     the lease goes with no replacement
 *   rewritten by LA2 (stamp)   identity on the wire becomes the audit token
 *   rewritten by LA3 (binding) bindings become channel properties
 *
 * The cases need a test issuer (cap_process(2) CAP_AUTH_ISSUER_CREATE off
 * PID 1): the stack tier, GENERIC-TEST booted with
 * kern.mac_capability.test_issuer=1 (vm-provider.sh STACK_TIER=1
 * KERNEL_TIER=test PLANE_OFF=1).  Elsewhere they skip as
 * DEFERRED_STACK_TIER; on the stack tier itself an issuer that cannot be
 * created is a failure.  The SwitchBoard-level pins of the same design
 * rows (a unit's lookups, the end it is handed) are
 * usr.sbin/switchboard/tests/launch_authority_stack_test and
 * subset_stack_test; the Core role's effect is cap_exclusion_test.  The
 * other kernel consumer of the grant, the pinned-image predicate
 * cap_authority_runs_pinned_image() read by the mac_ntpd clock delegation
 * (mac_capability_system.c sys_clock_delegated()), is pinned with the
 * mac_ntpd tests, not here (design section 6.3).
 *
 * Waits are on events only: a child's exit, a pipe's end of file, a
 * message on a channel (MAC_CAPABILITY_RECV_F_WAIT), or the kernel's own
 * lease revocation waking a blocked receive.  The images the grants pin are
 * copies of launch_authority_helper in the work directory, which must not
 * be on a nosuid mount: exec selects no authority there (kept behaviour,
 * design section 6.6), so the pins check the mount first.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/procctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "channel.h"
#include "mac_capability_ioctl.h"
#include "launch_authority.h"

#define	HELPER		"launch_authority_helper"
#define	PINNED_IMAGE	"pinned-image"
#define	OTHER_IMAGE	"other-image"

#define	ERRNO_OF(rv)	((rv) == -1 ? errno : 0)

/*
 * A pinned answer.  The message names the row, so a run of these pins on a
 * later kernel lists every changed answer.
 */
#define	ROW(what, got, want) do {					\
	int got_ = (int)(got), want_ = (int)(want);			\
	ATF_CHECK_EQ_MSG(want_, got_, "%s: got %d (%s), pinned %d (%s)",	\
	    (what), got_, got_ > 0 ? strerror(got_) : "-", want_,	\
	    want_ > 0 ? strerror(want_) : "-");				\
} while (0)

static int
op(int cmd, int fd, void *data)
{

	return (syscall(SYS_cap_process, cmd, fd, 0, data));
}

/*
 * The issuer a case may use.  Off the stack tier a DEFERRED_STACK_TIER
 * skip; on it (kyua config stack_tier=1, as the capd harness reads it) an
 * issuer that cannot be created fails the case.
 */
static int
require_issuer(const atf_tc_t *tc)
{
	size_t len;
	int enabled, fd;
	bool stack_tier;

	stack_tier = strcmp(atf_tc_get_config_var_wd(tc, "stack_tier", "0"),
	    "1") == 0;
	len = sizeof(enabled);
	if (sysctlbyname("kern.mac_capability.test_issuer", &enabled, &len,
	    NULL, 0) != 0 || enabled != 1) {
		if (stack_tier)
			atf_tc_fail("the stack tier has no test issuer switch "
			    "(kern.mac_capability.test_issuer=1)");
		atf_tc_skip("DEFERRED_STACK_TIER: no test issuer: needs "
		    "GENERIC-TEST with kern.mac_capability.test_issuer=1, boot "
		    "not anchored (vm-provider.sh STACK_TIER=1 KERNEL_TIER=test "
		    "PLANE_OFF=1)");
	}
	fd = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	if (fd == -1) {
		if (stack_tier)
			atf_tc_fail("the stack tier has no test issuer: "
			    "CAP_AUTH_ISSUER_CREATE: %s", strerror(errno));
		atf_tc_skip("DEFERRED_STACK_TIER: no test issuer: "
		    "CAP_AUTH_ISSUER_CREATE: %s (boot anchored?)",
		    strerror(errno));
	}
	return (fd);
}

static int
managed_token(int issuer)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	int token;

	token = op(CAP_AUTH_ISSUE, issuer, &spec);
	ATF_REQUIRE_MSG(token >= 0, "CAP_AUTH_ISSUE: %s", strerror(errno));
	return (token);
}

static struct cap_authority_info
token_info(int token)
{
	struct cap_authority_info info;

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE_MSG(op(CAP_AUTH_TOKEN_INFO, token, &info) == 0,
	    "CAP_AUTH_TOKEN_INFO: %s", strerror(errno));
	return (info);
}

static struct cap_authority_info
self_info(void)
{
	struct cap_authority_info info;

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE_MSG(op(CAP_AUTH_INFO, -1, &info) == 0, "CAP_AUTH_INFO: %s",
	    strerror(errno));
	return (info);
}

/* CAP_AUTH_CONSTRAIN token to the image open on image, with flags. */
static int
constrain(int issuer, int token, int image, uint32_t flags)
{
	struct cap_authority_constraint c;

	memset(&c, 0, sizeof(c));
	c.token_fd = token;
	c.flags = flags;
	c.nexec = 1;
	c.executable_fds[0] = image;
	return (ERRNO_OF(op(CAP_AUTH_CONSTRAIN, issuer, &c)));
}

/* A managed token constrained to the image open on image (flags 0). */
static int
constrained_token(int issuer, int image)
{
	int token;

	token = managed_token(issuer);
	ATF_REQUIRE_MSG(constrain(issuer, token, image, 0) == 0,
	    "CAP_AUTH_CONSTRAIN: %s", strerror(errno));
	return (token);
}

/*
 * A copy of the helper at ./name, mode 0755; its path in path.  The work
 * directory's mount must not be nosuid: exec_image_vnode.c selects no
 * authority for an image on such a mount, and the pins would fail with no
 * hint.
 */
static void
copy_image(const atf_tc_t *tc, const char *name, char *path, size_t len)
{
	struct statfs sfs;
	char src[MAXPATHLEN], buf[65536];
	ssize_t n;
	int in, out;

	ATF_REQUIRE_MSG(statfs(".", &sfs) == 0, "statfs: %s", strerror(errno));
	ATF_REQUIRE_MSG((sfs.f_flags & MNT_NOSUID) == 0,
	    "the work directory is on a nosuid mount (%s on %s): exec selects "
	    "no authority for an image there; run from a mount without "
	    "nosuid", sfs.f_fstypename, sfs.f_mntonname);
	snprintf(src, sizeof(src), "%s/%s", atf_tc_get_config_var(tc,
	    "srcdir"), HELPER);
	in = open(src, O_RDONLY);
	ATF_REQUIRE_MSG(in >= 0, "%s: %s", src, strerror(errno));
	out = open(name, O_WRONLY | O_CREAT | O_EXCL, 0755);
	ATF_REQUIRE_MSG(out >= 0, "%s: %s", name, strerror(errno));
	while ((n = read(in, buf, sizeof(buf))) > 0)
		ATF_REQUIRE(write(out, buf, n) == n);
	ATF_REQUIRE(n == 0);
	ATF_REQUIRE(close(in) == 0 && close(out) == 0);
	ATF_REQUIRE(getcwd(path, len) != NULL);
	ATF_REQUIRE(strlcat(path, "/", len) < len);
	ATF_REQUIRE(strlcat(path, name, len) < len);
}

static int
open_image(const char *path)
{
	int fd;

	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", path, strerror(errno));
	return (fd);
}

/* GETINFO: the endpoint's binding and lease check comes before anything. */
static int
probe(int fd)
{
	struct mac_capability_info_args info;

	memset(&info, 0, sizeof(info));
	return (ERRNO_OF(ioctl(fd, MAC_CAPABILITY_GETINFO, &info)));
}

static int
send_byte(int fd)
{
	struct mac_capability_sendmsg_args sa;
	char byte = 'a';

	memset(&sa, 0, sizeof(sa));
	sa.payload = &byte;
	sa.payload_len = 1;
	return (ERRNO_OF(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa)));
}

/* Receive one message with its stamps, waiting for it. */
static int
recv_v3(int fd, struct mac_capability_recvmsg_v3_args *rx, void *buf,
    size_t len)
{

	memset(rx, 0, sizeof(*rx));
	rx->message.payload = buf;
	rx->message.payload_len = len;
	rx->message.flags = MAC_CAPABILITY_RECV_F_WAIT;
	rx->message._reserved[0] = MAC_CAPABILITY_RECV_WAIT_FOREVER;
	return (ERRNO_OF(ioctl(fd, MAC_CAPABILITY_RECVMSG_V3, rx)));
}

static void
channel_pair(int pair[2])
{

	ATF_REQUIRE_MSG(mac_capability_channel_create(pair) == 0,
	    "channel pair: %s", strerror(errno));
}

static void
read_all(int fd, void *buf, size_t len)
{
	char *p = buf;
	ssize_t n;

	while (len > 0) {
		n = read(fd, p, len);
		ATF_REQUIRE_MSG(n > 0, "read: %s", n == 0 ? "end of file" :
		    strerror(errno));
		p += n;
		len -= (size_t)n;
	}
}

static void
write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	ssize_t n;

	while (len > 0) {
		n = write(fd, p, len);
		ATF_REQUIRE_MSG(n > 0, "write: %s", strerror(errno));
		p += n;
		len -= (size_t)n;
	}
}

static void
read_report(int fd, struct la_report *r)
{

	read_all(fd, r, sizeof(*r));
}

static void
wait_exit(pid_t pid, int want)
{
	int status;

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status), "pid %d status %#x", (int)pid,
	    status);
	ATF_REQUIRE_EQ_MSG(want, WEXITSTATUS(status), "pid %d exited %d",
	    (int)pid, WEXITSTATUS(status));
}

static char *
fdstr(int fd)
{
	static char bufs[8][16];
	static unsigned next;
	char *s = bufs[next++ % nitems(bufs)];

	snprintf(s, sizeof(bufs[0]), "%d", fd);
	return (s);
}

/* Run fn in a child; its exit status is fn's return. */
static pid_t
spawn(int (*fn)(void *), void *arg)
{
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fn(arg));
	return (pid);
}

/* Send fd to a fresh child over a UNIX socket; the child's answer. */
static int
sibling_with_fd(int fd, int (*fn)(int))
{
	char cbuf[CMSG_SPACE(sizeof(int))], byte = 'x';
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	pid_t pid;
	int got, sp[2], status, v;

	ATF_REQUIRE(socketpair(PF_UNIX, SOCK_STREAM, 0, sp) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		(void)close(sp[0]);
		memset(&msg, 0, sizeof(msg));
		memset(cbuf, 0, sizeof(cbuf));
		iov.iov_base = &byte;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		if (recvmsg(sp[1], &msg, 0) != 1)
			_exit(LA_HELPER_BROKEN);
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS)
			_exit(LA_HELPER_BROKEN);
		memcpy(&got, CMSG_DATA(cmsg), sizeof(got));
		v = fn(got);
		_exit(write(sp[1], &v, sizeof(v)) == (ssize_t)sizeof(v) ? 0 :
		    LA_HELPER_BROKEN);
	}
	(void)close(sp[1]);
	memset(&msg, 0, sizeof(msg));
	memset(cbuf, 0, sizeof(cbuf));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	ATF_REQUIRE_MSG(sendmsg(sp[0], &msg, 0) == 1, "sendmsg: %s",
	    strerror(errno));
	read_all(sp[0], &v, sizeof(v));
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	(void)close(sp[0]);
	return (v);
}

static int
sibling_probe(int fd)
{

	return (sibling_with_fd(fd, probe));
}

/* INSTALL in the sibling; its errno, with 1000 added when valid after. */
static int
install_here(int fd)
{
	struct cap_authority_info info;
	int error;

	error = ERRNO_OF(op(CAP_AUTH_INSTALL, fd, NULL));
	if (op(CAP_AUTH_INFO, -1, &info) == -1)
		return (LA_HELPER_BROKEN);
	return (error + (info.valid ? 1000 : 0));
}

/*
 * A child that installs the token, reports once, and with first set
 * executes it as "bound" (announce, gate, chan passed on; next after).
 * With pdeathsig the child sets SIGUSR1 as its parent death signal before
 * the exec.  Without first, the child exits after its report.
 */
struct exec_arg {
	int		 token;
	int		 report;
	int		 announce;	/* -1 for none */
	int		 gate;		/* -1 for none */
	int		 chan;		/* a channel end to probe, or -1 */
	const char	*first;		/* image to execute, or NULL */
	const char	*next;		/* image it executes next, or "-" */
	bool		 pdeathsig;
};

static int
install_then_exec(void *varg)
{
	struct exec_arg *a = varg;
	struct la_report r;
	int sig;

	memset(&r, 0, sizeof(r));
	r.install = ERRNO_OF(op(CAP_AUTH_INSTALL, a->token, NULL));
	if (op(CAP_AUTH_INFO, -1, &r.info) == -1)
		return (LA_HELPER_BROKEN);
	r.pid = getpid();
	r.issetugid = issetugid();
	r.probe = a->chan >= 0 ? probe(a->chan) : LA_NA;
	r.child_probe = r.cleared_probe = r.send = r.dq_open = LA_NA;
	r.pdeathsig = LA_NA;
	if (write(a->report, &r, sizeof(r)) != (ssize_t)sizeof(r))
		return (LA_HELPER_BROKEN);
	if (a->first == NULL)
		return (0);
	if (fcntl(a->report, F_SETFD, 0) != 0 ||
	    (a->chan >= 0 && fcntl(a->chan, F_SETFD, 0) != 0) ||
	    (a->announce >= 0 && fcntl(a->announce, F_SETFD, 0) != 0) ||
	    (a->gate >= 0 && fcntl(a->gate, F_SETFD, 0) != 0))
		return (LA_HELPER_BROKEN);
	if (a->pdeathsig) {
		sig = SIGUSR1;
		if (procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &sig) == -1)
			return (LA_HELPER_BROKEN);
	}
	execl(a->first, HELPER, "bound", fdstr(a->report), fdstr(a->announce),
	    fdstr(a->gate), fdstr(a->chan), a->next, (char *)NULL);
	return (LA_HELPER_BROKEN);
}

static void
exec_arg_init(struct exec_arg *a, int token, int report)
{

	memset(a, 0, sizeof(*a));
	a->token = token;
	a->report = report;
	a->announce = a->gate = a->chan = -1;
	a->first = NULL;
	a->next = "-";
}

/* ----------------------------------------------------------------
 * 1. Mint
 * ---------------------------------------------------------------- */

/*
 * LA0 pin: kept by LA1.  Today's mint is three steps (ISSUE, CONSTRAIN,
 * REGISTER_APP) on a mutable object; LA1 makes it one immutable step with
 * the same outcome: one image, one role, no registration of a role grant.
 * The errno of a second constraint today is EALREADY.
 */
ATF_TC(mint_constrain_once);
ATF_TC_HEAD(mint_constrain_once, tc)
{
	atf_tc_set_md_var(tc, "descr", "ISSUE then CONSTRAIN pins a grant to "
	    "one image with a role; a second CONSTRAIN is EALREADY; "
	    "REGISTER_APP of a role grant is EINVAL and consumes nothing; "
	    "the role shows nowhere in TOKEN_INFO");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_constrain_once, tc)
{
	struct cap_authority_application app;
	struct cap_authority_info before, after;
	struct cap_authority_revoke revoke;
	char pinned[MAXPATHLEN];
	int image, issuer, plain, token;

	issuer = require_issuer(tc);
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	image = open_image(pinned);

	token = managed_token(issuer);
	before = token_info(token);
	ATF_CHECK(before.issuer != 0 && before.identity != 0);
	ATF_CHECK_EQ(CAP_AUTH_MANAGED, before.kind);
	ATF_CHECK_EQ(0, before.consumed);
	ATF_CHECK_EQ(0, before.revoked);
	ATF_CHECK_EQ(1, before.references);
	ATF_CHECK_EQ(0, before.generation); /* a token has no generation */

	ROW("constrain role to one image", constrain(issuer, token, image,
	    CAP_AUTH_ROLE_DQ_SUPERVISOR), 0);
	ROW("second constrain, same role", constrain(issuer, token, image,
	    CAP_AUTH_ROLE_DQ_SUPERVISOR), EALREADY);
	ROW("second constrain, no role", constrain(issuer, token, image, 0),
	    EALREADY);
	memset(&app, 0, sizeof(app));
	app.token_fd = token;
	ROW("register a role grant", ERRNO_OF(op(CAP_AUTH_REGISTER_APP, issuer,
	    &app)), EINVAL);
	ROW("register it again", ERRNO_OF(op(CAP_AUTH_REGISTER_APP, issuer,
	    &app)), EINVAL);
	after = token_info(token);
	ATF_CHECK_EQ_MSG(0, memcmp(&before, &after, sizeof(before)),
	    "the constraint changed TOKEN_INFO (consumed=%u revoked=%u "
	    "references=%u)", after.consumed, after.revoked,
	    after.references);

	/* The contrast: a plain constraint of the same image registers. */
	plain = constrained_token(issuer, image);
	app.token_fd = plain;
	ROW("register a plain grant", ERRNO_OF(op(CAP_AUTH_REGISTER_APP,
	    issuer, &app)), 0);
	ATF_CHECK_EQ(1, token_info(plain).consumed);
	memset(&revoke, 0, sizeof(revoke));
	revoke.token_fd = plain;
	ATF_REQUIRE(op(CAP_AUTH_REVOKE, issuer, &revoke) == 0);
	ATF_CHECK_EQ(1, token_info(plain).revoked);

	(void)close(plain);
	(void)close(token);
	(void)close(image);
	(void)close(issuer);
}

/* ----------------------------------------------------------------
 * 2. Install once
 * ---------------------------------------------------------------- */

/*
 * LA0 pin: kept by LA1 for the one-install rule and its errno (EALREADY,
 * rev 1.2) and for the non-token refusals.  The five attenuation rows and
 * the two bearer rows (a token with its close-on-exec flag cleared installs
 * in the next image; a token passed over a UNIX socket installs in the
 * receiver) are "rewritten by LA1 (1.7)": LA1 refuses the limits on a
 * grant and makes it non-passable, where today the limits are accepted and
 * only INSTALL refuses the attenuated token (ENOTCAPABLE).
 */
ATF_TC(install_once);
ATF_TC_HEAD(install_once, tc)
{
	atf_tc_set_md_var(tc, "descr", "INSTALL of a constrained grant succeeds "
	    "once, in one process; every later INSTALL is EALREADY; a "
	    "non-token descriptor is EINVAL/EBADF; a token with a propagation "
	    "limit or reduced rights installs nowhere (ENOTCAPABLE) and stays "
	    "unconsumed; a token that survived exec, or was passed over a "
	    "UNIX socket, installs there");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(install_once, tc)
{
	static const struct {
		const char	*what;
		int		 limit;	/* 0 rights, 1 clofork, 2 cloexec */
		int		 state;
	} attenuated[] = {
		{ "rewritten by LA1 (1.7): rights CAP_FSTAT only", 0, 0 },
		{ "rewritten by LA1 (1.7): clofork locked", 1,
		    CAP_CLOFORK_LOCKED },
		{ "rewritten by LA1 (1.7): clofork once", 1, CAP_CLOFORK_ONCE },
		{ "rewritten by LA1 (1.7): cloexec locked", 2,
		    CAP_CLOEXEC_LOCKED },
		{ "rewritten by LA1 (1.7): cloexec once", 2, CAP_CLOEXEC_ONCE },
	};
	struct exec_arg a;
	struct la_report r;
	struct cap_authority_info tok;
	cap_rights_t rights;
	char pinned[MAXPATHLEN];
	int devnull, image, issuer, p[2], token;
	pid_t pid;

	issuer = require_issuer(tc);
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	image = open_image(pinned);
	token = constrained_token(issuer, image);
	tok = token_info(token);
	ATF_REQUIRE(pipe(p) == 0);

	/* The first install, in a child: pending until the pinned exec. */
	exec_arg_init(&a, token, p[1]);
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &r);
	wait_exit(pid, 0);
	ROW("first install", r.install, 0);
	ATF_CHECK_EQ(0, r.info.valid);
	ATF_CHECK_EQ(tok.identity, r.info.identity);
	ATF_CHECK_EQ(tok.issuer, r.info.issuer);
	ATF_CHECK_EQ(CAP_AUTH_MANAGED, r.info.kind);
	ATF_CHECK_EQ(1, r.info.consumed);
	ATF_CHECK_EQ(1, token_info(token).consumed);

	/* The second, in another child, and in this process. */
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &r);
	wait_exit(pid, 0);
	ROW("second install, another process", r.install, EALREADY);
	ATF_CHECK_EQ(0, r.info.valid);
	ATF_CHECK_EQ(0, r.info.identity);
	ROW("second install, this process", ERRNO_OF(op(CAP_AUTH_INSTALL,
	    token, NULL)), EALREADY);
	ATF_CHECK_EQ(0, self_info().valid);

	/* Not a token. */
	devnull = open("/dev/null", O_RDWR);
	ATF_REQUIRE(devnull >= 0);
	ROW("install the issuer", ERRNO_OF(op(CAP_AUTH_INSTALL, issuer, NULL)),
	    EINVAL);
	ROW("install /dev/null", ERRNO_OF(op(CAP_AUTH_INSTALL, devnull, NULL)),
	    EINVAL);
	ROW("install -1", ERRNO_OF(op(CAP_AUTH_INSTALL, -1, NULL)), EBADF);
	ROW("install with data", ERRNO_OF(op(CAP_AUTH_INSTALL, token, &r)),
	    EINVAL);
	(void)close(devnull);
	(void)close(token);

	/* Attenuated tokens: the limit is accepted, the install refused. */
	for (size_t i = 0; i < nitems(attenuated); i++) {
		token = constrained_token(issuer, image);
		switch (attenuated[i].limit) {
		case 0:
			ROW(attenuated[i].what, ERRNO_OF(cap_rights_limit(token,
			    cap_rights_init(&rights, CAP_FSTAT))), 0);
			break;
		case 1:
			ROW(attenuated[i].what, ERRNO_OF(cap_clofork_limit(token,
			    attenuated[i].state)), 0);
			break;
		default:
			ROW(attenuated[i].what, ERRNO_OF(cap_cloexec_limit(token,
			    attenuated[i].state)), 0);
			break;
		}
		ROW(attenuated[i].what, ERRNO_OF(op(CAP_AUTH_INSTALL, token,
		    NULL)), ENOTCAPABLE);
		ATF_CHECK_EQ(0, token_info(token).consumed);
		/* TOKEN_INFO needs only CAP_FSTAT: it still answers. */
		(void)close(token);
	}

	/*
	 * Bearer rows (rewritten by LA1 (1.7)): a token whose close-on-exec
	 * flag is cleared reaches the next image, which installs it.  The
	 * exec is an ordinary one (no grant installed): not set-id.
	 */
	token = constrained_token(issuer, image);
	tok = token_info(token);
	ATF_CHECK_MSG((fcntl(token, F_GETFD) & FD_CLOEXEC) != 0,
	    "a fresh token is not close-on-exec");
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (fcntl(token, F_SETFD, 0) != 0 ||
		    fcntl(p[1], F_SETFD, 0) != 0)
			_exit(LA_HELPER_BROKEN);
		execl(pinned, HELPER, "install", fdstr(p[1]), fdstr(token),
		    (char *)NULL);
		_exit(LA_HELPER_BROKEN);
	}
	read_report(p[0], &r);
	wait_exit(pid, 0);
	ROW("rewritten by LA1 (1.7): install after exec", r.install, 0);
	ATF_CHECK_EQ(0, r.info.valid);	/* pending: not the pinned exec */
	ATF_CHECK_EQ(tok.identity, r.info.identity);
	ATF_CHECK_EQ(1, token_info(token).consumed);
	ROW("kept by LA1: an exec without a grant is not set-id", r.issetugid,
	    0);
	(void)close(token);

	/* A token passed over a UNIX socket installs in the receiver. */
	token = constrained_token(issuer, image);
	ROW("rewritten by LA1 (1.7): install a token received over SCM_RIGHTS",
	    sibling_with_fd(token, install_here), 0);
	ATF_CHECK_EQ(1, token_info(token).consumed);
	ROW("the sender cannot install it after that", ERRNO_OF(op(
	    CAP_AUTH_INSTALL, token, NULL)), EALREADY);

	(void)close(token);
	(void)close(image);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(issuer);
}

/* ----------------------------------------------------------------
 * 3. Exec pin
 * ---------------------------------------------------------------- */

/*
 * LA0 pin: kept by LA1 (rev 1.2 section 6.1): with a grant pinned to one
 * image installed, the holder is pending until it executes that image,
 * which is a set-id exec (issetugid 1); valid on it; the exec of another
 * image succeeds and leaves the authority named and invalid (valid 0, same
 * identity, generation + 1), an ordinary exec (issetugid 0).  The parent
 * death signal is kept across both execs today: kern_exec.c clears it
 * only when the credential changes, which an authority-only set-id exec
 * does not (design section 6.1).
 */
ATF_TC(exec_pin);
ATF_TC_HEAD(exec_pin, tc)
{
	atf_tc_set_md_var(tc, "descr", "with a grant pinned to one image "
	    "installed, the holder is pending until it executes that image "
	    "(a set-id exec, issetugid 1), valid on it; executing another "
	    "image, from the pinned one or directly, succeeds as an ordinary "
	    "exec and leaves the authority named and invalid; the parent "
	    "death signal survives both execs");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(exec_pin, tc)
{
	struct exec_arg a;
	struct la_report pre, pinned_r, other_r;
	struct cap_authority_info tok;
	char pinned[MAXPATHLEN], other[MAXPATHLEN];
	int image, issuer, p[2], token;
	pid_t pid;

	issuer = require_issuer(tc);
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	copy_image(tc, OTHER_IMAGE, other, sizeof(other));
	image = open_image(pinned);
	ATF_REQUIRE(pipe(p) == 0);

	/* Pinned image, then another image from it. */
	token = constrained_token(issuer, image);
	tok = token_info(token);
	exec_arg_init(&a, token, p[1]);
	a.first = pinned;
	a.next = other;
	a.pdeathsig = true;
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &pre);
	read_report(p[0], &pinned_r);
	read_report(p[0], &other_r);
	wait_exit(pid, 0);

	ROW("install a pinned grant", pre.install, 0);
	ATF_CHECK_EQ_MSG(0, pre.info.valid, "pending before the exec");
	ATF_CHECK_EQ(tok.identity, pre.info.identity);
	ATF_CHECK_EQ(1, pre.info.consumed);
	ROW("the installing process is not set-id", pre.issetugid, 0);

	ATF_CHECK_EQ_MSG(1, pinned_r.info.valid, "valid on the pinned image");
	ATF_CHECK_EQ(tok.identity, pinned_r.info.identity);
	ATF_CHECK_EQ(tok.issuer, pinned_r.info.issuer);
	ATF_CHECK_EQ_MSG(pre.info.generation, pinned_r.info.generation,
	    "the exec of the pinned image keeps the generation");
	ATF_CHECK_EQ(pre.pid, pinned_r.pid);
	ROW("exec of the pinned image", pinned_r.exec_errno, 0);
	ROW("the pinned image is set-id (issetugid)", pinned_r.issetugid, 1);
	ROW("the pinned image keeps the parent death signal",
	    pinned_r.pdeathsig, SIGUSR1);

	ROW("exec of another image from the pinned one", other_r.exec_errno,
	    0);
	ATF_CHECK_EQ_MSG(0, other_r.info.valid,
	    "the other image runs with the authority invalid");
	ATF_CHECK_EQ_MSG(tok.identity, other_r.info.identity,
	    "the authority stays named");
	ATF_CHECK_EQ(pinned_r.info.generation + 1, other_r.info.generation);
	ATF_CHECK_EQ(pre.pid, other_r.pid);
	ROW("the other image is not set-id", other_r.issetugid, 0);
	ROW("the other image keeps the parent death signal",
	    other_r.pdeathsig, SIGUSR1);
	ATF_CHECK_EQ(1, token_info(token).consumed);
	(void)close(token);

	/* Another image directly from the pending state. */
	token = constrained_token(issuer, image);
	tok = token_info(token);
	exec_arg_init(&a, token, p[1]);
	a.first = other;
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &pre);
	read_report(p[0], &other_r);
	wait_exit(pid, 0);
	ROW("install the second grant", pre.install, 0);
	ATF_CHECK_EQ(0, pre.info.valid);
	ROW("exec of another image while pending", other_r.exec_errno, 0);
	ATF_CHECK_EQ(0, other_r.info.valid);
	ATF_CHECK_EQ(tok.identity, other_r.info.identity);
	ATF_CHECK_EQ(pre.info.generation + 1, other_r.info.generation);
	ROW("another image from pending is not set-id", other_r.issetugid, 0);
	ATF_CHECK_EQ(1, token_info(token).consumed);

	(void)close(token);
	(void)close(image);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(issuer);
}

/*
 * LA0 pin: deleted by LA2 (rev 1.2 section 6.2).  An image-less grant
 * (CONSTRAIN never called, nexec 0) is valid at install and stays valid
 * across the exec of any image, generation unchanged, with no set-id exec.
 * Its one shipped user is SwitchBoard's rc bootstrap grant
 * (svc_authority_issue_boot(), authority.c; execute.c for the want_console
 * units): the /etc/rc tree executes many images and needs a wire identity
 * that survives them.  Every other unit grant is constrained to its program
 * (svc_authority_constrain_application()) or to its service policy's
 * images.  It lives until the identity moves to the audit token.
 */
ATF_TC(unconstrained_grant_survives_exec);
ATF_TC_HEAD(unconstrained_grant_survives_exec, tc)
{
	atf_tc_set_md_var(tc, "descr", "a grant with no image is valid at "
	    "install and stays valid, generation unchanged, across two execs "
	    "of any images, neither of them set-id");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unconstrained_grant_survives_exec, tc)
{
	struct exec_arg a;
	struct la_report pre, first, second;
	struct cap_authority_info tok;
	char pinned[MAXPATHLEN], other[MAXPATHLEN];
	int issuer, p[2], token;
	pid_t pid;

	issuer = require_issuer(tc);
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	copy_image(tc, OTHER_IMAGE, other, sizeof(other));
	ATF_REQUIRE(pipe(p) == 0);
	token = managed_token(issuer);
	tok = token_info(token);
	exec_arg_init(&a, token, p[1]);
	a.first = pinned;
	a.next = other;
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &pre);
	read_report(p[0], &first);
	read_report(p[0], &second);
	wait_exit(pid, 0);

	ROW("install an image-less grant", pre.install, 0);
	ATF_CHECK_EQ_MSG(1, pre.info.valid, "valid at once");
	ATF_CHECK_EQ(tok.identity, pre.info.identity);
	ROW("first exec", first.exec_errno, 0);
	ATF_CHECK_EQ(1, first.info.valid);
	ATF_CHECK_EQ(tok.identity, first.info.identity);
	ATF_CHECK_EQ(pre.info.generation, first.info.generation);
	ROW("first exec is not set-id", first.issetugid, 0);
	ROW("second exec", second.exec_errno, 0);
	ATF_CHECK_EQ(1, second.info.valid);
	ATF_CHECK_EQ(tok.identity, second.info.identity);
	ATF_CHECK_EQ(pre.info.generation, second.info.generation);
	ROW("second exec is not set-id", second.issetugid, 0);
	ATF_CHECK_EQ(pre.pid, second.pid);

	(void)close(token);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(issuer);
}

/* ----------------------------------------------------------------
 * 4. Role effect
 * ---------------------------------------------------------------- */

/*
 * LA0 pin: kept by LA1.  CAP_AUTH_ROLE_DQ_SUPERVISOR is a carrier today:
 * no kernel interface consults it (cap_process(2) says so; sys/dev/dq and
 * kern_dqres.c read no role; the only reader of cap_authority_roles_locked()
 * is the OES process record), so there is no supervisor-only operation to
 * pin as succeeding with the role and refused without it.  What can be
 * pinned is that the role grant installs and runs its pinned image valid
 * exactly as a plain one does, and that the one dq operation a holder can
 * reach, opening /dev/dq, answers the same with and without the role.  The
 * Core role's observable effect (base exclusion of the pinned image) is
 * pinned on this tier by cap_exclusion_test x4_core_exec_sets and
 * x5_x7_other_image_clears; it is not repeated here.
 */
ATF_TC(role_dq_supervisor_carried);
ATF_TC_HEAD(role_dq_supervisor_carried, tc)
{
	atf_tc_set_md_var(tc, "descr", "a DQ_SUPERVISOR role grant installs and "
	    "runs its pinned image valid like a plain grant; INFO shows no "
	    "role; opening /dev/dq answers the same with and without the "
	    "role (no kernel interface consults it today)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(role_dq_supervisor_carried, tc)
{
	struct exec_arg a;
	struct la_report pre, with_role, without;
	struct cap_authority_info tok;
	char pinned[MAXPATHLEN];
	int image, issuer, p[2], token;
	pid_t pid;

	issuer = require_issuer(tc);
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	image = open_image(pinned);
	ATF_REQUIRE(pipe(p) == 0);

	token = managed_token(issuer);
	ROW("constrain with the role", constrain(issuer, token, image,
	    CAP_AUTH_ROLE_DQ_SUPERVISOR), 0);
	tok = token_info(token);
	exec_arg_init(&a, token, p[1]);
	a.first = pinned;
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &pre);
	read_report(p[0], &with_role);
	wait_exit(pid, 0);
	ROW("install the role grant", pre.install, 0);
	ATF_CHECK_EQ(0, pre.info.valid);
	ATF_CHECK_EQ(1, with_role.info.valid);
	ATF_CHECK_EQ(tok.identity, with_role.info.identity);
	ATF_CHECK_EQ(CAP_AUTH_MANAGED, with_role.info.kind);
	ATF_CHECK_EQ(0, with_role.info.uid);
	ROW("the role image is set-id like a plain one", with_role.issetugid,
	    1);
	(void)close(token);

	token = constrained_token(issuer, image);
	exec_arg_init(&a, token, p[1]);
	a.first = pinned;
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &pre);
	read_report(p[0], &without);
	wait_exit(pid, 0);
	ATF_CHECK_EQ(1, without.info.valid);

	/* The role is invisible in INFO and makes no difference to dq. */
	ATF_CHECK_EQ(with_role.info.kind, without.info.kind);
	ATF_CHECK_EQ(with_role.info.uid, without.info.uid);
	ATF_CHECK_EQ(with_role.info.valid, without.info.valid);
	ATF_CHECK_EQ(with_role.issetugid, without.issetugid);
	ATF_CHECK_EQ_MSG(without.dq_open, with_role.dq_open,
	    "open(/dev/dq): %d with the role, %d without", with_role.dq_open,
	    without.dq_open);
	ROW("open /dev/dq as root with the role", with_role.dq_open, 0);

	(void)close(token);
	(void)close(image);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(issuer);
}

/* ----------------------------------------------------------------
 * 5. Revoke
 * ---------------------------------------------------------------- */

/*
 * LA0 pin: kept by LA1 (auth_revoke).  The holder is the pinned image,
 * valid (its announcement carries a valid stamp); the test revokes while
 * it waits, and the image reports what it sees.
 */
ATF_TC(revoke);
ATF_TC_HEAD(revoke, tc)
{
	atf_tc_set_md_var(tc, "descr", "after REVOKE the holder's INFO reports "
	    "valid 0 and revoked 1 with the identity kept, TOKEN_INFO reports "
	    "revoked, a later INSTALL is EPERM; another issuer cannot revoke "
	    "it (EPERM); an unconsumed revoked token never installs");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(revoke, tc)
{
	struct exec_arg a;
	struct la_report pre, r;
	struct mac_capability_recvmsg_v3_args rx;
	struct cap_authority_revoke revoke;
	struct cap_authority_info tok;
	char pinned[MAXPATHLEN], byte;
	int announce[2], gate[2], image, issuer, other, p[2], token;
	pid_t pid;

	issuer = require_issuer(tc);
	other = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	ATF_REQUIRE_MSG(other >= 0, "second issuer: %s", strerror(errno));
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	image = open_image(pinned);
	channel_pair(announce);
	ATF_REQUIRE(pipe(p) == 0 && pipe(gate) == 0);

	token = constrained_token(issuer, image);
	tok = token_info(token);
	exec_arg_init(&a, token, p[1]);
	a.first = pinned;
	a.announce = announce[0];
	a.gate = gate[0];
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &pre);
	ROW("install", pre.install, 0);
	ATF_REQUIRE_EQ(0, recv_v3(announce[1], &rx, &byte, sizeof(byte)));
	ATF_CHECK_EQ_MSG(1, rx.authority.valid, "the holder is valid before");
	ATF_CHECK_EQ(tok.identity, rx.authority.identity);

	memset(&revoke, 0, sizeof(revoke));
	revoke.token_fd = token;
	ROW("revoke through another issuer", ERRNO_OF(op(CAP_AUTH_REVOKE,
	    other, &revoke)), EPERM);
	ATF_CHECK_EQ(0, token_info(token).revoked);
	ROW("revoke", ERRNO_OF(op(CAP_AUTH_REVOKE, issuer, &revoke)), 0);
	ATF_CHECK_EQ(1, token_info(token).revoked);
	ROW("revoke again", ERRNO_OF(op(CAP_AUTH_REVOKE, issuer, &revoke)), 0);

	write_all(gate[1], "g", 1);
	read_report(p[0], &r);
	wait_exit(pid, 0);
	ATF_CHECK_EQ_MSG(0, r.info.valid, "the holder is invalid after revoke");
	ATF_CHECK_EQ(1, r.info.revoked);
	ATF_CHECK_EQ_MSG(tok.identity, r.info.identity, "the identity is kept");
	ATF_CHECK_EQ(1, r.info.consumed);

	/* A later install of the revoked token, consumed or not. */
	ROW("install a revoked, consumed token", ERRNO_OF(op(CAP_AUTH_INSTALL,
	    token, NULL)), EPERM);
	(void)close(token);
	token = constrained_token(issuer, image);
	revoke.token_fd = token;
	ROW("revoke an unconsumed token", ERRNO_OF(op(CAP_AUTH_REVOKE, issuer,
	    &revoke)), 0);
	ROW("install a revoked, unconsumed token", ERRNO_OF(op(CAP_AUTH_INSTALL,
	    token, NULL)), EPERM);
	ATF_CHECK_EQ(0, token_info(token).consumed);
	ATF_CHECK_EQ(1, token_info(token).revoked);

	(void)close(token);
	(void)close(other);
	(void)close(image);
	(void)close(announce[0]);
	(void)close(announce[1]);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(gate[0]);
	(void)close(gate[1]);
	(void)close(issuer);
}

/* ----------------------------------------------------------------
 * 6. Library directories
 * ---------------------------------------------------------------- */

/*
 * LA0 pin: rewritten by LA1 (rev 1.2 section 6.4: the directories stay per
 * grant and become part of the one-step mint; the semantics do not
 * change).  Today SET_LIBDIRS is an issuer step after CONSTRAIN, once per
 * grant, and GET_LIBDIR gives the holder of a valid grant a fresh
 * close-on-exec descriptor for each directory with the rights the issuer
 * held, as rtld reads them.
 */
ATF_TC(libdirs_per_grant);
ATF_TC_HEAD(libdirs_per_grant, tc)
{
	atf_tc_set_md_var(tc, "descr", "SET_LIBDIRS needs a constrained, "
	    "unconsumed grant (EINVAL before CONSTRAIN and for a second set, "
	    "EPERM through another issuer, EINVAL for a count of 0 or more "
	    "than the maximum); GET_LIBDIR is ENOENT without a valid grant "
	    "(none, pending) and past the count, EINVAL at the maximum index "
	    "or with data, and in the pinned image returns a close-on-exec "
	    "descriptor of the directory with the issuer's rights");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(libdirs_per_grant, tc)
{
	struct cap_authority_libdirs dirs;
	struct la_libdir_report lr;
	struct stat st;
	cap_rights_t rights;
	char pinned[MAXPATHLEN];
	int directory, image, issuer, other, p[2], token;
	pid_t pid;

	issuer = require_issuer(tc);
	other = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	ATF_REQUIRE(other >= 0);
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	image = open_image(pinned);
	directory = open("/lib", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(directory >= 0);
	ATF_REQUIRE(fstat(directory, &st) == 0);
	ATF_REQUIRE(cap_rights_limit(directory, cap_rights_init(&rights,
	    CAP_LOOKUP, CAP_READ, CAP_FSTAT)) == 0);
	ATF_REQUIRE(pipe(p) == 0);

	ROW("GET_LIBDIR without a grant", ERRNO_OF(op(CAP_AUTH_GET_LIBDIR, 0,
	    NULL)), ENOENT);
	token = managed_token(issuer);
	memset(&dirs, 0, sizeof(dirs));
	dirs.token_fd = token;
	dirs.count = 1;
	dirs.directory_fds[0] = directory;
	ROW("set before CONSTRAIN", ERRNO_OF(op(CAP_AUTH_SET_LIBDIRS, issuer,
	    &dirs)), EINVAL);
	ROW("constrain", constrain(issuer, token, image, 0), 0);
	ROW("set through another issuer", ERRNO_OF(op(CAP_AUTH_SET_LIBDIRS,
	    other, &dirs)), EPERM);
	dirs.count = 0;
	ROW("set none", ERRNO_OF(op(CAP_AUTH_SET_LIBDIRS, issuer, &dirs)),
	    EINVAL);
	dirs.count = CAP_AUTH_LIBDIR_MAX + 1;
	ROW("set more than the maximum", ERRNO_OF(op(CAP_AUTH_SET_LIBDIRS,
	    issuer, &dirs)), EINVAL);
	dirs.count = 1;
	dirs.reserved = 1;
	ROW("set with a reserved bit", ERRNO_OF(op(CAP_AUTH_SET_LIBDIRS,
	    issuer, &dirs)), EINVAL);
	dirs.reserved = 0;
	dirs.directory_fds[0] = image;
	ROW("set a file, not a directory", ERRNO_OF(op(CAP_AUTH_SET_LIBDIRS,
	    issuer, &dirs)), EINVAL);
	dirs.directory_fds[0] = directory;
	ROW("set", ERRNO_OF(op(CAP_AUTH_SET_LIBDIRS, issuer, &dirs)), 0);
	ROW("set again", ERRNO_OF(op(CAP_AUTH_SET_LIBDIRS, issuer, &dirs)),
	    EINVAL);
	ATF_CHECK_EQ(0, token_info(token).consumed);
	(void)close(directory);

	/* The pending holder has no valid grant to read them through. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int v;

		if (op(CAP_AUTH_INSTALL, token, NULL) != 0)
			_exit(LA_HELPER_BROKEN);
		v = ERRNO_OF(op(CAP_AUTH_GET_LIBDIR, 0, NULL));
		if (write(p[1], &v, sizeof(v)) != (ssize_t)sizeof(v))
			_exit(LA_HELPER_BROKEN);
		if (fcntl(p[1], F_SETFD, 0) != 0)
			_exit(LA_HELPER_BROKEN);
		execl(pinned, HELPER, "libdir", fdstr(p[1]), (char *)NULL);
		_exit(LA_HELPER_BROKEN);
	}
	{
		int v;

		read_all(p[0], &v, sizeof(v));
		ROW("GET_LIBDIR while pending", v, ENOENT);
	}
	read_all(p[0], &lr, sizeof(lr));
	wait_exit(pid, 0);
	ATF_CHECK_EQ(1, lr.info.valid);
	ROW("GET_LIBDIR 0 in the pinned image", lr.get0, 0);
	ATF_CHECK_EQ_MSG(1, lr.cloexec, "the descriptor is close-on-exec");
	ATF_CHECK_EQ_MSG(1, lr.is_dir, "the descriptor is a directory");
	ATF_CHECK_EQ(st.st_dev, lr.dev);
	ATF_CHECK_EQ(st.st_ino, lr.ino);
	ATF_CHECK_MSG(cap_rights_contains(&rights, &lr.rights) &&
	    cap_rights_contains(&lr.rights, &rights),
	    "the descriptor's rights are not the issuer's");
	ROW("GET_LIBDIR 1, past the count", lr.get1, ENOENT);
	ROW("GET_LIBDIR at the maximum index", lr.get3, EINVAL);
	ROW("GET_LIBDIR with data", lr.get_data, EINVAL);

	(void)close(token);
	(void)close(image);
	(void)close(other);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(issuer);
}

/* ----------------------------------------------------------------
 * 7. Bound channel ends
 * ---------------------------------------------------------------- */

/*
 * LA0 pin: rewritten by LA3 (binding).  Today CAP_AUTH_BIND ties a channel
 * end to a grant (naming.c:570, every non-sendable lookup end): any process
 * that holds the grant valid may use it, a process without it may not,
 * whatever the descriptor's travels.  LA3's chan_bind_coalition keeps the
 * reach ("the unit and its tree") without the grant as the key.  The
 * holder is the pinned image of a constrained grant.
 */
ATF_TC(bind_to_grant);
ATF_TC_HEAD(bind_to_grant, tc)
{
	atf_tc_set_md_var(tc, "descr", "an end bound to a grant (CAP_AUTH_BIND) "
	    "is EPERM in a process without the grant (the issuer's, a "
	    "sibling it was sent to, a fork child that cleared it, a pending "
	    "holder) and 0 for the holder and its fork child; a second BIND "
	    "is EALREADY; an unbound end works anywhere");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bind_to_grant, tc)
{
	struct cap_authority_bind bind;
	struct exec_arg a;
	struct la_report pre, r;
	char pinned[MAXPATHLEN];
	int image, issuer, other, p[2], pair[2], plain[2], token;
	pid_t pid;

	issuer = require_issuer(tc);
	other = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	ATF_REQUIRE(other >= 0);
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	image = open_image(pinned);
	token = constrained_token(issuer, image);
	channel_pair(pair);
	channel_pair(plain);
	ATF_REQUIRE(pipe(p) == 0);

	memset(&bind, 0, sizeof(bind));
	bind.token_fd = token;
	bind.capability_fd = pair[0];
	ROW("bind through another issuer", ERRNO_OF(op(CAP_AUTH_BIND, other,
	    &bind)), EPERM);
	ROW("bind", ERRNO_OF(op(CAP_AUTH_BIND, issuer, &bind)), 0);
	ROW("bind again", ERRNO_OF(op(CAP_AUTH_BIND, issuer, &bind)),
	    EALREADY);
	ATF_CHECK_EQ(2, token_info(token).references);

	/* Nobody holds the grant yet: not this process, not a sibling. */
	ROW("the issuer's process probes the bound end", probe(pair[0]),
	    EPERM);
	ROW("the issuer's process sends on it", send_byte(pair[0]), EPERM);
	ROW("a process without the grant, sent the end", sibling_probe(pair[0]),
	    EPERM);
	ROW("the unbound peer end", probe(pair[1]), 0);
	ROW("an unbound end anywhere", sibling_probe(plain[0]), 0);

	/* The holder (the pinned image) and its tree. */
	exec_arg_init(&a, token, p[1]);
	a.chan = pair[0];
	a.first = pinned;
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &pre);
	read_report(p[0], &r);
	wait_exit(pid, 0);
	ROW("install in the holder", pre.install, 0);
	ROW("the pending holder probes the bound end", pre.probe, EPERM);
	ATF_CHECK_EQ(1, r.info.valid);
	ROW("the holder probes the bound end", r.probe, 0);
	ROW("the holder's fork child", r.child_probe, 0);
	ROW("the fork child after CAP_AUTH_CLEAR", r.cleared_probe, EPERM);
	ROW("the holder sends on it", r.send, 0);

	/* After the holder's exit the grant is still consumed: nobody else. */
	ROW("the issuer's process, holder gone", probe(pair[0]), EPERM);
	ROW("a sibling, holder gone", sibling_probe(pair[0]), EPERM);

	(void)close(pair[0]);
	(void)close(pair[1]);
	(void)close(plain[0]);
	(void)close(plain[1]);
	(void)close(token);
	(void)close(image);
	(void)close(other);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(issuer);
}

/*
 * LA0 pin: rewritten by LA3 (binding).  The grant binding across exec: the
 * pinned image keeps the end (the grant is valid there), another image
 * loses it (EPERM), and a pending holder (installed, not yet exec'd) is
 * refused too.  LA3's coalition binding must keep the first two answers.
 */
ATF_TC(bind_to_grant_across_exec);
ATF_TC_HEAD(bind_to_grant_across_exec, tc)
{
	atf_tc_set_md_var(tc, "descr", "a grant-bound end is EPERM while the "
	    "installed grant is pending, 0 in the pinned image and its fork "
	    "child, EPERM once that process executes another image");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bind_to_grant_across_exec, tc)
{
	struct cap_authority_bind bind;
	struct exec_arg a;
	struct la_report pre, pinned_r, other_r;
	char pinned[MAXPATHLEN], other[MAXPATHLEN];
	int image, issuer, p[2], pair[2], token;
	pid_t pid;

	issuer = require_issuer(tc);
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	copy_image(tc, OTHER_IMAGE, other, sizeof(other));
	image = open_image(pinned);
	token = constrained_token(issuer, image);
	channel_pair(pair);
	ATF_REQUIRE(pipe(p) == 0);
	memset(&bind, 0, sizeof(bind));
	bind.token_fd = token;
	bind.capability_fd = pair[0];
	ROW("bind", ERRNO_OF(op(CAP_AUTH_BIND, issuer, &bind)), 0);

	exec_arg_init(&a, token, p[1]);
	a.chan = pair[0];
	a.first = pinned;
	a.next = other;
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &pre);
	read_report(p[0], &pinned_r);
	read_report(p[0], &other_r);
	wait_exit(pid, 0);

	ROW("install", pre.install, 0);
	ROW("pending holder probes the bound end", pre.probe, EPERM);
	ATF_CHECK_EQ(1, pinned_r.info.valid);
	ROW("the pinned image probes it", pinned_r.probe, 0);
	ROW("the pinned image's fork child", pinned_r.child_probe, 0);
	ROW("the pinned image sends on it", pinned_r.send, 0);
	ATF_CHECK_EQ(0, other_r.info.valid);
	ROW("the other image probes it", other_r.probe, EPERM);
	ROW("the other image's fork child", other_r.child_probe, EPERM);
	ROW("the other image sends on it", other_r.send, EPERM);
	ROW("exec of the other image", other_r.exec_errno, 0);

	(void)close(pair[0]);
	(void)close(pair[1]);
	(void)close(token);
	(void)close(image);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(issuer);
}

/*
 * LA0 pin: rewritten by LA3 (binding).  CAP_AUTH_BIND_INVOCATION
 * (naming.c:363, the control channel) names one observed invocation: the
 * holder, not its fork child, and not its next execution even of the same
 * pinned image, whose stamp carries a new nonce.  LA3's chan_bind_process
 * keeps these three answers.
 */
ATF_TC(bind_to_invocation);
ATF_TC_HEAD(bind_to_invocation, tc)
{
	atf_tc_set_md_var(tc, "descr", "an end bound to the invocation the "
	    "kernel stamped on a message is 0 for that process only: its fork "
	    "child is EPERM and so is its next execution of the same pinned "
	    "image (a new nonce); a zero identity or nonce is EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bind_to_invocation, tc)
{
	struct cap_authority_bind_invocation inv;
	struct mac_capability_recvmsg_v3_args rx, rx2;
	struct exec_arg a;
	struct la_report pre, first, again;
	char pinned[MAXPATHLEN];
	char byte;
	int announce[2], gate[2], image, issuer, p[2], pair[2], token;
	pid_t pid;

	issuer = require_issuer(tc);
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	image = open_image(pinned);
	token = constrained_token(issuer, image);
	channel_pair(pair);
	channel_pair(announce);
	ATF_REQUIRE(pipe(p) == 0 && pipe(gate) == 0);

	/* The pinned image announces itself, waits, then re-executes. */
	exec_arg_init(&a, token, p[1]);
	a.first = pinned;
	a.next = pinned;
	a.announce = announce[0];
	a.gate = gate[0];
	a.chan = pair[0];
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &pre);
	ROW("install", pre.install, 0);

	/* What the kernel stamped on the pinned image's message. */
	ATF_REQUIRE_EQ_MSG(0, recv_v3(announce[1], &rx, &byte, sizeof(byte)),
	    "receive the announcement: %s", strerror(errno));
	ATF_CHECK_EQ(pid, rx.process.pid);
	ATF_CHECK_EQ(1, rx.authority.valid);
	ATF_REQUIRE(rx.process.identity != 0 && rx.message.trailer.nonce != 0);

	memset(&inv, 0, sizeof(inv));
	inv.token_fd = token;
	inv.capability_fd = pair[0];
	inv.process_identity = rx.process.identity;
	ROW("bind with a zero nonce", ERRNO_OF(op(CAP_AUTH_BIND_INVOCATION,
	    issuer, &inv)), EINVAL);
	inv.process_identity = 0;
	inv.execution_nonce = rx.message.trailer.nonce;
	ROW("bind with a zero identity", ERRNO_OF(op(CAP_AUTH_BIND_INVOCATION,
	    issuer, &inv)), EINVAL);
	inv.process_identity = rx.process.identity;
	ROW("bind to the invocation", ERRNO_OF(op(CAP_AUTH_BIND_INVOCATION,
	    issuer, &inv)), 0);
	ROW("bind again", ERRNO_OF(op(CAP_AUTH_BIND_INVOCATION, issuer, &inv)),
	    EALREADY);
	ROW("the issuer's process probes it", probe(pair[0]), EPERM);

	write_all(gate[1], "g", 1);
	read_report(p[0], &first);
	ATF_CHECK_EQ(1, first.info.valid);
	ROW("the bound invocation probes it", first.probe, 0);
	ROW("the bound invocation sends on it", first.send, 0);
	ROW("its fork child", first.child_probe, EPERM);

	/* The next execution of the same image announces with a new nonce. */
	ATF_REQUIRE_EQ(0, recv_v3(announce[1], &rx2, &byte, sizeof(byte)));
	ATF_CHECK_EQ(pid, rx2.process.pid);
	ATF_CHECK_EQ(1, rx2.authority.valid);
	ATF_CHECK_EQ(rx.process.identity, rx2.process.identity);
	ATF_CHECK_MSG(rx2.message.trailer.nonce != rx.message.trailer.nonce,
	    "the nonce did not change across exec");
	write_all(gate[1], "g", 1);
	read_report(p[0], &again);
	wait_exit(pid, 0);
	ROW("re-exec of the pinned image", again.exec_errno, 0);
	ATF_CHECK_EQ_MSG(1, again.info.valid,
	    "the grant is valid again on the same pinned image");
	ROW("the next execution probes it", again.probe, EPERM);
	ROW("the next execution sends on it", again.send, EPERM);
	ATF_CHECK_EQ(first.pid, again.pid);

	(void)close(pair[0]);
	(void)close(pair[1]);
	(void)close(announce[0]);
	(void)close(announce[1]);
	(void)close(token);
	(void)close(image);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(gate[0]);
	(void)close(gate[1]);
	(void)close(issuer);
}

/* ----------------------------------------------------------------
 * 8. Lease
 * ---------------------------------------------------------------- */

/* A blocked receive on fd, in a child; what it returned. */
static int
blocked_recv_child(void *varg)
{
	struct mac_capability_recvmsg_v3_args rx;
	int *fds = varg;
	char byte;
	int v;

	v = recv_v3(fds[0], &rx, &byte, sizeof(byte));
	return (write(fds[1], &v, sizeof(v)) == (ssize_t)sizeof(v) ? 0 :
	    LA_HELPER_BROKEN);
}

/*
 * LA0 pin: deleted by LA1 (lease).  The lease has no shipped creator
 * (section 0); these two cases record what it does so that its deletion is
 * a known loss: the deadline revokes every bound end (a blocked receive
 * wakes with EPERM; LEASE_CHECK answers EPERM), and so does the last close
 * of the owner or control descriptor.  Issuer revocation of a lease is
 * authority_test_issuer_anchor_test:anchor.
 */
ATF_TC(lease_deadline_revokes);
ATF_TC_HEAD(lease_deadline_revokes, tc)
{
	atf_tc_set_md_var(tc, "descr", "a lease of one second binds a channel "
	    "end (LEASE_BIND, once: EALREADY); when its deadline passes a "
	    "receive blocked on that end returns EPERM, LEASE_CHECK and the "
	    "end answer EPERM, the unbound peer still works; the owner "
	    "descriptor is not a control (EINVAL)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(lease_deadline_revokes, tc)
{
	struct cap_authority_lease_create lease;
	struct cap_authority_lease_bind lb;
	struct mac_capability_recvmsg_v3_args rx;
	char byte;
	int issuer, pair[2];

	issuer = require_issuer(tc);
	channel_pair(pair);
	memset(&lease, 0, sizeof(lease));
	lease.seconds = 0;
	ROW("a lease of zero seconds", ERRNO_OF(op(CAP_AUTH_LEASE_CREATE,
	    issuer, &lease)), EINVAL);
	lease.seconds = CAP_AUTH_LEASE_SECONDS_MAX + 1;
	ROW("a lease past the maximum", ERRNO_OF(op(CAP_AUTH_LEASE_CREATE,
	    issuer, &lease)), EINVAL);
	lease.seconds = 1;	/* the shortest lease the interface grants */
	ROW("create", ERRNO_OF(op(CAP_AUTH_LEASE_CREATE, issuer, &lease)), 0);
	ATF_REQUIRE(lease.control_fd >= 0 && lease.owner_fd >= 0);
	ROW("check a fresh lease", ERRNO_OF(op(CAP_AUTH_LEASE_CHECK,
	    lease.control_fd, NULL)), 0);
	ROW("check through the owner descriptor", ERRNO_OF(op(
	    CAP_AUTH_LEASE_CHECK, lease.owner_fd, NULL)), EINVAL);
	/* Both descriptors are nailed to this process. */
	ROW("owner: loosen close-on-fork", ERRNO_OF(cap_clofork_limit(
	    lease.owner_fd, CAP_CLOFORK_UNLOCKED)), ENOTCAPABLE);
	ROW("control: loosen close-on-exec", ERRNO_OF(cap_cloexec_limit(
	    lease.control_fd, CAP_CLOEXEC_UNLOCKED)), ENOTCAPABLE);
	ROW("control: allow transfer", ERRNO_OF(cap_xfer_limit(
	    lease.control_fd, CAP_XFER_ONCE)), ENOTCAPABLE);

	memset(&lb, 0, sizeof(lb));
	lb.lease_fd = lease.owner_fd;
	lb.capability_fd = pair[0];
	ROW("bind through the owner descriptor", ERRNO_OF(op(CAP_AUTH_LEASE_BIND,
	    issuer, &lb)), EINVAL);
	lb.lease_fd = lease.control_fd;
	ROW("bind", ERRNO_OF(op(CAP_AUTH_LEASE_BIND, issuer, &lb)), 0);
	ROW("bind again", ERRNO_OF(op(CAP_AUTH_LEASE_BIND, issuer, &lb)),
	    EALREADY);
	ROW("the bound end before the deadline", probe(pair[0]), 0);

	/*
	 * Wait for the deadline on the event itself: the expiry wakes every
	 * receiver blocked on a bound end, and the receive answers EPERM
	 * (so does a receive entered after the deadline: both orders pass).
	 */
	ROW("a receive blocked across the deadline", recv_v3(pair[0], &rx,
	    &byte, sizeof(byte)), EPERM);
	ROW("check after the deadline", ERRNO_OF(op(CAP_AUTH_LEASE_CHECK,
	    lease.control_fd, NULL)), EPERM);
	ROW("the bound end after the deadline", probe(pair[0]), EPERM);
	ROW("send on the bound end", send_byte(pair[0]), EPERM);
	ROW("the unbound peer", probe(pair[1]), 0);
	ROW("bind to an expired lease", ERRNO_OF(op(CAP_AUTH_LEASE_BIND, issuer,
	    &(struct cap_authority_lease_bind){ .lease_fd = lease.control_fd,
	    .capability_fd = pair[1] })), EPERM);

	(void)close(pair[0]);
	(void)close(pair[1]);
	(void)close(lease.owner_fd);
	(void)close(lease.control_fd);
	(void)close(issuer);
}

/* LA0 pin: deleted by LA1 (lease). */
ATF_TC(lease_last_close_revokes);
ATF_TC_HEAD(lease_last_close_revokes, tc)
{
	atf_tc_set_md_var(tc, "descr", "closing the owner descriptor revokes "
	    "the lease (LEASE_CHECK EPERM, bound ends EPERM, a blocked "
	    "receive wakes with EPERM); closing the control descriptor of "
	    "another lease revokes it the same way");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(lease_last_close_revokes, tc)
{
	struct cap_authority_lease_create lease;
	struct cap_authority_lease_bind lb;
	int fds[2], issuer, p[2], pair[2], v;
	pid_t pid;

	issuer = require_issuer(tc);

	/* The owner's last close, with a receiver blocked on the end. */
	channel_pair(pair);
	ATF_REQUIRE(pipe(p) == 0);
	memset(&lease, 0, sizeof(lease));
	lease.seconds = CAP_AUTH_LEASE_SECONDS_MAX;
	ROW("create", ERRNO_OF(op(CAP_AUTH_LEASE_CREATE, issuer, &lease)), 0);
	memset(&lb, 0, sizeof(lb));
	lb.lease_fd = lease.control_fd;
	lb.capability_fd = pair[0];
	ROW("bind", ERRNO_OF(op(CAP_AUTH_LEASE_BIND, issuer, &lb)), 0);
	fds[0] = pair[0];
	fds[1] = p[1];
	pid = spawn(blocked_recv_child, fds);
	/*
	 * Revocation is sticky: whether the child is blocked already or
	 * receives after this close, its receive answers EPERM.
	 */
	ATF_REQUIRE(close(lease.owner_fd) == 0);
	read_all(p[0], &v, sizeof(v));
	wait_exit(pid, 0);
	ROW("a receive across the owner's close", v, EPERM);
	ROW("check after the owner's close", ERRNO_OF(op(CAP_AUTH_LEASE_CHECK,
	    lease.control_fd, NULL)), EPERM);
	ROW("the bound end after the owner's close", probe(pair[0]), EPERM);
	ROW("the unbound peer", probe(pair[1]), 0);
	(void)close(lease.control_fd);
	(void)close(pair[0]);
	(void)close(pair[1]);

	/* The control's last close. */
	channel_pair(pair);
	memset(&lease, 0, sizeof(lease));
	lease.seconds = CAP_AUTH_LEASE_SECONDS_MAX;
	ROW("create another", ERRNO_OF(op(CAP_AUTH_LEASE_CREATE, issuer,
	    &lease)), 0);
	lb.lease_fd = lease.control_fd;
	lb.capability_fd = pair[0];
	ROW("bind it", ERRNO_OF(op(CAP_AUTH_LEASE_BIND, issuer, &lb)), 0);
	ROW("the bound end", probe(pair[0]), 0);
	fds[0] = pair[0];
	pid = spawn(blocked_recv_child, fds);
	ATF_REQUIRE(close(lease.control_fd) == 0);
	read_all(p[0], &v, sizeof(v));
	wait_exit(pid, 0);
	ROW("a receive across the control's close", v, EPERM);
	ROW("the bound end after the control's close", probe(pair[0]), EPERM);
	(void)close(lease.owner_fd);
	(void)close(pair[0]);
	(void)close(pair[1]);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(issuer);
}

/* ----------------------------------------------------------------
 * 9. Stamp
 * ---------------------------------------------------------------- */

/* An anonymous sender: no grant; one message on chan, then a report. */
struct anon_arg {
	int	chan;
	int	report;
};

static int
anonymous_sender(void *varg)
{
	struct anon_arg *a = varg;
	struct la_report r;

	memset(&r, 0, sizeof(r));
	if (op(CAP_AUTH_INFO, -1, &r.info) == -1)
		return (LA_HELPER_BROKEN);
	r.pid = getpid();
	r.send = send_byte(a->chan);
	r.install = r.probe = r.child_probe = r.cleared_probe = r.dq_open =
	    LA_NA;
	return (write(a->report, &r, sizeof(r)) == (ssize_t)sizeof(r) ? 0 :
	    LA_HELPER_BROKEN);
}

/*
 * LA0 pin: rewritten by LA2 (stamp).  Today a received message's
 * cap_authority_stamp (MAC_CAPABILITY_RECVMSG_V3; libchannel
 * channel_message_authority) names the sender's issuer and grant identity
 * while its grant is valid, and is all zero for an anonymous sender and
 * for a holder whose grant was revoked; the message itself is delivered in
 * every case (an unbound end).  LA2 deletes the stamp and keys SwitchBoard
 * on the audit token, which the trailer carries already: these rows say
 * what the stamp distinguished, so LA2 can show the token distinguishes
 * the same senders.  The holder is the pinned image of a constrained
 * grant; the revoked holder is its next execution after the revoke.
 */
ATF_TC(stamp_names_grant_holder);
ATF_TC_HEAD(stamp_names_grant_holder, tc)
{
	atf_tc_set_md_var(tc, "descr", "a message from a grant holder carries a "
	    "valid stamp with the holder's issuer, identity, kind and uid and "
	    "the holder's generation; an anonymous sender's stamp is all "
	    "zero; a revoked holder's is too; all three are delivered");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(stamp_names_grant_holder, tc)
{
	struct mac_capability_recvmsg_v3_args rx;
	struct cap_authority_revoke revoke;
	struct cap_authority_info tok;
	struct exec_arg a;
	struct anon_arg an;
	struct la_report pre, r;
	char pinned[MAXPATHLEN], byte;
	int gate[2], image, issuer, p[2], pair[2], token;
	pid_t pid;

	issuer = require_issuer(tc);
	copy_image(tc, PINNED_IMAGE, pinned, sizeof(pinned));
	image = open_image(pinned);
	channel_pair(pair);
	ATF_REQUIRE(pipe(p) == 0 && pipe(gate) == 0);

	/* A grant holder: the pinned image announces on the pair. */
	token = constrained_token(issuer, image);
	tok = token_info(token);
	exec_arg_init(&a, token, p[1]);
	a.first = pinned;
	a.next = pinned;
	a.announce = pair[0];
	a.gate = gate[0];
	pid = spawn(install_then_exec, &a);
	read_report(p[0], &pre);
	ROW("install", pre.install, 0);
	ATF_REQUIRE_EQ(0, recv_v3(pair[1], &rx, &byte, sizeof(byte)));
	ATF_CHECK_EQ(pid, rx.process.pid);
	ATF_CHECK_EQ_MSG(1, rx.authority.valid, "a holder's stamp is valid");
	ATF_CHECK_EQ(tok.issuer, rx.authority.issuer);
	ATF_CHECK_EQ(tok.identity, rx.authority.identity);
	ATF_CHECK_EQ(CAP_AUTH_MANAGED, rx.authority.kind);
	ATF_CHECK_EQ(0, rx.authority.uid);
	ATF_CHECK(rx.authority.generation != 0);
	ATF_CHECK_EQ(0, rx.authority.reserved);
	ATF_CHECK(rx.process.identity != 0);
	ATF_CHECK(rx.message.trailer.nonce != 0);

	/*
	 * Revoke while the holder waits; its report shows the revoke, and
	 * its next execution (the same pinned image) announces again with
	 * the grant revoked.
	 */
	memset(&revoke, 0, sizeof(revoke));
	revoke.token_fd = token;
	ATF_REQUIRE(op(CAP_AUTH_REVOKE, issuer, &revoke) == 0);
	write_all(gate[1], "g", 1);
	read_report(p[0], &r);
	ATF_CHECK_EQ_MSG(rx.authority.generation, r.info.generation,
	    "the stamp's generation is the holder's");
	ATF_CHECK_EQ(0, r.info.valid);
	ATF_CHECK_EQ(1, r.info.revoked);
	ATF_REQUIRE_EQ(0, recv_v3(pair[1], &rx, &byte, sizeof(byte)));
	ATF_CHECK_EQ(pid, rx.process.pid);
	ATF_CHECK_EQ_MSG(0, rx.authority.valid, "a revoked holder's stamp is "
	    "not valid");
	ATF_CHECK_EQ(0, rx.authority.issuer);
	ATF_CHECK_EQ(0, rx.authority.identity);
	ATF_CHECK_EQ(0, rx.authority.generation);
	ATF_CHECK_MSG(rx.process.identity != 0, "the process stamp is there");
	write_all(gate[1], "g", 1);
	read_report(p[0], &r);
	wait_exit(pid, 0);
	ROW("the revoked holder's re-exec", r.exec_errno, 0);
	ATF_CHECK_EQ(0, r.info.valid);
	ATF_CHECK_EQ(1, r.info.revoked);
	(void)close(token);

	/* An anonymous sender. */
	an.chan = pair[0];
	an.report = p[1];
	pid = spawn(anonymous_sender, &an);
	read_report(p[0], &r);
	wait_exit(pid, 0);
	ROW("the anonymous send", r.send, 0);
	ATF_CHECK_EQ(0, r.info.valid);
	ATF_REQUIRE_EQ(0, recv_v3(pair[1], &rx, &byte, sizeof(byte)));
	ATF_CHECK_EQ(pid, rx.process.pid);
	ATF_CHECK_EQ_MSG(0, rx.authority.valid, "an anonymous stamp is not "
	    "valid");
	ATF_CHECK_EQ(0, rx.authority.issuer);
	ATF_CHECK_EQ(0, rx.authority.identity);
	ATF_CHECK_EQ(0, rx.authority.generation);
	ATF_CHECK_EQ(0, rx.authority.kind);
	ATF_CHECK_EQ(0, rx.authority.uid);
	ATF_CHECK_MSG(rx.process.identity != 0, "the process stamp is there");

	(void)close(image);
	(void)close(pair[0]);
	(void)close(pair[1]);
	(void)close(p[0]);
	(void)close(p[1]);
	(void)close(gate[0]);
	(void)close(gate[1]);
	(void)close(issuer);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mint_constrain_once);
	ATF_TP_ADD_TC(tp, install_once);
	ATF_TP_ADD_TC(tp, exec_pin);
	ATF_TP_ADD_TC(tp, unconstrained_grant_survives_exec);
	ATF_TP_ADD_TC(tp, role_dq_supervisor_carried);
	ATF_TP_ADD_TC(tp, revoke);
	ATF_TP_ADD_TC(tp, libdirs_per_grant);
	ATF_TP_ADD_TC(tp, bind_to_grant);
	ATF_TP_ADD_TC(tp, bind_to_grant_across_exec);
	ATF_TP_ADD_TC(tp, bind_to_invocation);
	ATF_TP_ADD_TC(tp, lease_deadline_revokes);
	ATF_TP_ADD_TC(tp, lease_last_close_revokes);
	ATF_TP_ADD_TC(tp, stamp_names_grant_holder);
	return (atf_no_error());
}
