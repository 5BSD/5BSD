/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * The audit token (audit_token(3)): the three ids it carries, when they
 * change, and the three system calls that hand it out and look it up.
 *
 * A process's uniqueid is set at fork and never changes; its execgen is new
 * at fork and at every exec; its imageid belongs to its credential, is new
 * at exec, is inherited across fork with the credential, and is 0 ("no
 * image") for credentials the kernel makes itself.  A token names a process
 * when the pid, the uniqueid and the execgen all match
 * (AUDIT_TOKEN_MAY_EXEC ignores the execgen, AUDIT_TOKEN_MAY_EXIT accepts a
 * zombie).
 *
 * The cases call the interface through syscall(2) at its reserved numbers
 * (audit_token_pins.h), so on a tree that only reserves them every case
 * fails with ENOSYS: SIGSYS is ignored for that.  The program is exclusive
 * because pid_reuse_check lowers kern.pid_max.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/jail.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "audit_token_pins.h"

#define	PID_MAX_SYSCTL	"kern.pid_max"
#define	RANDOMPID	"kern.randompid"
/* The lowered pid space, and the most live processes it is used with. */
#define	PID_LOW		1000
#define	PROCS_MOST	(PID_LOW / 4)
/* Four wraps of the lowered space; more forks than this is a failure. */
#define	FORKS_MOST	(8 * PID_LOW)

/*
 * The bits of a sequence value the boot's random offset never sets: bit 63
 * and the low 32 (kernel-identity-and-coalitions.md 1.1, rev 1.3).
 */
#define	BOOT_OFFSET_CLEAR	0x80000000ffffffffULL

/* The unprivileged ids setuid_keeps_ids changes to. */
#define	UNPRIV_UID	65534
#define	UNPRIV_GID	65534

extern char **environ;

static void
pins_init(void)
{
	/* On a tree without the calls, nosys() would kill us. */
	ATF_REQUIRE(signal(SIGSYS, SIG_IGN) != SIG_ERR);
}

static void
tok_get(int pd, pid_t pid, int flags, audit_token_t *tok)
{
	memset(tok, 0xa5, sizeof(*tok));
	ATF_REQUIRE_EQ_MSG(0, pin_audit_token_get(pd, pid, flags, tok),
	    "audit_token_get(%d, %d, %#x): %s", pd, (int)pid, flags,
	    strerror(errno));
}

static void
tok_self(audit_token_t *tok)
{
	tok_get(-1, 0, 0, tok);
}

/* The errno of a call that must fail, or 0 if it succeeded. */
static int
fails(int rv)
{
	return (rv == -1 ? errno : 0);
}

static void
kinfo_get(pid_t pid, struct kinfo_proc *kp)
{
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;
	len = sizeof(*kp);
	ATF_REQUIRE_EQ_MSG(0, sysctl(mib, nitems(mib), kp, &len, NULL, 0),
	    "kern.proc.pid.%d: %s", (int)pid, strerror(errno));
	ATF_REQUIRE_EQ(sizeof(*kp), len);
}

/*
 * A child that waits for end of file on the pipe it is given, then exits
 * with `code'.  The parent keeps the write end in *wfd.
 */
static pid_t
child_waiting(int *wfd, int code)
{
	int p[2];
	pid_t pid;
	char c;

	ATF_REQUIRE_EQ(0, pipe2(p, O_CLOEXEC));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		(void)close(p[1]);
		while (read(p[0], &c, 1) > 0)
			;
		_exit(code);
	}
	ATF_REQUIRE_EQ(0, close(p[0]));
	*wfd = p[1];
	return (pid);
}

static void
child_release(pid_t pid, int wfd, int code)
{
	int status;

	ATF_REQUIRE_EQ(0, close(wfd));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == code,
	    "child %d: status %#x, wanted exit %d", (int)pid, status, code);
}

/* Read a token a child wrote to fd, or fail. */
static void
tok_read(int fd, audit_token_t *tok)
{
	ATF_REQUIRE_EQ_MSG(sizeof(*tok), read(fd, tok, sizeof(*tok)),
	    "the child sent no token");
}

static void
tok_same_process(audit_token_t a, audit_token_t b)
{
	ATF_CHECK_EQ(audit_token_to_pid(a), audit_token_to_pid(b));
	ATF_CHECK_EQ(audit_token_to_uniqueid(a), audit_token_to_uniqueid(b));
}

/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(self_fields);
ATF_TC_BODY(self_fields, tc)
{
	audit_token_t tok;
	struct kinfo_proc kp;

	pins_init();
	tok_self(&tok);
	ATF_CHECK_EQ(getpid(), audit_token_to_pid(tok));
	ATF_CHECK_EQ(geteuid(), audit_token_to_euid(tok));
	ATF_CHECK_EQ(getuid(), audit_token_to_ruid(tok));
	ATF_CHECK_EQ(getegid(), audit_token_to_egid(tok));
	ATF_CHECK_EQ(getgid(), audit_token_to_rgid(tok));
	ATF_CHECK(audit_token_to_uniqueid(tok) != 0);
	ATF_CHECK(audit_token_to_execgen(tok) != 0);
	/* The test program was exec'd: its credential has an image. */
	ATF_CHECK(audit_token_to_imageid(tok) != 0);

	kinfo_get(getpid(), &kp);
	ATF_CHECK_EQ(kp.ki_jid, audit_token_to_jid(tok));
	ATF_CHECK_EQ(KP_UNIQUEID(&kp), audit_token_to_uniqueid(tok));
	ATF_CHECK_EQ(KP_EXECGEN(&kp), audit_token_to_execgen(tok));
	ATF_CHECK_EQ(KP_IMAGEID(&kp), audit_token_to_imageid(tok));
}

ATF_TC_WITHOUT_HEAD(fork_distinct);
ATF_TC_BODY(fork_distinct, tc)
{
	audit_token_t before, after, child, bypid;
	int out[2], in[2], status;
	pid_t pid;

	pins_init();
	tok_self(&before);
	ATF_REQUIRE_EQ(0, pipe(out));
	ATF_REQUIRE_EQ(0, pipe(in));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		audit_token_t t;
		char c;

		(void)close(out[0]);
		(void)close(in[1]);
		if (pin_audit_token_get(-1, 0, 0, &t) != 0 ||
		    write(out[1], &t, sizeof(t)) != sizeof(t))
			_exit(1);
		/* Stay until the parent has looked at us by pid. */
		(void)read(in[0], &c, 1);
		_exit(0);
	}
	ATF_REQUIRE_EQ(0, close(out[1]));
	ATF_REQUIRE_EQ(0, close(in[0]));
	tok_read(out[0], &child);
	tok_get(-1, pid, 0, &bypid);
	tok_self(&after);
	ATF_REQUIRE_EQ(0, close(in[1]));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE_EQ(0, close(out[0]));

	/* The parent is unchanged by its fork. */
	ATF_CHECK_EQ(0, memcmp(&before, &after, sizeof(before)));

	ATF_CHECK_EQ(pid, audit_token_to_pid(child));
	ATF_CHECK(audit_token_to_uniqueid(child) !=
	    audit_token_to_uniqueid(before));
	/* Counters, not random: the later process has the larger ids. */
	ATF_CHECK(audit_token_to_uniqueid(child) >
	    audit_token_to_uniqueid(before));
	ATF_CHECK(audit_token_to_execgen(child) >
	    audit_token_to_execgen(before));
	/* The credential, and with it the image id, is the parent's. */
	ATF_CHECK_EQ(audit_token_to_imageid(before),
	    audit_token_to_imageid(child));
	ATF_CHECK_EQ(0, memcmp(&child, &bypid, sizeof(child)));
}

/*
 * The helper is exec'd by a child; the ids it reads after the exec are
 * compared with the child's before it.  A failed exec (ENOEXEC) first
 * changes nothing.
 */
ATF_TC_WITHOUT_HEAD(exec_changes_execgen_imageid);
ATF_TC_BODY(exec_changes_execgen_imageid, tc)
{
	audit_token_t pre, failed, post, bypid;
	char helper[PATH_MAX];
	int out[2], in[2], fd, status;
	pid_t pid;

	pins_init();
	snprintf(helper, sizeof(helper), "%s/audit_token_helper",
	    atf_tc_get_config_var(tc, "srcdir"));
	/* Executable, but no image activator knows it. */
	fd = open("noexec", O_WRONLY | O_CREAT | O_EXCL, 0755);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(8, write(fd, "\001\002\003\004\005\006\007\010", 8));
	ATF_REQUIRE_EQ(0, close(fd));

	ATF_REQUIRE_EQ(0, pipe(out));
	ATF_REQUIRE_EQ(0, pipe(in));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		audit_token_t t;
		char *const argv[] = { helper, NULL };
		char *const noargv[] = { __DECONST(char *, "noexec"), NULL };

		if (pin_audit_token_get(-1, 0, 0, &t) != 0 ||
		    write(out[1], &t, sizeof(t)) != sizeof(t))
			_exit(1);
		if (execve("noexec", noargv, environ) != -1 ||
		    errno != ENOEXEC)
			_exit(3);
		if (pin_audit_token_get(-1, 0, 0, &t) != 0 ||
		    write(out[1], &t, sizeof(t)) != sizeof(t))
			_exit(1);
		if (dup2(out[1], STDOUT_FILENO) == -1 ||
		    dup2(in[0], STDIN_FILENO) == -1)
			_exit(1);
		(void)close(in[1]);
		execve(helper, argv, environ);
		_exit(4);
	}
	ATF_REQUIRE_EQ(0, close(out[1]));
	ATF_REQUIRE_EQ(0, close(in[0]));
	tok_read(out[0], &pre);
	tok_read(out[0], &failed);
	tok_read(out[0], &post);
	/* The exec'd image, seen from outside while it runs. */
	tok_get(-1, pid, 0, &bypid);
	ATF_REQUIRE_EQ(0, close(in[1]));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child status %#x", status);

	ATF_CHECK_EQ_MSG(0, memcmp(&pre, &failed, sizeof(pre)),
	    "a failed exec changed the token");
	tok_same_process(pre, post);
	ATF_CHECK(audit_token_to_execgen(post) >
	    audit_token_to_execgen(pre));
	ATF_CHECK(audit_token_to_imageid(post) != 0);
	ATF_CHECK(audit_token_to_imageid(post) !=
	    audit_token_to_imageid(pre));
	ATF_CHECK(audit_token_to_imageid(post) >
	    audit_token_to_imageid(pre));
	ATF_CHECK_EQ(0, memcmp(&post, &bypid, sizeof(post)));
}

ATF_TC(setuid_keeps_ids);
ATF_TC_HEAD(setuid_keeps_ids, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setuid_keeps_ids, tc)
{
	audit_token_t pre, post;
	int p[2], status;
	pid_t pid;

	pins_init();
	ATF_REQUIRE_EQ(0, pipe(p));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		audit_token_t t;

		if (pin_audit_token_get(-1, 0, 0, &t) != 0 ||
		    write(p[1], &t, sizeof(t)) != sizeof(t))
			_exit(1);
		if (setgid(UNPRIV_GID) != 0 || setuid(UNPRIV_UID) != 0)
			_exit(2);
		if (pin_audit_token_get(-1, 0, 0, &t) != 0 ||
		    write(p[1], &t, sizeof(t)) != sizeof(t))
			_exit(1);
		_exit(0);
	}
	ATF_REQUIRE_EQ(0, close(p[1]));
	tok_read(p[0], &pre);
	tok_read(p[0], &post);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	ATF_CHECK_EQ((uid_t)0, audit_token_to_euid(pre));
	ATF_CHECK_EQ((uid_t)UNPRIV_UID, audit_token_to_euid(post));
	ATF_CHECK_EQ((uid_t)UNPRIV_UID, audit_token_to_ruid(post));
	ATF_CHECK_EQ((gid_t)UNPRIV_GID, audit_token_to_egid(post));
	ATF_CHECK_EQ((gid_t)UNPRIV_GID, audit_token_to_rgid(post));
	/* A credential change is not a new image or a new process. */
	tok_same_process(pre, post);
	ATF_CHECK_EQ(audit_token_to_execgen(pre),
	    audit_token_to_execgen(post));
	ATF_CHECK_EQ(audit_token_to_imageid(pre),
	    audit_token_to_imageid(post));
}

/*
 * Credentials the kernel makes for itself have no image: proc0's (and so
 * every kernel process's, forked from it without an exec), as seen through
 * kinfo_proc.  proc0 is the first process: it has the first uniqueid and
 * execgen of the boot, the boot's offset (low 32 bits 0, bit 63 clear)
 * plus one.
 */
ATF_TC_WITHOUT_HEAD(crget_cred_imageid_zero);
ATF_TC_BODY(crget_cred_imageid_zero, tc)
{
	struct kinfo_proc *kp;
	size_t len;
	int mib[3], i, n, nsys;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PROC;
	len = 0;
	ATF_REQUIRE_EQ(0, sysctl(mib, nitems(mib), NULL, &len, NULL, 0));
	len *= 2;
	kp = malloc(len);
	ATF_REQUIRE(kp != NULL);
	ATF_REQUIRE_EQ(0, sysctl(mib, nitems(mib), kp, &len, NULL, 0));
	n = len / sizeof(*kp);
	nsys = 0;
	for (i = 0; i < n; i++) {
		if (kp[i].ki_pid == 0) {
			ATF_CHECK_EQ_MSG((uint64_t)1,
			    KP_UNIQUEID(&kp[i]) & BOOT_OFFSET_CLEAR,
			    "proc0 uniqueid %#jx", (uintmax_t)KP_UNIQUEID(&kp[i]));
			ATF_CHECK_EQ_MSG((uint64_t)1,
			    KP_EXECGEN(&kp[i]) & BOOT_OFFSET_CLEAR,
			    "proc0 execgen %#jx", (uintmax_t)KP_EXECGEN(&kp[i]));
		}
		if ((kp[i].ki_flag & P_SYSTEM) != 0) {
			nsys++;
			ATF_CHECK_EQ_MSG((uint64_t)0, KP_IMAGEID(&kp[i]),
			    "kernel process %d (%s) has image id %ju",
			    kp[i].ki_pid, kp[i].ki_comm,
			    (uintmax_t)KP_IMAGEID(&kp[i]));
			ATF_CHECK_MSG(KP_UNIQUEID(&kp[i]) != 0,
			    "kernel process %d (%s) has no uniqueid",
			    kp[i].ki_pid, kp[i].ki_comm);
		} else {
			/* Every user process has been exec'd. */
			ATF_CHECK_MSG(KP_IMAGEID(&kp[i]) != 0,
			    "process %d (%s) has no image id", kp[i].ki_pid,
			    kp[i].ki_comm);
		}
	}
	ATF_CHECK(nsys > 1);
	free(kp);
}

/*
 * A process descriptor is the authority: its holder gets the token of a
 * process it cannot see by pid.  The looker is jailed after it took the
 * descriptor; its child stays outside the jail.
 */
ATF_TC(pd_get_needs_no_cansee);
ATF_TC_HEAD(pd_get_needs_no_cansee, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pd_get_needs_no_cansee, tc)
{
	struct iovec iov[2];
	audit_token_t bypd;
	pid_t looker, cpid;
	int status, pd, err;

	pins_init();
	looker = fork();
	ATF_REQUIRE(looker != -1);
	if (looker == 0) {
		cpid = pdfork(&pd, 0);
		if (cpid == -1)
			_exit(10);
		if (cpid == 0) {
			/* Killed when the looker's descriptor closes. */
			for (;;)
				pause();
		}
		iov[0].iov_base = __DECONST(char *, "path");
		iov[0].iov_len = sizeof("path");
		iov[1].iov_base = __DECONST(char *, "/");
		iov[1].iov_len = sizeof("/");
		if (jail_set(iov, nitems(iov), JAIL_CREATE | JAIL_ATTACH) == -1)
			_exit(11);
		/* By pid the child is out of sight ... */
		err = fails(pin_audit_token_get(-1, cpid, 0, &bypd));
		if (err == ENOSYS)
			_exit(12);
		if (err != ESRCH)
			_exit(13);
		/* ... by its descriptor it is not. */
		if (pin_audit_token_get(pd, 0, 0, &bypd) != 0)
			_exit(errno == ENOSYS ? 12 : 14);
		if (audit_token_to_pid(bypd) != cpid ||
		    audit_token_to_uniqueid(bypd) == 0 ||
		    audit_token_to_jid(bypd) != 0)
			_exit(15);
		_exit(0);
	}
	ATF_REQUIRE_EQ(looker, waitpid(looker, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	switch (WEXITSTATUS(status)) {
	case 0:
		break;
	case 12:
		atf_tc_fail("audit_token_get: %s", strerror(ENOSYS));
	case 13:
		atf_tc_fail("by pid, a process outside the jail was not ESRCH");
	case 14:
		atf_tc_fail("by procdesc, the token was refused");
	case 15:
		atf_tc_fail("by procdesc, the token named another process");
	default:
		atf_tc_fail("looker setup failed: exit %d",
		    WEXITSTATUS(status));
	}
}

/*
 * In capability mode a token check can only match the caller or its
 * descendants: a sandbox cannot probe the process table.  By pid, a token
 * is not handed out at all; by descriptor and for self, it is.
 */
ATF_TC_WITHOUT_HEAD(check_capmode);
ATF_TC_BODY(check_capmode, tc)
{
	audit_token_t self, child, parent, t;
	pid_t box, cpid;
	int status, pd, e1, e2;

	pins_init();
	tok_self(&parent);
	box = fork();
	ATF_REQUIRE(box != -1);
	if (box == 0) {
		if (pin_audit_token_get(-1, 0, 0, &self) != 0)
			_exit(errno == ENOSYS ? 12 : 10);
		cpid = pdfork(&pd, 0);
		if (cpid == -1)
			_exit(10);
		if (cpid == 0) {
			/* Killed when the box's descriptor closes. */
			for (;;)
				pause();
		}
		if (pin_audit_token_get(-1, cpid, 0, &child) != 0)
			_exit(10);
		if (cap_enter() != 0)
			_exit(10);
		if (pin_audit_token_check(&self, 0) != 0)
			_exit(20);
		if (pin_audit_token_check(&child, 0) != 0)
			_exit(21);
		if (fails(pin_audit_token_check(&parent, 0)) != ESRCH)
			_exit(22);
		if (fails(pin_audit_token_check(&parent,
		    AUDIT_TOKEN_MAY_EXEC | AUDIT_TOKEN_MAY_EXIT)) != ESRCH)
			_exit(22);
		if (fails(pin_audit_token_get(-1, getppid(), 0, &t)) !=
		    ECAPMODE)
			_exit(23);
		if (fails(pin_audit_token_get(-1, cpid, 0, &t)) != ECAPMODE)
			_exit(23);
		if (pin_audit_token_get(-1, 0, 0, &t) != 0 ||
		    memcmp(&t, &self, sizeof(t)) != 0)
			_exit(24);
		if (pin_audit_token_get(pd, 0, 0, &t) != 0 ||
		    memcmp(&t, &child, sizeof(t)) != 0)
			_exit(25);
		/* pdopentoken refuses as pdopenpid refuses. */
		e1 = fails(pdopenpid(getppid(), 0));
		e2 = fails(pin_pdopentoken(&parent, 0));
		if (e1 == 0 || e1 != e2)
			_exit(26);
		(void)pdkill(pd, SIGKILL);
		_exit(0);
	}
	ATF_REQUIRE_EQ(box, waitpid(box, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	switch (WEXITSTATUS(status)) {
	case 0:
		break;
	case 12:
		atf_tc_fail("audit_token_get: %s", strerror(ENOSYS));
	case 20:
		atf_tc_fail("capability mode: own token did not match");
	case 21:
		atf_tc_fail("capability mode: descendant did not match");
	case 22:
		atf_tc_fail("capability mode: a non-descendant matched");
	case 23:
		atf_tc_fail("capability mode: get by pid was not ECAPMODE");
	case 24:
		atf_tc_fail("capability mode: own token refused or changed");
	case 25:
		atf_tc_fail("capability mode: get by procdesc refused");
	case 26:
		atf_tc_fail("capability mode: pdopentoken differs from "
		    "pdopenpid");
	default:
		atf_tc_fail("setup failed: exit %d", WEXITSTATUS(status));
	}
}

/* Exact match, AUDIT_TOKEN_MAY_EXEC across an exec, and the zombie. */
ATF_TC_WITHOUT_HEAD(check_exec_and_exit);
ATF_TC_BODY(check_exec_and_exit, tc)
{
	audit_token_t pre, post, gone;
	int out[2], in[2], status;
	pid_t pid;

	pins_init();
	ATF_REQUIRE_EQ(0, pipe(out));
	ATF_REQUIRE_EQ(0, pipe(in));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		char *const argv[] = { __DECONST(char *, "cat"), NULL };
		char c;

		(void)close(in[1]);
		(void)close(out[0]);
		/* Wait for the go, then become cat(1) on the same pipe. */
		if (read(in[0], &c, 1) != 1 || write(out[1], "x", 1) != 1)
			_exit(1);
		if (dup2(in[0], STDIN_FILENO) == -1 ||
		    dup2(out[1], STDOUT_FILENO) == -1)
			_exit(1);
		execv("/bin/cat", argv);
		_exit(1);
	}
	ATF_REQUIRE_EQ(0, close(in[0]));
	ATF_REQUIRE_EQ(0, close(out[1]));
	tok_get(-1, pid, 0, &pre);
	ATF_CHECK_EQ(0, pin_audit_token_check(&pre, 0));
	ATF_CHECK_EQ(0, pin_audit_token_check(&pre, AUDIT_TOKEN_MAY_EXEC));

	/* Let it exec cat(1), and wait for cat to echo a byte. */
	ATF_REQUIRE_EQ(1, write(in[1], "g", 1));
	{
		char c;

		ATF_REQUIRE_EQ(1, read(out[0], &c, 1));
		ATF_REQUIRE_EQ(1, write(in[1], "e", 1));
		ATF_REQUIRE_EQ(1, read(out[0], &c, 1));
		ATF_REQUIRE_EQ('e', c);
	}
	tok_get(-1, pid, 0, &post);
	ATF_CHECK(audit_token_to_execgen(post) != audit_token_to_execgen(pre));
	ATF_CHECK_EQ(ESRCH, fails(pin_audit_token_check(&pre, 0)));
	ATF_CHECK_EQ(0, pin_audit_token_check(&pre, AUDIT_TOKEN_MAY_EXEC));
	ATF_CHECK_EQ(0, pin_audit_token_check(&post, 0));
	/* A token with the right ids but another pid names nobody. */
	gone = post;
	gone.__at_w[3] ^= 0x7fffffff;
	ATF_CHECK_EQ(ESRCH, fails(pin_audit_token_check(&gone,
	    AUDIT_TOKEN_MAY_EXEC | AUDIT_TOKEN_MAY_EXIT)));

	/* End of input: cat exits; it is a zombie until waited for. */
	ATF_REQUIRE_EQ(0, close(in[1]));
	{
		siginfo_t si;

		ATF_REQUIRE_EQ(0, waitid(P_PID, pid, &si, WEXITED | WNOWAIT));
	}
	ATF_CHECK_EQ(ESRCH, fails(pin_audit_token_check(&post, 0)));
	ATF_CHECK_EQ(0, pin_audit_token_check(&post, AUDIT_TOKEN_MAY_EXIT));
	ATF_CHECK_EQ(ESRCH, fails(pin_audit_token_get(-1, pid, 0, &gone)));
	ATF_CHECK_EQ(0, pin_audit_token_get(-1, pid, AUDIT_TOKEN_MAY_EXIT,
	    &gone));
	ATF_CHECK_EQ(0, memcmp(&gone, &post, sizeof(gone)));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK_EQ(ESRCH, fails(pin_audit_token_check(&post,
	    AUDIT_TOKEN_MAY_EXIT)));
	ATF_REQUIRE_EQ(0, close(out[0]));
}

/* pdopentoken(2) opens the process the token names, and only it. */
ATF_TC_WITHOUT_HEAD(pdopentoken_basic);
ATF_TC_BODY(pdopentoken_basic, tc)
{
	audit_token_t tok, stale;
	pid_t pid, got;
	int wfd, pd;

	pins_init();
	pid = child_waiting(&wfd, 0);
	tok_get(-1, pid, 0, &tok);
	pd = pin_pdopentoken(&tok, PD_CLOEXEC);
	ATF_REQUIRE_MSG(pd >= 0, "pdopentoken: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, pdgetpid(pd, &got));
	ATF_CHECK_EQ(pid, got);
	ATF_CHECK_EQ(FD_CLOEXEC, fcntl(pd, F_GETFD) & FD_CLOEXEC);
	ATF_REQUIRE_EQ(0, close(pd));

	stale = tok;
	stale.__at_w[1]++;		/* another execgen */
	ATF_CHECK_EQ(ESRCH, fails(pin_pdopentoken(&stale, 0)));
	stale = tok;
	stale.__at_w[0]++;		/* another process */
	ATF_CHECK_EQ(ESRCH, fails(pin_pdopentoken(&stale, 0)));
	ATF_CHECK_EQ(EINVAL, fails(pin_pdopentoken(&tok, ~0)));
	child_release(pid, wfd, 0);
	ATF_CHECK_EQ(ESRCH, fails(pin_pdopentoken(&tok, 0)));
}

/* Argument checks, in the order the calls make them. */
ATF_TC_WITHOUT_HEAD(bad_arguments);
ATF_TC_BODY(bad_arguments, tc)
{
	audit_token_t tok;
	int fd;

	pins_init();
	tok_self(&tok);
	ATF_CHECK_EQ(EINVAL, fails(pin_audit_token_get(-1, -1, 0, &tok)));
	ATF_CHECK_EQ(EINVAL, fails(pin_audit_token_get(-1, 0, ~0, &tok)));
	ATF_CHECK_EQ(EBADF, fails(pin_audit_token_get(-2, 0, 0, &tok)));
	ATF_CHECK_EQ(EBADF, fails(pin_audit_token_get(INT_MAX, 0, 0, &tok)));
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	/* Not a process descriptor. */
	ATF_CHECK_EQ(EBADF, fails(pin_audit_token_get(fd, 0, 0, &tok)));
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_CHECK_EQ(EFAULT, fails(pin_audit_token_get(-1, 0, 0,
	    (audit_token_t *)1)));
	ATF_CHECK_EQ(EINVAL, fails(pin_audit_token_check(&tok, ~0)));
	ATF_CHECK_EQ(EFAULT, fails(pin_audit_token_check(
	    (audit_token_t *)1, 0)));
	ATF_CHECK_EQ(EFAULT, fails(pin_pdopentoken((audit_token_t *)1, 0)));
	ATF_CHECK_EQ(0, pin_audit_token_check(&tok, 0));
}

/*
 * pid_reuse_check: once a process is gone and its pid is given to
 * another, its token names nobody.  The pid space is lowered (as
 * procdesc_pid_test does) so that a pass over it is a few hundred forks.
 */
static void
sysctl_change(const char *name, int val)
{
	FILE *fp;
	size_t len;
	int old;

	len = sizeof(old);
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, &old, &len, NULL, 0),
	    "%s: %s", name, strerror(errno));
	fp = fopen(name, "wx");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fprintf(fp, "%d\n", old) > 0);
	ATF_REQUIRE_EQ(0, fclose(fp));
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, NULL, NULL, &val,
	    sizeof(val)), "%s: %s", name, strerror(errno));
}

static void
sysctl_restore(const char *name)
{
	FILE *fp;
	int old;

	fp = fopen(name, "r");
	if (fp == NULL)
		return;
	if (fscanf(fp, "%d", &old) != 1 ||
	    sysctlbyname(name, NULL, NULL, &old, sizeof(old)) != 0)
		fprintf(stderr, "%s was not restored\n", name);
	else
		(void)unlink(name);
	(void)fclose(fp);
}

ATF_TC_WITH_CLEANUP(pid_reuse_check);
ATF_TC_HEAD(pid_reuse_check, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pid_reuse_check, tc)
{
	audit_token_t old, cur;
	pid_t want, pid, prev;
	size_t len;
	int mib[3], val, wfd, forks, wraps;

	pins_init();
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PROC;
	len = 0;
	ATF_REQUIRE_EQ(0, sysctl(mib, nitems(mib), NULL, &len, NULL, 0));
	if (len / sizeof(struct kinfo_proc) > PROCS_MOST)
		atf_tc_fail("too many processes for a pid space of %d",
		    PID_LOW);
	len = sizeof(val);
	ATF_REQUIRE_EQ(0, sysctlbyname(RANDOMPID, &val, &len, NULL, 0));
	if (val != 0)
		sysctl_change(RANDOMPID, 0);
	sysctl_change(PID_MAX_SYSCTL, PID_LOW);

	/* The process whose pid will come back, gone. */
	want = child_waiting(&wfd, 0);
	tok_get(-1, want, 0, &old);
	child_release(want, wfd, 0);

	prev = 0;
	wraps = 0;
	for (forks = 0;; forks++) {
		ATF_REQUIRE_MSG(forks < FORKS_MOST && wraps < 4,
		    "pid %d was not handed out again in %d forks", (int)want,
		    forks);
		pid = child_waiting(&wfd, 0);
		if (pid == want)
			break;
		child_release(pid, wfd, 0);
		if (pid < prev)
			wraps++;
		prev = pid;
	}

	/* The pid is live again, and the old token names nobody. */
	tok_get(-1, want, 0, &cur);
	ATF_CHECK(audit_token_to_uniqueid(cur) !=
	    audit_token_to_uniqueid(old));
	ATF_CHECK_EQ(ESRCH, fails(pin_audit_token_check(&old, 0)));
	ATF_CHECK_EQ(ESRCH, fails(pin_audit_token_check(&old,
	    AUDIT_TOKEN_MAY_EXEC | AUDIT_TOKEN_MAY_EXIT)));
	ATF_CHECK_EQ(ESRCH, fails(pin_pdopentoken(&old, 0)));
	ATF_CHECK_EQ(0, pin_audit_token_check(&cur, 0));
	child_release(want, wfd, 0);
}
ATF_TC_CLEANUP(pid_reuse_check, tc)
{
	sysctl_restore(PID_MAX_SYSCTL);
	sysctl_restore(RANDOMPID);
}

/* proc0's kinfo_proc. */
static void
proc0_kinfo(struct kinfo_proc *kp)
{
	kinfo_get(0, kp);
	ATF_REQUIRE_EQ(0, kp->ki_pid);
}

/*
 * Within a boot the ids only grow: every process's uniqueid is above
 * proc0's and shares its offset; children forked one after another get
 * increasing uniqueids and execgens; images exec'd one after another get
 * increasing image ids.
 */
ATF_TC_WITHOUT_HEAD(uniqueid_monotonic_within_boot);
ATF_TC_BODY(uniqueid_monotonic_within_boot, tc)
{
	struct kinfo_proc p0, *kp;
	audit_token_t prev, cur;
	size_t len;
	pid_t pid;
	int mib[3], i, n, wfd;

	pins_init();
	proc0_kinfo(&p0);
	ATF_CHECK_EQ_MSG((uint64_t)0, KP_UNIQUEID(&p0) & (1ULL << 63),
	    "proc0 uniqueid %#jx has bit 63", (uintmax_t)KP_UNIQUEID(&p0));

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PROC;
	len = 0;
	ATF_REQUIRE_EQ(0, sysctl(mib, nitems(mib), NULL, &len, NULL, 0));
	len *= 2;
	kp = malloc(len);
	ATF_REQUIRE(kp != NULL);
	ATF_REQUIRE_EQ(0, sysctl(mib, nitems(mib), kp, &len, NULL, 0));
	n = len / sizeof(*kp);
	for (i = 0; i < n; i++) {
		if (kp[i].ki_pid == 0)
			continue;
		ATF_CHECK_MSG(KP_UNIQUEID(&kp[i]) > KP_UNIQUEID(&p0),
		    "pid %d uniqueid %#jx not above proc0's %#jx",
		    kp[i].ki_pid, (uintmax_t)KP_UNIQUEID(&kp[i]),
		    (uintmax_t)KP_UNIQUEID(&p0));
		ATF_CHECK_MSG(KP_EXECGEN(&kp[i]) > KP_EXECGEN(&p0),
		    "pid %d execgen %#jx not above proc0's %#jx",
		    kp[i].ki_pid, (uintmax_t)KP_EXECGEN(&kp[i]),
		    (uintmax_t)KP_EXECGEN(&p0));
	}
	free(kp);

	tok_self(&prev);
	for (i = 0; i < 16; i++) {
		pid = child_waiting(&wfd, 0);
		tok_get(-1, pid, 0, &cur);
		child_release(pid, wfd, 0);
		ATF_CHECK(audit_token_to_uniqueid(cur) >
		    audit_token_to_uniqueid(prev));
		ATF_CHECK(audit_token_to_execgen(cur) >
		    audit_token_to_execgen(prev));
		prev = cur;
	}
}

/*
 * Two boots start the sequences at different offsets.  The case prints
 * proc0's uniqueid; given the value another boot printed (config variable
 * previous_boot_uniqueid0, decimal), it checks that this boot's differs.
 * A guest reroot (reboot -r) keeps the kernel and its sequences, so the
 * two values must come from two kernel boots.
 */
ATF_TC_WITHOUT_HEAD(uniqueid_start_differs_across_boots);
ATF_TC_BODY(uniqueid_start_differs_across_boots, tc)
{
	struct kinfo_proc p0;
	unsigned long long prev;
	const char *v;
	char *end;

	proc0_kinfo(&p0);
	printf("proc0_uniqueid=%ju proc0_execgen=%ju\n",
	    (uintmax_t)KP_UNIQUEID(&p0), (uintmax_t)KP_EXECGEN(&p0));
	ATF_CHECK_EQ((uint64_t)1, KP_UNIQUEID(&p0) & BOOT_OFFSET_CLEAR);
	if (!atf_tc_has_config_var(tc, "previous_boot_uniqueid0"))
		atf_tc_skip("DEFERRED_SECOND_BOOT: set previous_boot_uniqueid0 "
		    "to the proc0_uniqueid another boot printed");
	v = atf_tc_get_config_var(tc, "previous_boot_uniqueid0");
	errno = 0;
	prev = strtoull(v, &end, 10);
	ATF_REQUIRE_MSG(errno == 0 && *v != '\0' && *end == '\0',
	    "bad previous_boot_uniqueid0 '%s'", v);
	ATF_CHECK_MSG(prev != KP_UNIQUEID(&p0),
	    "proc0 uniqueid %#jx is the other boot's", (uintmax_t)prev);
	/* The offsets themselves differ, not just the first value. */
	ATF_CHECK((prev >> 32) != (KP_UNIQUEID(&p0) >> 32));
}

/* The libc wrappers and libbsm accessors are the calls the pins make. */
ATF_TC_WITHOUT_HEAD(libc_wrappers);
ATF_TC_BODY(libc_wrappers, tc)
{
	audit_token_t pin, tok;
	au_asid_t asid;
	uid_t auid, euid, ruid;
	gid_t egid, rgid;
	pid_t pid, got;
	int pd;

	pins_init();
	tok_self(&pin);
	ATF_REQUIRE_EQ(0, audit_token_get(-1, 0, 0, &tok));
	ATF_CHECK_EQ(0, memcmp(&pin, &tok, sizeof(tok)));
	ATF_CHECK_EQ(0, audit_token_check(&tok, 0));
	ATF_CHECK_EQ((int)(audit_token_to_execgen(tok) & 0xffffffff),
	    audit_token_to_pidversion(tok));
	audit_token_to_au32(tok, &auid, &euid, &egid, &ruid, &rgid, &pid,
	    &asid, NULL);
	ATF_CHECK_EQ(audit_token_to_auid(tok), auid);
	ATF_CHECK_EQ(geteuid(), euid);
	ATF_CHECK_EQ(getegid(), egid);
	ATF_CHECK_EQ(getuid(), ruid);
	ATF_CHECK_EQ(getgid(), rgid);
	ATF_CHECK_EQ(getpid(), pid);
	ATF_CHECK_EQ(audit_token_to_asid(tok), asid);

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		for (;;)
			pause();
	}
	ATF_REQUIRE_EQ(0, audit_token_get(-1, pid, 0, &tok));
	pd = pdopentoken(&tok, PD_CLOEXEC);
	ATF_REQUIRE_MSG(pd >= 0, "pdopentoken: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, pdgetpid(pd, &got));
	ATF_CHECK_EQ(pid, got);
	ATF_REQUIRE_EQ(0, audit_token_get(pd, 0, 0, &pin));
	ATF_CHECK_EQ(0, memcmp(&pin, &tok, sizeof(tok)));
	ATF_REQUIRE_EQ(0, pdkill(pd, SIGKILL));
	ATF_REQUIRE_EQ(pid, waitpid(pid, NULL, 0));
	ATF_REQUIRE_EQ(0, close(pd));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, self_fields);
	ATF_TP_ADD_TC(tp, fork_distinct);
	ATF_TP_ADD_TC(tp, exec_changes_execgen_imageid);
	ATF_TP_ADD_TC(tp, setuid_keeps_ids);
	ATF_TP_ADD_TC(tp, crget_cred_imageid_zero);
	ATF_TP_ADD_TC(tp, pd_get_needs_no_cansee);
	ATF_TP_ADD_TC(tp, check_capmode);
	ATF_TP_ADD_TC(tp, check_exec_and_exit);
	ATF_TP_ADD_TC(tp, pdopentoken_basic);
	ATF_TP_ADD_TC(tp, bad_arguments);
	ATF_TP_ADD_TC(tp, pid_reuse_check);
	ATF_TP_ADD_TC(tp, libc_wrappers);
	ATF_TP_ADD_TC(tp, uniqueid_monotonic_within_boot);
	ATF_TP_ADD_TC(tp, uniqueid_start_differs_across_boots);
	return (atf_no_error());
}
