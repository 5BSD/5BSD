/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The system-call return path for the syscalls stage 1c touched, for an
 * unattached process.
 *
 * Stage 1c-iii-a (D157) maps a stray EDQRESOLVED to EIO right after each
 * sy_call in syscallenter() (subr_syscall.c syscall_dq_stray), before
 * audit, DTrace and sv_set_syscall_retval.  For a process that is not
 * attached nothing may change: the errno of each touched syscall is the
 * same through the libc wrapper and through syscall(2), never EIO, and
 * ktrace(2) records the same error and return value (KTR_SYSRET).
 *
 * Every expected errno below is the pre-1c one (see the other procnet
 * programs for its derivation); the calls run as root, unattached.
 */

#include <sys/param.h>
#include <sys/acct.h>
#include <sys/extattr.h>
#include <sys/jail.h>
#include <sys/ktrace.h>
#include <sys/linker.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <ufs/ufs/quota.h>

#include <elf.h>

#include "procnet_common.h"

#define	NOPATH	"/nonexistent/procnet"

extern char **environ;

static int ctx_stream = -1;	/* an unconnected AF_UNIX stream socket */
static int ctx_dgram = -1;	/* an unconnected AF_UNIX dgram socket */

static struct sockaddr_un ctx_sun;
static socklen_t ctx_sunlen;

static void
ctx_setup(void)
{

	if (ctx_stream < 0) {
		ctx_stream = socket(AF_UNIX, SOCK_STREAM, 0);
		ATF_REQUIRE(ctx_stream >= 0);
	}
	if (ctx_dgram < 0) {
		ctx_dgram = socket(AF_UNIX, SOCK_DGRAM, 0);
		ATF_REQUIRE(ctx_dgram >= 0);
	}
	memset(&ctx_sun, 0, sizeof(ctx_sun));
	ctx_sun.sun_family = AF_UNIX;
	strlcpy(ctx_sun.sun_path, NOPATH ".sock", sizeof(ctx_sun.sun_path));
	ctx_sunlen = (socklen_t)SUN_LEN(&ctx_sun);
	ctx_sun.sun_len = (uint8_t)ctx_sunlen;
}

static bool
securelevel_raised(void)
{
	size_t len;
	int v;

	len = sizeof(v);
	if (sysctlbyname("kern.securelevel", &v, &len, NULL, 0) != 0)
		return (false);
	return (v > 0);
}

/*
 * Each case: the syscall number, the expected errno, and the call through
 * libc and through syscall(2).
 */
struct sccase {
	const char	*name;
	int		 code;
	int		 expected;
	int		(*libc)(void);
	int		(*raw)(void);
};

#define	R(expr)	(PN_ERR(expr))

static int l_socket(void) { int s = socket(255, SOCK_STREAM, 0);
	return (s == -1 ? errno : (close(s), 0)); }
static int r_socket(void) { int s = syscall(SYS_socket, 255, SOCK_STREAM,
	0); return (s == -1 ? errno : (close(s), 0)); }

static int l_socketpair(void) { int sv[2];
	return (R(socketpair(255, SOCK_STREAM, 0, sv))); }
static int r_socketpair(void) { int sv[2];
	return (R(syscall(SYS_socketpair, 255, SOCK_STREAM, 0, sv))); }

static int l_bind(void) { return (R(bind(-1,
	(struct sockaddr *)&ctx_sun, ctx_sunlen))); }
static int r_bind(void) { return (R(syscall(SYS_bind, -1, &ctx_sun,
	ctx_sunlen))); }

static int l_connect(void) { return (R(connect(ctx_stream,
	(struct sockaddr *)&ctx_sun, ctx_sunlen))); }
static int r_connect(void) { return (R(syscall(SYS_connect, ctx_stream,
	&ctx_sun, ctx_sunlen))); }

static int l_bindat(void) { return (R(bindat(1000, ctx_stream,
	(struct sockaddr *)&ctx_sun, ctx_sunlen))); }
static int r_bindat(void) { return (R(syscall(SYS_bindat, 1000,
	ctx_stream, &ctx_sun, ctx_sunlen))); }

static int l_connectat(void) { return (R(connectat(AT_FDCWD, ctx_stream,
	(struct sockaddr *)&ctx_sun, ctx_sunlen))); }
static int r_connectat(void) { return (R(syscall(SYS_connectat, AT_FDCWD,
	ctx_stream, &ctx_sun, ctx_sunlen))); }

static int l_sendto(void) { return (R(sendto(ctx_dgram, "x", 1, 0,
	(struct sockaddr *)&ctx_sun, ctx_sunlen))); }
static int r_sendto(void) { return (R(syscall(SYS_sendto, ctx_dgram, "x",
	1, 0, &ctx_sun, ctx_sunlen))); }

static int l_accept(void) { return (R(accept(ctx_dgram, NULL, NULL))); }
static int r_accept(void) { return (R(syscall(SYS_accept, ctx_dgram, NULL,
	NULL))); }

static int l_unmount(void) { return (R(unmount(NOPATH, 0))); }
static int r_unmount(void) { return (R(syscall(SYS_unmount, NOPATH, 0))); }

static struct iovec three_iov[3] = {
	{ __DECONST(char *, "fstype"), sizeof("fstype") },
	{ __DECONST(char *, "tmpfs"), sizeof("tmpfs") },
	{ __DECONST(char *, "fspath"), sizeof("fspath") },
};
static int l_nmount(void) { return (R(nmount(three_iov, 3, 0))); }
static int r_nmount(void) { return (R(syscall(SYS_nmount, three_iov, 3,
	0))); }

static int l_swapon(void) { return (R(swapon(NOPATH))); }
static int r_swapon(void) { return (R(syscall(SYS_swapon, NOPATH))); }

static int l_swapoff(void) { return (R(swapoff(NOPATH, 0))); }
static int r_swapoff(void) { return (R(syscall(SYS_swapoff, NOPATH, 0))); }

static char quotafile[] = "quota.user";
static int l_quotactl(void) { return (R(quotactl(NOPATH,
	QCMD(Q_QUOTAON, USRQUOTA), 0, quotafile))); }
static int r_quotactl(void) { return (R(syscall(SYS_quotactl, NOPATH,
	QCMD(Q_QUOTAON, USRQUOTA), 0, quotafile))); }

static int l_kldload(void) { return (R(kldload(NOPATH ".ko"))); }
static int r_kldload(void) { return (R(syscall(SYS_kldload,
	NOPATH ".ko"))); }

static int l_ktrace(void) { return (R(ktrace(NOPATH, KTROP_SET,
	KTRFAC_SYSCALL, getpid()))); }
static int r_ktrace(void) { return (R(syscall(SYS_ktrace, NOPATH,
	KTROP_SET, KTRFAC_SYSCALL, getpid()))); }

static int l_acct(void) { return (R(acct(NOPATH))); }
static int r_acct(void) { return (R(syscall(SYS_acct, NOPATH))); }

static int l_extattrctl(void) { return (R(extattrctl(NOPATH, 1, NULL,
	EXTATTR_NAMESPACE_USER, "x"))); }
static int r_extattrctl(void) { return (R(syscall(SYS_extattrctl, NOPATH,
	1, NULL, EXTATTR_NAMESPACE_USER, "x"))); }

static struct setcred sc_wc;
static int l_setcred(void) { return (R(setcred(0, &sc_wc,
	sizeof(sc_wc) - 1))); }
static int r_setcred(void) { return (R(syscall(SYS_setcred, 0, &sc_wc,
	sizeof(sc_wc) - 1))); }

static int l_jail_attach(void) { return (R(jail_attach(999999))); }
static int r_jail_attach(void) { return (R(syscall(SYS_jail_attach,
	999999))); }

static struct iovec jail_iov[6] = {
	{ __DECONST(char *, "name"), sizeof("name") },
	{ __DECONST(char *, "procnet_sc"), sizeof("procnet_sc") },
	{ __DECONST(char *, "path"), sizeof("path") },
	{ __DECONST(char *, NOPATH), sizeof(NOPATH) },
	{ __DECONST(char *, "persist"), sizeof("persist") },
	{ NULL, 0 },
};
static int l_jail_set(void) { return (R(jail_set(jail_iov, 6,
	JAIL_CREATE))); }
static int r_jail_set(void) { return (R(syscall(SYS_jail_set, jail_iov,
	6, JAIL_CREATE))); }

static char *exec_argv[] = { __DECONST(char *, "x"), NULL };
static int l_execve(void) { return (R(execve(NOPATH, exec_argv,
	environ))); }
static int r_execve(void) { return (R(syscall(SYS_execve, NOPATH,
	exec_argv, environ))); }

static int l_mac_set_proc(void) { return (R(syscall(SYS___mac_set_proc,
	(void *)(uintptr_t)8))); }
static int r_mac_set_proc(void) { return (R(__syscall(SYS___mac_set_proc,
	(void *)(uintptr_t)8))); }

static int l_setgroups(void) { gid_t g = 0;
	return (R(setgroups(-1, &g))); }
static int r_setgroups(void) { gid_t g = 0;
	return (R(syscall(SYS_setgroups, -1, &g))); }

static const struct sccase sccases[] = {
	{ "socket", SYS_socket, EAFNOSUPPORT, l_socket, r_socket },
	{ "socketpair", SYS_socketpair, EAFNOSUPPORT, l_socketpair,
	    r_socketpair },
	{ "bind", SYS_bind, EBADF, l_bind, r_bind },
	{ "connect", SYS_connect, ENOENT, l_connect, r_connect },
	/* An absolute name: the dirfd (1000, not open) is never used. */
	{ "bindat", SYS_bindat, ENOENT, l_bindat, r_bindat },
	{ "connectat", SYS_connectat, ENOENT, l_connectat, r_connectat },
	{ "sendto", SYS_sendto, ENOENT, l_sendto, r_sendto },
	{ "accept", SYS_accept, EINVAL, l_accept, r_accept },
	{ "unmount", SYS_unmount, EINVAL, l_unmount, r_unmount },
	{ "nmount", SYS_nmount, EINVAL, l_nmount, r_nmount },
	{ "swapon", SYS_swapon, ENOENT, l_swapon, r_swapon },
	{ "swapoff", SYS_swapoff, ENOENT, l_swapoff, r_swapoff },
	{ "quotactl", SYS_quotactl, ENOENT, l_quotactl, r_quotactl },
	{ "kldload", SYS_kldload, ENOENT, l_kldload, r_kldload },
	{ "ktrace", SYS_ktrace, ENOENT, l_ktrace, r_ktrace },
	{ "acct", SYS_acct, ENOENT, l_acct, r_acct },
	{ "extattrctl", SYS_extattrctl, ENOENT, l_extattrctl, r_extattrctl },
	{ "setcred", SYS_setcred, EINVAL, l_setcred, r_setcred },
	{ "jail_attach", SYS_jail_attach, EINVAL, l_jail_attach,
	    r_jail_attach },
	{ "jail_set", SYS_jail_set, ENOENT, l_jail_set, r_jail_set },
	{ "execve", SYS_execve, ENOENT, l_execve, r_execve },
	{ "__mac_set_proc", SYS___mac_set_proc, EFAULT, l_mac_set_proc,
	    r_mac_set_proc },
	{ "setgroups", SYS_setgroups, EINVAL, l_setgroups, r_setgroups },
};

static int
expected_for(const struct sccase *c)
{

	/* kldload(2) is EPERM first with a raised securelevel. */
	if (c->code == SYS_kldload && securelevel_raised())
		return (EPERM);
	return (c->expected);
}

ATF_TC(errno_libc_and_syscall);
ATF_TC_HEAD(errno_libc_and_syscall, tc)
{
	atf_tc_set_md_var(tc, "descr", "the touched syscalls fail with the "
	    "pre-1c errno through libc and through syscall(2)/__syscall(2), "
	    "never EIO");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(errno_libc_and_syscall, tc)
{
	const struct sccase *c;
	size_t i;
	int el, er, want;

	ctx_setup();
	for (i = 0; i < nitems(sccases); i++) {
		c = &sccases[i];
		want = expected_for(c);
		el = c->libc();
		er = c->raw();
		ATF_CHECK_MSG(el == want, "%s via libc: expected %s, got %s",
		    c->name, pn_errname(want), pn_errname(el));
		ATF_CHECK_MSG(er == want, "%s via syscall(2): expected %s, "
		    "got %s", c->name, pn_errname(want), pn_errname(er));
		ATF_CHECK_MSG(el != EIO && er != EIO, "%s: EIO", c->name);
	}
}

ATF_TC(success_values);
ATF_TC_HEAD(success_values, tc)
{
	atf_tc_set_md_var(tc, "descr", "successful socket(2)/socketpair(2)/"
	    "accept(2) through syscall(2) return the lowest free descriptor "
	    "and fill their arguments");
}
ATF_TC_BODY(success_values, tc)
{
	struct sockaddr_un sun;
	int s, sv[2], lowest, l, c, a;

	lowest = dup(0);
	ATF_REQUIRE(lowest >= 0);
	close(lowest);
	s = syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
	ATF_CHECK_EQ(lowest, s);
	close(s);
	sv[0] = sv[1] = -1;
	ATF_REQUIRE(syscall(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	ATF_CHECK_EQ(lowest, sv[0]);
	ATF_CHECK(sv[1] > sv[0]);
	close(sv[0]);
	close(sv[1]);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, "sc.sock", sizeof(sun.sun_path));
	sun.sun_len = (uint8_t)SUN_LEN(&sun);
	l = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(l >= 0);
	ATF_REQUIRE(syscall(SYS_bind, l, &sun, sun.sun_len) == 0);
	ATF_REQUIRE(listen(l, 1) == 0);
	c = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(c >= 0);
	ATF_REQUIRE(syscall(SYS_connect, c, &sun, sun.sun_len) == 0);
	lowest = dup(0);
	close(lowest);
	a = syscall(SYS_accept, l, NULL, NULL);
	ATF_CHECK_EQ(lowest, a);
	close(a);
	close(c);
	close(l);
}

/* --- KTR_SYSRET ------------------------------------------------------ */

struct sysret_seen {
	int	code;
	int	error;
	long	retval;
};

static int
ktrace_run(void *arg __unused)
{
	size_t i;
	int s;

	ctx_setup();
	if (ktrace("ktrace.out", KTROP_SET, KTRFAC_SYSCALL | KTRFAC_SYSRET,
	    getpid()) != 0)
		return (errno);
	for (i = 0; i < nitems(sccases); i++)
		(void)sccases[i].raw();
	s = syscall(SYS_socket, AF_UNIX, SOCK_DGRAM, 0);
	if (ktrace(NULL, KTROP_CLEAR, KTRFAC_SYSCALL | KTRFAC_SYSRET,
	    getpid()) != 0)
		return (errno);
	/* Report the descriptor the successful socket(2) returned. */
	return (s >= 0 && s < PN_X_BASE ? s : PN_X_SETUP);
}

ATF_TC(ktrace_sysret);
ATF_TC_HEAD(ktrace_sysret, tc)
{
	atf_tc_set_md_var(tc, "descr", "ktrace(2) records for each touched "
	    "syscall a KTR_SYSRET with the pre-1c errno, and for a "
	    "successful socket(2) error 0 and the descriptor");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ktrace_sysret, tc)
{
	struct ktr_header h;
	struct ktr_sysret sr;
	struct sysret_seen seen[256];
	unsigned char buf[4096];
	size_t i, j, nseen;
	ssize_t n;
	int fd, sockfd, want;
	bool found, sockok;

	pn_writefile("ktrace.out", "", 0, 0600);
	sockfd = pn_child(ktrace_run, NULL, 0, 0);
	ATF_REQUIRE_MSG(sockfd < PN_X_BASE, "child: %s", pn_errname(sockfd));

	fd = open("ktrace.out", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	nseen = 0;
	sockok = false;
	for (;;) {
		n = read(fd, &h, sizeof(h));
		if (n == 0)
			break;
		ATF_REQUIRE(n == (ssize_t)sizeof(h));
		ATF_REQUIRE(h.ktr_len >= 0 && (size_t)h.ktr_len <= sizeof(buf));
		ATF_REQUIRE(read(fd, buf, (size_t)h.ktr_len) == h.ktr_len);
		if ((h.ktr_type & ~KTR_TYPE) != KTR_SYSRET)
			continue;
		ATF_REQUIRE((size_t)h.ktr_len >= sizeof(sr));
		memcpy(&sr, buf, sizeof(sr));
		if (sr.ktr_code == SYS_socket && sr.ktr_error == 0 &&
		    sr.ktr_retval == sockfd)
			sockok = true;
		if (nseen < nitems(seen)) {
			seen[nseen].code = sr.ktr_code;
			seen[nseen].error = sr.ktr_error;
			seen[nseen].retval = (long)sr.ktr_retval;
			nseen++;
		}
	}
	close(fd);
	ATF_CHECK_MSG(sockok, "no KTR_SYSRET for socket(2) returning %d",
	    sockfd);
	/*
	 * The cases ran in order: match each with the next record of its
	 * code.  Other records share codes (the KTROP_SET's own ktrace(2)
	 * before them, the successful socket(2) after them).
	 */
	for (i = 0, j = 0; i < nitems(sccases); i++) {
		want = expected_for(&sccases[i]);
		found = false;
		for (; j < nseen; j++) {
			if (seen[j].code != sccases[i].code)
				continue;
			found = true;
			ATF_CHECK_MSG(seen[j].error == want, "%s: KTR_SYSRET "
			    "error %d, expected %d", sccases[i].name,
			    seen[j].error, want);
			j++;
			break;
		}
		ATF_CHECK_MSG(found, "%s: no KTR_SYSRET", sccases[i].name);
	}
}

/* --- ktrace(2) closes its trace file after proctree_lock ------------- */

/*
 * The ELF image activator calls uprintf(), which takes proctree_lock, with
 * the image vnode locked: vnode -> proctree_lock.  ktrace(2) used to close
 * a trace file whose last reference ktrops() dropped (a KTROP_SET to
 * another file, a KTROP_CLEAR) with proctree_lock held:
 * proctree_lock -> vnode.  Run both in one boot, on one file system, and
 * read WITNESS's list of reversals when it is compiled in and running.
 */

/* A copy of the dynamic helper whose PT_INTERP is 1 byte long. */
static void
lor_bad_interp(const atf_tc_t *tc, const char *to)
{
	char helper[PATH_MAX];
	Elf64_Ehdr eh;
	Elf64_Phdr ph;
	off_t off;
	int fd, i;
	bool found;

	pn_srcfile(tc, "procnet_helper", helper, sizeof(helper));
	pn_copyfile(helper, to, 0755);
	fd = open(to, O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pread(fd, &eh, sizeof(eh), 0) == (ssize_t)sizeof(eh));
	ATF_REQUIRE(memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0);
	if (eh.e_ident[EI_CLASS] != ELFCLASS64)
		atf_tc_skip("not an ELF64 helper");
	found = false;
	for (i = 0; i < eh.e_phnum; i++) {
		off = (off_t)(eh.e_phoff + (size_t)i * eh.e_phentsize);
		ATF_REQUIRE(pread(fd, &ph, sizeof(ph), off) ==
		    (ssize_t)sizeof(ph));
		if (ph.p_type != PT_INTERP)
			continue;
		found = true;
		ph.p_filesz = 1;	/* get_interp(): "Invalid PT_INTERP" */
		ATF_REQUIRE(pwrite(fd, &ph, sizeof(ph), off) ==
		    (ssize_t)sizeof(ph));
	}
	ATF_REQUIRE_MSG(found, "the helper has no PT_INTERP");
	ATF_REQUIRE(close(fd) == 0);
}

static int
lor_exec(void *arg)
{
	char *argv[] = { __DECONST(char *, "img"), NULL };

	(void)execve(arg, argv, environ);
	return (errno);
}

static int
lor_ktrace(void *arg __unused)
{
	int facs;

	facs = KTRFAC_SYSCALL | KTRFAC_SYSRET;
	if (ktrace("ktrace.a", KTROP_SET, facs, getpid()) != 0)
		return (errno);
	(void)getppid();
	/* ktrops() (by ktrsetchildren()) drops the last ktrace.a reference. */
	if (ktrace("ktrace.b", KTROP_SET | KTRFLAG_DESCEND, facs,
	    getpid()) != 0)
		return (errno);
	(void)getppid();
	/* And ktrops() the last ktrace.b reference. */
	if (ktrace(NULL, KTROP_CLEAR, facs, getpid()) != 0)
		return (errno);
	return (0);
}

/* A successful KTR_SYSRET for getppid(2) in a trace file. */
static bool
lor_has_getppid(const char *path)
{
	struct ktr_header h;
	struct ktr_sysret sr;
	unsigned char buf[4096];
	ssize_t n;
	int fd;
	bool found;

	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "open %s: %s", path, strerror(errno));
	found = false;
	while ((n = read(fd, &h, sizeof(h))) != 0) {
		ATF_REQUIRE(n == (ssize_t)sizeof(h));
		ATF_REQUIRE(h.ktr_len >= 0 && (size_t)h.ktr_len <= sizeof(buf));
		ATF_REQUIRE(read(fd, buf, (size_t)h.ktr_len) == h.ktr_len);
		if ((h.ktr_type & ~KTR_TYPE) != KTR_SYSRET ||
		    (size_t)h.ktr_len < sizeof(sr))
			continue;
		memcpy(&sr, buf, sizeof(sr));
		if (sr.ktr_code == SYS_getppid && sr.ktr_error == 0)
			found = true;
	}
	ATF_REQUIRE(close(fd) == 0);
	return (found);
}

ATF_TC(ktrace_close_lor);
ATF_TC_HEAD(ktrace_close_lor, tc)
{
	atf_tc_set_md_var(tc, "descr", "ktrace(2) closes a released trace "
	    "file without proctree_lock: no WITNESS reversal against the "
	    "vnode -> proctree_lock order of uprintf() in ELF exec");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ktrace_close_lor, tc)
{
	struct statfs sf;
	char img[PATH_MAX], pair[2][128], *bad;
	size_t len;
	int error, i;

	/* vnode -> proctree_lock. */
	pn_cwdpath("img", img, sizeof(img));
	lor_bad_interp(tc, img);
	error = pn_child(lor_exec, img, 0, 0);
	ATF_REQUIRE_MSG(error == ENOEXEC, "execve: %s", pn_errname(error));

	/* proctree_lock -> vnode, without the fix. */
	pn_writefile("ktrace.a", "", 0, 0600);
	pn_writefile("ktrace.b", "", 0, 0600);
	error = pn_child(lor_ktrace, NULL, 0, 0);
	ATF_REQUIRE_MSG(error == 0, "ktrace: %s", pn_errname(error));
	ATF_CHECK_MSG(lor_has_getppid("ktrace.a"), "ktrace.a: no getppid");
	ATF_CHECK_MSG(lor_has_getppid("ktrace.b"), "ktrace.b: no getppid");

	/* Without WITNESS the cycle ran, unchecked. */
	if (sysctlbyname("debug.witness.badstacks", NULL, &len, NULL,
	    0) != 0)
		return;
	/* WITNESS names a vnode lock after its file system type. */
	ATF_REQUIRE(statfs(".", &sf) == 0);
	len += 65536;
	bad = malloc(len);
	ATF_REQUIRE(bad != NULL);
	ATF_REQUIRE_MSG(sysctlbyname("debug.witness.badstacks", bad, &len,
	    NULL, 0) == 0, "debug.witness.badstacks: %s", strerror(errno));
	snprintf(pair[0], sizeof(pair[0]),
	    "between \"proctree\"(sx) and \"%s\"(lockmgr)", sf.f_fstypename);
	snprintf(pair[1], sizeof(pair[1]),
	    "between \"%s\"(lockmgr) and \"proctree\"(sx)", sf.f_fstypename);
	for (i = 0; i < 2; i++)
		ATF_CHECK_MSG(strstr(bad, pair[i]) == NULL, "WITNESS: lock "
		    "order reversal %s", pair[i]);
	free(bad);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, errno_libc_and_syscall);
	ATF_TP_ADD_TC(tp, success_values);
	ATF_TP_ADD_TC(tp, ktrace_sysret);
	ATF_TP_ADD_TC(tp, ktrace_close_lor);
	return (atf_no_error());
}
