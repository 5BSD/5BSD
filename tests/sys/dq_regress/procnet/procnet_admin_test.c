/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Administrative calls that take paths, of unattached processes, as
 * before stage 1c.
 *
 * Stage 1c wraps each of these in a kernel-consumer intent for ATTACHED
 * callers: nmount(2) path-valued options and fspath, unmount(2) (where an
 * attached caller loses the fallback to the literal mount-on name),
 * swapon(2)/swapoff(2), quotactl(2), kldload(2) with a path, ktrace(2),
 * acct(2), extattrctl(2) and md(4) MDIOCATTACH.  For other callers each
 * must succeed and fail as before, as root and unprivileged.
 *
 * Expectations from 3f330ee172d: vfs_mount.c vfs_buildopts(),
 * vfs_donmount(), vfs_domount(), kern_unmount(); null_vfsops.c
 * nullfs_mount(); swap_pager.c kern_swapon_priority(), kern_swapoff();
 * vfs_syscalls.c sys_quotactl(); kern_linker.c kldload_common() and
 * linker_load_file() (an unloadable existing file is ENOEXEC);
 * kern_ktrace.c sys_ktrace(); kern_acct.c sys_acct(); vfs_extattr.c
 * sys_extattrctl() (the filename is looked up before the path); md.c
 * mdcreate_vnode().
 */

#include <sys/param.h>
#include <sys/acct.h>
#include <sys/extattr.h>
#include <sys/ioctl.h>
#include <sys/linker.h>
#include <sys/mdioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/ktrace.h>

#include <ufs/ufs/quota.h>

#include "procnet_common.h"

/* --- nmount(2) helpers ----------------------------------------------- */

struct pn_iov {
	struct iovec	iov[32];
	int		n;
};

/* len (size_t)-1: strlen + 1 (the NUL included). */
static void
iov_add(struct pn_iov *v, const char *name, size_t nlen, const void *val,
    size_t vlen)
{

	ATF_REQUIRE(v->n + 2 <= (int)nitems(v->iov));
	v->iov[v->n].iov_base = __DECONST(char *, name);
	v->iov[v->n].iov_len = nlen == (size_t)-1 ? strlen(name) + 1 : nlen;
	v->n++;
	v->iov[v->n].iov_base = __DECONST(void *, val);
	if (val == NULL)
		v->iov[v->n].iov_len = 0;
	else
		v->iov[v->n].iov_len = vlen == (size_t)-1 ?
		    strlen(val) + 1 : vlen;
	v->n++;
}

#define	OPT(v, name, val)	iov_add((v), (name), (size_t)-1, (val), \
				    (size_t)-1)

static int
mount_tmpfs(const char *fspath)
{
	struct pn_iov v = { .n = 0 };

	OPT(&v, "fstype", "tmpfs");
	OPT(&v, "fspath", fspath);
	OPT(&v, "size", "4m");
	return (PN_ERR(nmount(v.iov, (u_int)v.n, 0)));
}

static int
mount_nullfs(const char *target, const char *fspath)
{
	struct pn_iov v = { .n = 0 };

	OPT(&v, "fstype", "nullfs");
	OPT(&v, "fspath", fspath);
	OPT(&v, "target", target);
	return (PN_ERR(nmount(v.iov, (u_int)v.n, 0)));
}

static void
require_tmpfs(const char *fspath)
{
	int e;

	e = mount_tmpfs(fspath);
	if (e == ENODEV || e == ENOENT)
		atf_tc_skip("tmpfs not available: %s", strerror(e));
	ATF_REQUIRE_MSG(e == 0, "mount tmpfs on %s: %s", fspath, strerror(e));
}

static bool
usermount_off(void)
{
	size_t len;
	int v;

	len = sizeof(v);
	if (sysctlbyname("vfs.usermount", &v, &len, NULL, 0) != 0)
		return (true);
	return (v == 0);
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

/* Unmount a work-directory mount point if a body left it mounted. */
static void
cleanup_unmount(const char *name)
{
	char p[PATH_MAX];

	if (realpath(name, p) != NULL)
		(void)unmount(p, MNT_FORCE);
}

/* --- mount, unmount -------------------------------------------------- */

ATF_TC_WITH_CLEANUP(mount_tmpfs_basic);
ATF_TC_HEAD(mount_tmpfs_basic, tc)
{
	atf_tc_set_md_var(tc, "descr", "nmount(2) tmpfs and unmount(2) by "
	    "absolute and relative path; f_mntonname is the global path");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mount_tmpfs_basic, tc)
{
	char mnt[PATH_MAX];
	struct statfs sf;

	ATF_REQUIRE(mkdir("m", 0755) == 0);
	ATF_REQUIRE(realpath("m", mnt) != NULL);
	require_tmpfs(mnt);
	ATF_REQUIRE(statfs("m", &sf) == 0);
	ATF_CHECK_STREQ("tmpfs", sf.f_fstypename);
	ATF_CHECK_STREQ(mnt, sf.f_mntonname);
	PN_EXPECT(0, unmount(mnt, 0));
	ATF_REQUIRE(statfs("m", &sf) == 0);
	ATF_CHECK(strcmp(sf.f_fstypename, "tmpfs") != 0 ||
	    strcmp(sf.f_mntonname, mnt) != 0);

	/* Relative fspath, relative unmount. */
	PN_EXPECT(0, mount_tmpfs("m"));
	ATF_REQUIRE(statfs("m", &sf) == 0);
	ATF_CHECK_STREQ(mnt, sf.f_mntonname);
	PN_EXPECT(0, unmount("m", 0));
}
ATF_TC_CLEANUP(mount_tmpfs_basic, tc)
{
	cleanup_unmount("m");
}

ATF_TC_WITH_CLEANUP(unmount_fallback);
ATF_TC_HEAD(unmount_fallback, tc)
{
	atf_tc_set_md_var(tc, "descr", "unmount(2) of a path that no longer "
	    "resolves falls back to matching the literal mount-on name "
	    "(kern_unmount); an unknown name is EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unmount_fallback, tc)
{
	char old[PATH_MAX], cwd[PATH_MAX], bogus[PATH_MAX + 16];
	struct statfs sf;

	ATF_REQUIRE(realpath(".", cwd) != NULL);
	ATF_REQUIRE(mkdir("X", 0755) == 0);
	ATF_REQUIRE(mkdir("X/mnt", 0755) == 0);
	snprintf(old, sizeof(old), "%s/X/mnt", cwd);
	require_tmpfs(old);
	/* The mount-on name no longer resolves. */
	ATF_REQUIRE_MSG(rename("X", "Y") == 0, "rename: %s", strerror(errno));
	ATF_REQUIRE(statfs("Y/mnt", &sf) == 0);
	ATF_CHECK_STREQ(old, sf.f_mntonname);
	ATF_REQUIRE(access(old, F_OK) != 0);
	/* By the stale literal name: found through the fallback. */
	PN_EXPECT(0, unmount(old, 0));
	ATF_REQUIRE(statfs("Y/mnt", &sf) == 0);
	ATF_CHECK(strcmp(sf.f_mntonname, old) != 0);

	/* Neither resolving nor mounted: EINVAL (not ENOENT). */
	snprintf(bogus, sizeof(bogus), "%s/nowhere/procnet", cwd);
	PN_EXPECT(EINVAL, unmount(bogus, 0));
	/* Resolving but not a mount point: EINVAL. */
	PN_EXPECT(EINVAL, unmount("Y/mnt", 0));
	PN_EXPECT(EINVAL, unmount("Y", 0));
}
ATF_TC_CLEANUP(unmount_fallback, tc)
{
	cleanup_unmount("Y/mnt");
	cleanup_unmount("X/mnt");
}

ATF_TC(unmount_errors);
ATF_TC_HEAD(unmount_errors, tc)
{
	atf_tc_set_md_var(tc, "descr", "unmount(2): MNT_BYFSID with a "
	    "malformed id EINVAL, an unknown one ENOENT; a name over MNAMELEN "
	    "ENAMETOOLONG; unprivileged EPERM before anything else");
	atf_tc_set_md_var(tc, "require.user", "root");
}

static int
unmount_unpriv(void *arg __unused)
{

	if (unmount("/nonexistent/procnet", 0) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (unmount("FSID:1:2", MNT_BYFSID) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC_BODY(unmount_errors, tc)
{
	char *longname;

	PN_EXPECT(EINVAL, unmount("garbage", MNT_BYFSID));
	PN_EXPECT(ENOENT, unmount("FSID:123456789:987654321", MNT_BYFSID));
	longname = malloc(MNAMELEN + 64);
	ATF_REQUIRE(longname != NULL);
	memset(longname, 'a', MNAMELEN + 32);
	longname[MNAMELEN + 32] = '\0';
	/* copyinstr() into MNAMELEN bytes. */
	PN_EXPECT(ENAMETOOLONG, unmount(longname, 0));
	free(longname);
	if (usermount_off())
		PN_CHECK_ERRNO(0, pn_child(unmount_unpriv, NULL, PN_UID,
		    PN_GID), "unprivileged unmount");
}

ATF_TC_WITH_CLEANUP(mount_unpriv);
ATF_TC_HEAD(mount_unpriv, tc)
{
	atf_tc_set_md_var(tc, "descr", "with vfs.usermount 0 an unprivileged "
	    "nmount(2) is EPERM before the lookup, unmount(2) of root's "
	    "mount EPERM, and the mount stays");
	atf_tc_set_md_var(tc, "require.user", "root");
}

static int
mount_unpriv_child(void *arg)
{
	const char *mnt = arg;

	if (mount_tmpfs("/nonexistent/procnet") != EPERM)
		return (PN_X_WRONG);
	if (mount_tmpfs(mnt) != EPERM)
		return (PN_X_WRONG);
	if (unmount(mnt, 0) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC_BODY(mount_unpriv, tc)
{
	char mnt[PATH_MAX];
	struct statfs sf;

	if (!usermount_off())
		atf_tc_skip("vfs.usermount is set");
	ATF_REQUIRE(mkdir("m", 0777) == 0);
	ATF_REQUIRE(realpath("m", mnt) != NULL);
	require_tmpfs(mnt);
	PN_CHECK_ERRNO(0, pn_child(mount_unpriv_child, mnt, PN_UID, PN_GID),
	    "unprivileged mount/unmount");
	ATF_REQUIRE(statfs(mnt, &sf) == 0);
	ATF_CHECK_STREQ(mnt, sf.f_mntonname);
	PN_EXPECT(0, unmount(mnt, 0));
}
ATF_TC_CLEANUP(mount_unpriv, tc)
{
	cleanup_unmount("m");
}

ATF_TC_WITH_CLEANUP(nullfs_relative);
ATF_TC_HEAD(nullfs_relative, tc)
{
	atf_tc_set_md_var(tc, "descr", "nullfs with a relative target and "
	    "fspath resolves both from the cwd; f_mntfromname is the target "
	    "as given; a missing target ENOENT, a file target over a "
	    "directory EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nullfs_relative, tc)
{
	char mnt[PATH_MAX];
	struct statfs sf;
	struct stat st;
	int e;

	ATF_REQUIRE(mkdir("src", 0755) == 0);
	ATF_REQUIRE(mkdir("mnt", 0755) == 0);
	pn_writefile("src/file", "n", 1, 0644);
	ATF_REQUIRE(realpath("mnt", mnt) != NULL);
	e = mount_nullfs("src", "mnt");
	if (e == ENODEV)
		atf_tc_skip("nullfs not available");
	ATF_REQUIRE_MSG(e == 0, "mount nullfs: %s", strerror(e));
	ATF_CHECK(stat("mnt/file", &st) == 0);
	ATF_REQUIRE(statfs("mnt", &sf) == 0);
	ATF_CHECK_STREQ("nullfs", sf.f_fstypename);
	ATF_CHECK_STREQ(mnt, sf.f_mntonname);
	/* vfs_mountedfrom(mp, target): the string as given (to confirm). */
	ATF_CHECK_STREQ("src", sf.f_mntfromname);
	PN_EXPECT(0, unmount("mnt", 0));

	pn_writefile("afile", "x", 1, 0644);
	PN_CHECK_ERRNO(ENOENT, mount_nullfs("missing", "mnt"),
	    "missing target");
	/* A file target over a directory: types differ, EINVAL. */
	e = mount_nullfs("afile", "mnt");
	PN_CHECK_ERRNO(EINVAL, e, "file target over a directory");
	if (e == 0)
		(void)unmount("mnt", 0);
	PN_CHECK_ERRNO(ENOENT, mount_nullfs("src", "missing"),
	    "missing fspath");
	PN_CHECK_ERRNO(ENOTDIR, mount_nullfs("src", "afile/x"),
	    "fspath through a file");
}
ATF_TC_CLEANUP(nullfs_relative, tc)
{
	cleanup_unmount("mnt");
}

ATF_TC_WITH_CLEANUP(nmount_unterminated);
ATF_TC_HEAD(nmount_unterminated, tc)
{
	atf_tc_set_md_var(tc, "descr", "nmount(2) strings without their NUL: "
	    "an option name, fstype, fspath and nullfs target are EINVAL "
	    "(with errmsg for fstype/fspath); a tmpfs \"from\" value is not "
	    "looked at and the mount succeeds (only an ATTACHED caller "
	    "gets EINVAL for it)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nmount_unterminated, tc)
{
	struct pn_iov v;
	char mnt[PATH_MAX], errmsg[256];
	struct statfs sf;
	int e;

	ATF_REQUIRE(mkdir("m", 0755) == 0);
	ATF_REQUIRE(mkdir("src", 0755) == 0);
	ATF_REQUIRE(realpath("m", mnt) != NULL);
	require_tmpfs(mnt);
	ATF_REQUIRE(unmount(mnt, 0) == 0);

	/* An option name without NUL. */
	memset(&v, 0, sizeof(v));
	OPT(&v, "fstype", "tmpfs");
	OPT(&v, "fspath", mnt);
	iov_add(&v, "size", 4, "4m", (size_t)-1);
	PN_EXPECT(EINVAL, nmount(v.iov, (u_int)v.n, 0));

	/* fstype without NUL, with errmsg. */
	memset(&v, 0, sizeof(v));
	memset(errmsg, 0, sizeof(errmsg));
	iov_add(&v, "fstype", (size_t)-1, "tmpfs", 5);
	OPT(&v, "fspath", mnt);
	iov_add(&v, "errmsg", (size_t)-1, errmsg, sizeof(errmsg));
	PN_EXPECT(EINVAL, nmount(v.iov, (u_int)v.n, 0));
	ATF_CHECK_STREQ("Invalid fstype", errmsg);

	/* fspath without NUL. */
	memset(&v, 0, sizeof(v));
	memset(errmsg, 0, sizeof(errmsg));
	OPT(&v, "fstype", "tmpfs");
	iov_add(&v, "fspath", (size_t)-1, mnt, strlen(mnt));
	iov_add(&v, "errmsg", (size_t)-1, errmsg, sizeof(errmsg));
	PN_EXPECT(EINVAL, nmount(v.iov, (u_int)v.n, 0));
	ATF_CHECK_STREQ("Invalid fspath", errmsg);

	/* No fstype at all. */
	memset(&v, 0, sizeof(v));
	OPT(&v, "fspath", mnt);
	PN_EXPECT(EINVAL, nmount(v.iov, (u_int)v.n, 0));

	/* An odd number of iovecs. */
	memset(&v, 0, sizeof(v));
	OPT(&v, "fstype", "tmpfs");
	OPT(&v, "fspath", mnt);
	PN_EXPECT(EINVAL, nmount(v.iov, (u_int)v.n - 1, 0));

	/* nullfs target without NUL. */
	memset(&v, 0, sizeof(v));
	OPT(&v, "fstype", "nullfs");
	OPT(&v, "fspath", mnt);
	iov_add(&v, "target", (size_t)-1, "src", 3);
	e = PN_ERR(nmount(v.iov, (u_int)v.n, 0));
	if (e != ENODEV)
		PN_CHECK_ERRNO(EINVAL, e, "nullfs target without NUL");
	if (e == 0)
		(void)unmount(mnt, 0);

	/*
	 * tmpfs "from" without NUL: no filesystem code reads it, so an
	 * unattached caller mounts (to be confirmed on the pre-1c kernel).
	 */
	memset(&v, 0, sizeof(v));
	OPT(&v, "fstype", "tmpfs");
	OPT(&v, "fspath", mnt);
	iov_add(&v, "from", (size_t)-1, "tmpfs", 5);
	PN_EXPECT(0, nmount(v.iov, (u_int)v.n, 0));
	ATF_REQUIRE(statfs(mnt, &sf) == 0);
	ATF_CHECK_STREQ("tmpfs", sf.f_fstypename);
	ATF_CHECK_STREQ(mnt, sf.f_mntonname);
	PN_EXPECT(0, unmount(mnt, 0));
}
ATF_TC_CLEANUP(nmount_unterminated, tc)
{
	cleanup_unmount("m");
}

/* --- md(4) and swap -------------------------------------------------- */

static int
md_attach(const char *file, unsigned options, off_t size, unsigned *unitp)
{
	struct md_ioctl mdio;
	int fd, e;

	fd = open("/dev/" MDCTL_NAME, O_RDWR);
	if (fd < 0)
		atf_tc_skip("/dev/" MDCTL_NAME ": %s", strerror(errno));
	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_type = MD_VNODE;
	mdio.md_file = __DECONST(char *, file);
	mdio.md_options = MD_AUTOUNIT | options;
	/* As mdconfig(8): the size of the file (at least a sector). */
	mdio.md_mediasize = size;
	e = PN_ERR(ioctl(fd, MDIOCATTACH, &mdio));
	if (e == 0 && unitp != NULL)
		*unitp = mdio.md_unit;
	close(fd);
	return (e);
}

static int
md_query(unsigned unit, char *file, size_t len)
{
	struct md_ioctl mdio;
	char buf[MAXPATHLEN];
	int fd, e;

	fd = open("/dev/" MDCTL_NAME, O_RDWR);
	ATF_REQUIRE(fd >= 0);
	memset(&mdio, 0, sizeof(mdio));
	memset(buf, 0, sizeof(buf));
	mdio.md_version = MDIOVERSION;
	mdio.md_unit = unit;
	mdio.md_file = buf;
	e = PN_ERR(ioctl(fd, MDIOCQUERY, &mdio));
	close(fd);
	strlcpy(file, buf, len);
	return (e);
}

static void
md_detach(unsigned unit)
{
	struct md_ioctl mdio;
	int fd;

	fd = open("/dev/" MDCTL_NAME, O_RDWR);
	if (fd < 0)
		return;
	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_unit = unit;
	mdio.md_options = MD_FORCE;
	(void)ioctl(fd, MDIOCDETACH, &mdio);
	close(fd);
}

static void
make_backing(const char *name, off_t size)
{
	int fd;

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(ftruncate(fd, size) == 0);
	close(fd);
}

#define	MD_UNIT_FILE	"procnet_md_unit"
#define	MB		(1024 * 1024)

static void
save_unit(unsigned unit)
{
	FILE *f;

	f = fopen(MD_UNIT_FILE, "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%u\n", unit);
	fclose(f);
}

static void
cleanup_md(void)
{
	char dev[64];
	unsigned unit;
	FILE *f;

	f = fopen(MD_UNIT_FILE, "r");
	if (f == NULL)
		return;
	if (fscanf(f, "%u", &unit) == 1) {
		snprintf(dev, sizeof(dev), "/dev/md%u", unit);
		(void)swapoff(dev, SWAPOFF_FORCE);
		md_detach(unit);
	}
	fclose(f);
}

ATF_TC_WITH_CLEANUP(md_attach_vnode);
ATF_TC_HEAD(md_attach_vnode, tc)
{
	atf_tc_set_md_var(tc, "descr", "MDIOCATTACH of a vnode: a relative "
	    "file resolves from the caller's cwd (MDIOCQUERY reports it as "
	    "given); missing ENOENT; a directory EISDIR read-write and "
	    "EINVAL read-only (vn_open before the type test)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(md_attach_vnode, tc)
{
	char file[MAXPATHLEN];
	unsigned unit;

	make_backing("backing", 1024 * 1024);
	ATF_REQUIRE(mkdir("dir", 0755) == 0);
	PN_CHECK_ERRNO(0, md_attach("backing", 0, MB, &unit), "relative file");
	save_unit(unit);
	PN_CHECK_ERRNO(0, md_query(unit, file, sizeof(file)), "query");
	/* sc->s_vnode.file: the string copied in (to be confirmed). */
	ATF_CHECK_STREQ("backing", file);
	md_detach(unit);
	(void)unlink(MD_UNIT_FILE);

	PN_CHECK_ERRNO(ENOENT, md_attach("missing", 0, MB, NULL), "missing");
	PN_CHECK_ERRNO(ENOENT, md_attach("/nonexistent/procnet", 0, MB, NULL),
	    "missing absolute");
	PN_CHECK_ERRNO(EISDIR, md_attach("dir", 0, MB, NULL), "directory");
	PN_CHECK_ERRNO(EINVAL, md_attach("dir", MD_READONLY, MB, NULL),
	    "directory read-only");
	PN_CHECK_ERRNO(ENOTDIR, md_attach("backing/x", 0, MB, NULL),
	    "through a file");
}
ATF_TC_CLEANUP(md_attach_vnode, tc)
{
	cleanup_md();
}

ATF_TC_WITH_CLEANUP(swap_md_vnode);
ATF_TC_HEAD(swap_md_vnode, tc)
{
	atf_tc_set_md_var(tc, "descr", "swapon(2)/swapoff(2) of an md vnode "
	    "device: on, EBUSY again, off, EINVAL again; a regular file and "
	    "a directory are ENOTBLK, a missing name ENOENT; bad swapoff "
	    "flags EINVAL; unprivileged EPERM first");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}

static int
swap_unpriv(void *arg)
{
	const char *dev = arg;

	if (swapon("/nonexistent/procnet") != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (swapon(dev) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (swapoff(dev, 0) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	/* priv_check comes before the flags test. */
	if (swapoff(dev, 0x100) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC_BODY(swap_md_vnode, tc)
{
	char dev[64];
	unsigned unit;

	make_backing("swapfile", 16 * 1024 * 1024);
	ATF_REQUIRE(mkdir("dir", 0755) == 0);
	PN_CHECK_ERRNO(0, md_attach("swapfile", 0, 16 * MB, &unit),
	    "md attach");
	save_unit(unit);
	snprintf(dev, sizeof(dev), "/dev/md%u", unit);

	PN_CHECK_ERRNO(0, pn_child(swap_unpriv, dev, PN_UID, PN_GID),
	    "unprivileged swap calls");
	PN_EXPECT(ENOENT, swapon("/nonexistent/procnet"));
	PN_EXPECT(ENOTBLK, swapon("swapfile"));
	PN_EXPECT(ENOTBLK, swapon("dir"));
	PN_EXPECT(EINVAL, swapoff(dev, 0x100));
	PN_EXPECT(EINVAL, swapoff(dev, 0));
	PN_EXPECT(0, swapon(dev));
	PN_EXPECT(EBUSY, swapon(dev));
	PN_EXPECT(EINVAL, swapoff("swapfile", 0));
	PN_EXPECT(ENOENT, swapoff("/nonexistent/procnet", 0));
	PN_EXPECT(0, swapoff(dev, 0));
	PN_EXPECT(EINVAL, swapoff(dev, 0));
	md_detach(unit);
	(void)unlink(MD_UNIT_FILE);
}
ATF_TC_CLEANUP(swap_md_vnode, tc)
{
	cleanup_md();
}

/* --- quotactl(2), extattrctl(2) -------------------------------------- */

ATF_TC_WITH_CLEANUP(quotactl_paths);
ATF_TC_HEAD(quotactl_paths, tc)
{
	atf_tc_set_md_var(tc, "descr", "quotactl(2) Q_QUOTAON: a missing path "
	    "ENOENT; on tmpfs (no quotas) EOPNOTSUPP, unprivileged too");
	atf_tc_set_md_var(tc, "require.user", "root");
}

static int
quota_unpriv(void *arg)
{
	char qf[] = "/nonexistent/quota.user";

	return (PN_ERR(quotactl(arg, QCMD(Q_QUOTAON, USRQUOTA), 0, qf)));
}

ATF_TC_BODY(quotactl_paths, tc)
{
	char mnt[PATH_MAX];
	char qf[] = "quota.user";

	PN_EXPECT(ENOENT, quotactl("/nonexistent/procnet",
	    QCMD(Q_QUOTAON, USRQUOTA), 0, qf));
	ATF_REQUIRE(mkdir("m", 0755) == 0);
	ATF_REQUIRE(realpath("m", mnt) != NULL);
	require_tmpfs(mnt);
	PN_EXPECT(EOPNOTSUPP, quotactl(mnt, QCMD(Q_QUOTAON, USRQUOTA), 0,
	    qf));
	PN_EXPECT(EOPNOTSUPP, quotactl(mnt, QCMD(Q_QUOTAOFF, USRQUOTA), 0,
	    NULL));
	PN_CHECK_ERRNO(EOPNOTSUPP, pn_child(quota_unpriv, mnt, PN_UID,
	    PN_GID), "unprivileged Q_QUOTAON on tmpfs");
	PN_EXPECT(0, unmount(mnt, 0));
}
ATF_TC_CLEANUP(quotactl_paths, tc)
{
	cleanup_unmount("m");
}

ATF_TC_WITH_CLEANUP(extattrctl_paths);
ATF_TC_HEAD(extattrctl_paths, tc)
{
	atf_tc_set_md_var(tc, "descr", "extattrctl(2): an over-long attribute "
	    "name ENAMETOOLONG first; the filename is looked up before the "
	    "path (ENOENT); on tmpfs EOPNOTSUPP with and without a filename, "
	    "unprivileged too");
	atf_tc_set_md_var(tc, "require.user", "root");
}

static int
extattrctl_unpriv(void *arg)
{

	return (PN_ERR(extattrctl(arg, 1, NULL, EXTATTR_NAMESPACE_USER,
	    "procnet")));
}

ATF_TC_BODY(extattrctl_paths, tc)
{
	char mnt[PATH_MAX], file[PATH_MAX];
	char longname[EXTATTR_MAXNAMELEN + 16];

	ATF_REQUIRE(mkdir("m", 0755) == 0);
	ATF_REQUIRE(realpath("m", mnt) != NULL);
	require_tmpfs(mnt);
	snprintf(file, sizeof(file), "%s/backing", mnt);
	pn_writefile(file, "", 0, 0644);

	memset(longname, 'a', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	PN_EXPECT(ENAMETOOLONG, extattrctl("/nonexistent/procnet", 1,
	    "/nonexistent/file", EXTATTR_NAMESPACE_USER, longname));
	/* The filename first: ENOENT although the path exists. */
	PN_EXPECT(ENOENT, extattrctl(mnt, 1, "/nonexistent/file",
	    EXTATTR_NAMESPACE_USER, "procnet"));
	PN_EXPECT(ENOENT, extattrctl("/nonexistent/procnet", 1, file,
	    EXTATTR_NAMESPACE_USER, "procnet"));
	PN_EXPECT(ENOENT, extattrctl("/nonexistent/procnet", 1, NULL,
	    EXTATTR_NAMESPACE_USER, "procnet"));
	PN_EXPECT(EOPNOTSUPP, extattrctl(mnt, 1, NULL,
	    EXTATTR_NAMESPACE_USER, "procnet"));
	PN_EXPECT(EOPNOTSUPP, extattrctl(mnt, 1, file,
	    EXTATTR_NAMESPACE_USER, "procnet"));
	PN_EXPECT(EOPNOTSUPP, extattrctl(mnt, 12345, NULL, 99, NULL));
	PN_CHECK_ERRNO(EOPNOTSUPP, pn_child(extattrctl_unpriv, mnt, PN_UID,
	    PN_GID), "unprivileged extattrctl on tmpfs");
	PN_EXPECT(0, unmount(mnt, 0));
}
ATF_TC_CLEANUP(extattrctl_paths, tc)
{
	cleanup_unmount("m");
}

/* --- kldload(2) ------------------------------------------------------ */

static int
kld_unpriv(void *arg __unused)
{

	if (kldload("/nonexistent/procnet.ko") != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (kldload("procnet_no_such_module") != -1 || errno != EPERM)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC(kldload_failures);
ATF_TC_HEAD(kldload_failures, tc)
{
	atf_tc_set_md_var(tc, "descr", "kldload(2) failures only: a missing "
	    "path or module ENOENT, an existing non-module file by relative "
	    "path ENOEXEC; unprivileged EPERM before the lookup");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kldload_failures, tc)
{

	if (securelevel_raised())
		atf_tc_skip("kern.securelevel > 0");
	PN_EXPECT(ENOENT, kldload("/nonexistent/procnet.ko"));
	PN_EXPECT(ENOENT, kldload("./procnet_missing.ko"));
	PN_EXPECT(ENOENT, kldload("procnet_no_such_module"));
	PN_EXPECT(ENOENT, kldload("procnet_no_such_file.ko"));
	pn_writefile("garbage.ko", "\177ELF-not-really", 15, 0644);
	/*
	 * linker_load_file(): found but unloadable is ENOEXEC (also when
	 * a capability-plane MAC check refuses it).
	 */
	PN_EXPECT(ENOEXEC, kldload("./garbage.ko"));
	PN_CHECK_ERRNO(0, pn_child(kld_unpriv, NULL, PN_UID, PN_GID),
	    "unprivileged kldload");
}

/* --- ktrace(2), acct(2) ---------------------------------------------- */

static int
ktrace_child(void *arg __unused)
{
	struct stat st;

	if (ktrace("trace.out", KTROP_SET, KTRFAC_SYSCALL | KTRFAC_SYSRET,
	    getpid()) != 0)
		return (errno);
	(void)getppid();
	if (ktrace(NULL, KTROP_CLEAR, KTRFAC_SYSCALL | KTRFAC_SYSRET,
	    getpid()) != 0)
		return (errno);
	if (stat("trace.out", &st) != 0 || st.st_size == 0)
		return (PN_X_WRONG);
	return (0);
}

static int
ktrace_unpriv(void *arg)
{
	const char *file = arg;

	/* Root's init: EPERM. */
	if (ktrace(file, KTROP_SET, KTRFAC_SYSCALL, 1) != -1 ||
	    errno != EPERM)
		return (PN_X_WRONG);
	/* Itself, into a file it may write: allowed. */
	if (ktrace(file, KTROP_SET, KTRFAC_SYSCALL, getpid()) != 0)
		return (errno);
	if (ktrace(NULL, KTROP_CLEAR, KTRFAC_SYSCALL, getpid()) != 0)
		return (errno);
	return (0);
}

ATF_TC(ktrace_file);
ATF_TC_HEAD(ktrace_file, tc)
{
	atf_tc_set_md_var(tc, "descr", "ktrace(2) to a file: works and "
	    "writes; facs 0 EINVAL first; missing ENOENT; a symlink EMLINK "
	    "(O_NOFOLLOW); a directory EISDIR; a device EACCES; unknown pid "
	    "ESRCH; unprivileged EPERM on another's process");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ktrace_file, tc)
{
	char dir[PATH_MAX], file[PATH_MAX];
	int fd;

	pn_writefile("trace.out", "", 0, 0644);
	ATF_REQUIRE(symlink("trace.out", "trace.link") == 0);
	ATF_REQUIRE(mkdir("dir", 0755) == 0);
	PN_CHECK_ERRNO(0, pn_child(ktrace_child, NULL, 0, 0),
	    "ktrace to a file");

	PN_EXPECT(EINVAL, ktrace("/nonexistent/procnet", KTROP_SET, 0,
	    getpid()));
	PN_EXPECT(ENOENT, ktrace("/nonexistent/procnet", KTROP_SET,
	    KTRFAC_SYSCALL, getpid()));
	PN_EXPECT(EMLINK, ktrace("trace.link", KTROP_SET, KTRFAC_SYSCALL,
	    getpid()));
	PN_EXPECT(EISDIR, ktrace("dir", KTROP_SET, KTRFAC_SYSCALL,
	    getpid()));
	PN_EXPECT(EACCES, ktrace("/dev/null", KTROP_SET, KTRFAC_SYSCALL,
	    getpid()));
	PN_EXPECT(ESRCH, ktrace("trace.out", KTROP_SET, KTRFAC_SYSCALL,
	    999999));
	/* Clearing by file works for a file nobody traces to. */
	PN_EXPECT(0, ktrace("trace.out", KTROP_CLEARFILE, 0, 0));

	pn_pubdir("ktrace_unpriv", dir, sizeof(dir));
	snprintf(file, sizeof(file), "%s/t", dir);
	fd = open(file, O_CREAT | O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(fchown(fd, PN_UID, PN_GID) == 0);
	close(fd);
	PN_CHECK_ERRNO(0, pn_child(ktrace_unpriv, file, PN_UID, PN_GID),
	    "unprivileged ktrace");
	pn_pubdir_remove("ktrace_unpriv");
}

static int
acct_unpriv(void *arg __unused)
{

	if (acct(NULL) != -1 || errno != EPERM)
		return (PN_X_WRONG);
	if (acct("/nonexistent/procnet") != -1 || errno != EPERM)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC(acct_paths);
ATF_TC_HEAD(acct_paths, tc)
{
	atf_tc_set_md_var(tc, "descr", "acct(2): a regular file is accepted "
	    "and NULL turns accounting off; missing ENOENT; a symlink "
	    "EMLINK (NOFOLLOW); a directory EISDIR; a device EACCES; "
	    "unprivileged EPERM first");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acct_paths, tc)
{
	size_t len;
	int configured;

	pn_writefile("acct.out", "", 0, 0644);
	ATF_REQUIRE(symlink("acct.out", "acct.link") == 0);
	ATF_REQUIRE(mkdir("dir", 0755) == 0);
	PN_CHECK_ERRNO(0, pn_child(acct_unpriv, NULL, PN_UID, PN_GID),
	    "unprivileged acct");
	PN_EXPECT(ENOENT, acct("/nonexistent/procnet"));
	PN_EXPECT(EMLINK, acct("acct.link"));
	PN_EXPECT(EISDIR, acct("dir"));
	PN_EXPECT(EACCES, acct("/dev/null"));

	len = sizeof(configured);
	if (sysctlbyname("kern.acct_configured", &configured, &len, NULL,
	    0) != 0 || configured != 0)
		atf_tc_skip("accounting is already on; not switching it");
	PN_EXPECT(0, acct("acct.out"));
	PN_EXPECT(0, acct(NULL));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mount_tmpfs_basic);
	ATF_TP_ADD_TC(tp, unmount_fallback);
	ATF_TP_ADD_TC(tp, unmount_errors);
	ATF_TP_ADD_TC(tp, mount_unpriv);
	ATF_TP_ADD_TC(tp, nullfs_relative);
	ATF_TP_ADD_TC(tp, nmount_unterminated);
	ATF_TP_ADD_TC(tp, md_attach_vnode);
	ATF_TP_ADD_TC(tp, swap_md_vnode);
	ATF_TP_ADD_TC(tp, quotactl_paths);
	ATF_TP_ADD_TC(tp, extattrctl_paths);
	ATF_TP_ADD_TC(tp, kldload_failures);
	ATF_TP_ADD_TC(tp, ktrace_file);
	ATF_TP_ADD_TC(tp, acct_paths);
	return (atf_no_error());
}
