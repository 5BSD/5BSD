/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Access times recorded while a UFS file system is suspended through
 * /dev/ufssuspend, as growfs(8) suspends a mounted file system.
 *
 * A read and an fstat(2) during the suspension leave the inode marked
 * IN_LAZYACCESS.  close(2) waits for the resume (vn_close1() starts a write
 * on the mount), so a program that reads a file and closes it during the
 * suspension (the devd growfs_postboot service script did) drops its last
 * use of the vnode as the file system resumes, while the resume runs
 * process_deferred_inactive().  That turns IN_LAZYACCESS into IN_MODIFIED,
 * and for a vnode no longer in use it must write the inode then: once the
 * last hold is dropped the vnode leaves the mount's lazy list, and an
 * INVARIANTS kernel asserts in ffs_unlock_debug() ("modified vnode not on
 * lazy list") at the next unlock of the vnode while it is in use, such as
 * the one that ends the next open(2) of the file.  A stat(2) does not show
 * it: its vput() releases the last use, and the inactivation that follows
 * writes the inode before the unlock.
 *
 * The readers are child processes: the suspending process must not close a
 * file on the suspended file system itself, or it would wait for its own
 * resume.  The defect needs a reader's last close to finish before the
 * resume's walk reaches the file, so closed_at_resume holds the walk with
 * the test kernel's resume hold (options FFS_TEST_HOOKS, GENERIC-TEST:
 * debug.ffs.test_hold_*) until every reader has exited, then lets it go
 * on.  Each case makes its own md(4)-backed UFS file system.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <ufs/ffs/fs.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	MD_FILE		"md.unit"
#define	MNT		"mnt"
#define	NREAD		32

static void
run(const char *cmd)
{
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
}

static void
path_of(char *buf, size_t len, const char *prefix, int i)
{
	snprintf(buf, len, "%s/%s%d", MNT, prefix, i);
}

static void
make_file(const char *path)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "create %s: %s", path, strerror(errno));
	ATF_REQUIRE_EQ(5, write(fd, "data\n", 5));
	ATF_REQUIRE_EQ(0, close(fd));
}

/*
 * The defect closed_at_resume pins shows only as
 * the INVARIANTS assertion in ffs_unlock_debug(): without INVARIANTS the
 * inode is left modified off the lazy list, which nothing it checks sees.
 */
static void
require_invariants(void)
{
	int on;
	size_t len;

	len = sizeof(on);
	if (sysctlbyname("kern.features.invariants", &on, &len, NULL, 0) != 0 ||
	    on == 0)
		atf_tc_skip("detects the defect only through an INVARIANTS "
		    "assertion; the kernel has no kern.features.invariants");
}

/* A soft updates UFS on a swap-backed md(4) device, with NREAD files. */
static void
fixture(void)
{
	char cmd[256], path[64], unit[32];
	FILE *fp;
	int i;

	fp = popen("mdconfig -a -t swap -s 64m", "r");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fgets(unit, sizeof(unit), fp) != NULL);
	ATF_REQUIRE_EQ(0, pclose(fp));
	unit[strcspn(unit, "\n")] = '\0';
	fp = fopen(MD_FILE, "w");
	ATF_REQUIRE(fp != NULL);
	fprintf(fp, "%s\n", unit);
	ATF_REQUIRE_EQ(0, fclose(fp));

	snprintf(cmd, sizeof(cmd), "newfs -U /dev/%s >/dev/null", unit);
	run(cmd);
	ATF_REQUIRE_EQ(0, mkdir(MNT, 0755));
	snprintf(cmd, sizeof(cmd), "mount /dev/%s %s", unit, MNT);
	run(cmd);
	for (i = 0; i < NREAD; i++) {
		path_of(path, sizeof(path), "f", i);
		make_file(path);
	}
	sync();
}

static void
cleanup(void)
{
	char cmd[256], unit[32];
	FILE *fp;

	(void)system("umount -f " MNT " 2>/dev/null");
	fp = fopen(MD_FILE, "r");
	if (fp == NULL)
		return;
	if (fgets(unit, sizeof(unit), fp) != NULL) {
		unit[strcspn(unit, "\n")] = '\0';
		snprintf(cmd, sizeof(cmd), "mdconfig -d -u %s", unit);
		(void)system(cmd);
	}
	fclose(fp);
}

/* Suspend writes to the file system mounted on MNT; returns the device fd. */
static int
suspend(void)
{
	struct statfs sfs;
	int fd;

	ATF_REQUIRE_EQ(0, statfs(MNT, &sfs));
	fd = open(_PATH_UFSSUSPEND, O_RDWR);
	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", _PATH_UFSSUSPEND, strerror(errno));
	ATF_REQUIRE_MSG(ioctl(fd, UFSSUSPEND, &sfs.f_fsid) == 0,
	    "UFSSUSPEND: %s", strerror(errno));
	return (fd);
}

static void
resume(int fd)
{
	ATF_REQUIRE_MSG(ioctl(fd, UFSRESUME) == 0, "UFSRESUME: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ(0, close(fd));
}

/* Read the file and fstat(2) it: the access time is noted lazily. */
static int
access_file(int fd)
{
	struct stat sb;
	char c;

	if (lseek(fd, 0, SEEK_SET) != 0 || read(fd, &c, 1) != 1 ||
	    fstat(fd, &sb) != 0)
		return (-1);
	return (0);
}

/* The resume hold of the test kernel. */
static void
require_resume_hold(void)
{
	size_t len;

	len = 0;
	if (sysctlbyname("debug.ffs.test_hold_fsid", NULL, &len, NULL, 0) != 0)
		atf_tc_skip("DEFERRED_TEST_KERNEL_TIER: needs the resume hold of "
		    "the test kernel (GENERIC-TEST, debug.ffs.test_hold_fsid)");
}

/* Arm the hold for fsid, or disarm it with an all-zero one. */
static int
resume_hold_arm(const fsid_t *fsid)
{

	return (sysctlbyname("debug.ffs.test_hold_fsid", NULL, NULL, fsid,
	    sizeof(*fsid)));
}

static void
resume_hold_set(const char *name, int value)
{

	ATF_REQUIRE_MSG(sysctlbyname(name, NULL, NULL, &value,
	    sizeof(value)) == 0, "%s: %s", name, strerror(errno));
}

/*
 * Start a child per read file that opens, reads and fstats it, says so on
 * the pipe, and closes it (the close waits for the resume).  Returns once
 * every reader has read during the suspension.
 */
static void
start_readers(pid_t *pids)
{
	char c, path[64];
	int fd, i, p[2];

	ATF_REQUIRE_EQ(0, pipe(p));
	for (i = 0; i < NREAD; i++) {
		path_of(path, sizeof(path), "f", i);
		pids[i] = fork();
		ATF_REQUIRE(pids[i] >= 0);
		if (pids[i] == 0) {
			close(p[0]);
			fd = open(path, O_RDONLY);
			if (fd < 0 || access_file(fd) != 0)
				_exit(1);
			c = 'r';
			if (write(p[1], &c, 1) != 1)
				_exit(2);
			_exit(close(fd) == 0 ? 0 : 3);
		}
	}
	close(p[1]);
	for (i = 0; i < NREAD; i++)
		ATF_REQUIRE_MSG(read(p[0], &c, 1) == 1,
		    "reader %d did not read during the suspension", i);
	close(p[0]);
}

static void
reap_readers(pid_t *pids)
{
	int i, status;

	for (i = 0; i < NREAD; i++) {
		ATF_REQUIRE_EQ(pids[i], waitpid(pids[i], &status, 0));
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "reader %d: status %#x", i, status);
	}
}

/*
 * Use every read file.  The open(2) comes first: it unlocks the vnode while
 * holding a use of it, where an unwritten modified inode is caught.  A
 * stat(2) first would write the inode at the vput() of its last use.
 */
static void
use_files(void)
{
	struct stat sb;
	char buf[8], path[64];
	int fd, i;

	for (i = 0; i < NREAD; i++) {
		path_of(path, sizeof(path), "f", i);
		fd = open(path, O_RDONLY);
		ATF_REQUIRE_MSG(fd >= 0, "open %s: %s", path, strerror(errno));
		ATF_CHECK_EQ(5, read(fd, buf, sizeof(buf)));
		ATF_REQUIRE_EQ(0, close(fd));
		ATF_REQUIRE_EQ_MSG(0, stat(path, &sb), "stat %s: %s", path,
		    strerror(errno));
		ATF_CHECK_EQ(5, sb.st_size);
	}
}

/* Unmount, check the file system read-only, and mount it again. */
static void
remount_and_check(void)
{
	char cmd[256], unit[32];
	FILE *fp;

	fp = fopen(MD_FILE, "r");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fgets(unit, sizeof(unit), fp) != NULL);
	fclose(fp);
	unit[strcspn(unit, "\n")] = '\0';
	run("umount " MNT);
	snprintf(cmd, sizeof(cmd), "fsck_ffs -n /dev/%s >/dev/null", unit);
	run(cmd);
	snprintf(cmd, sizeof(cmd), "mount /dev/%s %s", unit, MNT);
	run(cmd);
	use_files();
}

/* The resume, from a helper thread of the suspending process. */
struct resumer {
	pthread_t	thread;
	int		fd;
	int		error;
};

static void *
resumer_main(void *arg)
{
	struct resumer *r = arg;

	r->error = ioctl(r->fd, UFSRESUME) == 0 ? 0 : errno;
	return (NULL);
}

ATF_TC_WITH_CLEANUP(closed_at_resume);
ATF_TC_HEAD(closed_at_resume, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "files read during a suspension and closed before the resume's "
	    "walk reaches them can be used after the resume");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "mdconfig newfs fsck_ffs");
}
ATF_TC_BODY(closed_at_resume, tc)
{
	struct statfs sfs;
	struct resumer r;
	pid_t pids[NREAD];
	int sfd;

	require_invariants();
	require_resume_hold();
	fixture();
	ATF_REQUIRE_EQ(0, statfs(MNT, &sfs));
	ATF_REQUIRE_MSG(resume_hold_arm(&sfs.f_fsid) == 0,
	    "debug.ffs.test_hold_fsid: %s", strerror(errno));
	sfd = suspend();
	start_readers(pids);
	/*
	 * Resume from a helper thread (UFSSUSPEND wanted a single-threaded
	 * process; the resume belongs to the suspending one): the resume
	 * holds its caller at the walk.  It wakes the readers, whose closes
	 * finish while the walk is held; the hold is released only after
	 * every reader has been reaped, so the walk always meets their
	 * closed files.
	 */
	r.fd = sfd;
	r.error = -1;
	ATF_REQUIRE_EQ(0, pthread_create(&r.thread, NULL, resumer_main, &r));
	resume_hold_set("debug.ffs.test_hold_wait", 1);
	reap_readers(pids);
	resume_hold_set("debug.ffs.test_hold_release", 1);
	ATF_REQUIRE_EQ(0, pthread_join(r.thread, NULL));
	ATF_REQUIRE_MSG(r.error == 0, "UFSRESUME: %s", strerror(r.error));
	ATF_REQUIRE_EQ(0, close(sfd));
	use_files();
	remount_and_check();
}
ATF_TC_CLEANUP(closed_at_resume, tc)
{
	static const fsid_t zero;
	int value;

	(void)tc;
	/* Disarm, and let a walk still held go on before the unmount. */
	(void)resume_hold_arm(&zero);
	value = 1;
	(void)sysctlbyname("debug.ffs.test_hold_release", NULL, NULL, &value,
	    sizeof(value));
	cleanup();
}

ATF_TC_WITH_CLEANUP(open_across_resume);
ATF_TC_HEAD(open_across_resume, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a file read during a suspension and still open after it can be "
	    "used after the resume");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "mdconfig newfs fsck_ffs");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(open_across_resume, tc)
{
	char path[64];
	int fd, sfd;

	fixture();
	path_of(path, sizeof(path), "f", 0);
	/* Open before the suspension: UFSSUSPEND refuses writers only. */
	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "open: %s", strerror(errno));
	sfd = suspend();
	ATF_REQUIRE_EQ(0, access_file(fd));
	resume(sfd);
	ATF_REQUIRE_EQ(0, access_file(fd));
	ATF_REQUIRE_EQ(0, close(fd));
	use_files();
	remount_and_check();
}
ATF_TC_CLEANUP(open_across_resume, tc)
{
	(void)tc;
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, closed_at_resume);
	ATF_TP_ADD_TC(tp, open_across_resume);
	return (atf_no_error());
}
