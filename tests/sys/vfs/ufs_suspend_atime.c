/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Access times recorded while a UFS file system is suspended through
 * /dev/ufssuspend (as growfs(8) suspends a mounted file system).
 *
 * A read and an fstat(2) during the suspension leave the inode marked
 * IN_LAZYACCESS.  At resume, process_deferred_inactive() turns that into
 * IN_MODIFIED.  If the file is no longer open, its vnode must be written
 * then: once the last hold is dropped the vnode leaves the mount's lazy
 * list, and an INVARIANTS kernel asserts in ffs_unlock_debug() ("modified
 * vnode not on lazy list") at the next unlock of the vnode, for example
 * the lookup of the file by the next open(2) or stat(2).
 *
 * Each case makes its own md(4)-backed UFS file system.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <ufs/ffs/fs.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	MD_FILE		"md.unit"
#define	MNT		"mnt"
#define	FILE_PATH	MNT "/f"

static void
run(const char *cmd)
{
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
}

/* Make and mount a soft-updates UFS on a swap-backed md(4) device. */
static void
fixture(void)
{
	char cmd[256], unit[32];
	FILE *fp;
	int fd;

	fp = popen("mdconfig -a -t swap -s 32m", "r");
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

	fd = open(FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "create: %s", strerror(errno));
	ATF_REQUIRE_EQ(5, write(fd, "data\n", 5));
	ATF_REQUIRE_EQ(0, fsync(fd));
	ATF_REQUIRE_EQ(0, close(fd));
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
static void
access_file(int fd)
{
	struct stat sb;
	char c;

	ATF_REQUIRE_EQ(0, lseek(fd, 0, SEEK_SET));
	ATF_REQUIRE_EQ(1, read(fd, &c, 1));
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
}

/* Use the file after the resume: lookups lock and unlock its vnode. */
static void
use_after_resume(void)
{
	struct stat sb;
	char buf[8];
	int fd;

	ATF_REQUIRE_EQ_MSG(0, stat(FILE_PATH, &sb), "stat: %s",
	    strerror(errno));
	ATF_CHECK_EQ(5, sb.st_size);
	fd = open(FILE_PATH, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "open: %s", strerror(errno));
	ATF_CHECK_EQ(5, read(fd, buf, sizeof(buf)));
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_REQUIRE_EQ(0, stat(FILE_PATH, &sb));
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
	use_after_resume();
}

ATF_TC_WITH_CLEANUP(access_closed_during_suspension);
ATF_TC_HEAD(access_closed_during_suspension, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a file read and closed while the file system is suspended "
	    "can be used after the resume");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "mdconfig newfs fsck_ffs");
}
ATF_TC_BODY(access_closed_during_suspension, tc)
{
	int fd, sfd;

	fixture();
	sfd = suspend();
	fd = open(FILE_PATH, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "open: %s", strerror(errno));
	access_file(fd);
	/* The last close: the vnode is unused when the file system resumes. */
	ATF_REQUIRE_EQ(0, close(fd));
	resume(sfd);
	use_after_resume();
	remount_and_check();
}
ATF_TC_CLEANUP(access_closed_during_suspension, tc)
{
	(void)tc;
	cleanup();
}

ATF_TC_WITH_CLEANUP(access_open_across_resume);
ATF_TC_HEAD(access_open_across_resume, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a file read while the file system is suspended and still open "
	    "at the resume can be used after it");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "mdconfig newfs fsck_ffs");
}
ATF_TC_BODY(access_open_across_resume, tc)
{
	int fd, sfd;

	fixture();
	/* Open before the suspension: UFSSUSPEND refuses writers only. */
	fd = open(FILE_PATH, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "open: %s", strerror(errno));
	sfd = suspend();
	access_file(fd);
	resume(sfd);
	access_file(fd);
	ATF_REQUIRE_EQ(0, close(fd));
	use_after_resume();
	remount_and_check();
}
ATF_TC_CLEANUP(access_open_across_resume, tc)
{
	(void)tc;
	cleanup();
}

ATF_TC_WITH_CLEANUP(repeated_suspensions);
ATF_TC_HEAD(repeated_suspensions, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "files read during repeated suspensions can be used after each "
	    "resume");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "mdconfig newfs fsck_ffs");
}
ATF_TC_BODY(repeated_suspensions, tc)
{
	int fd, i, sfd;

	fixture();
	for (i = 0; i < 20; i++) {
		sfd = suspend();
		fd = open(FILE_PATH, O_RDONLY);
		ATF_REQUIRE_MSG(fd >= 0, "open: %s", strerror(errno));
		access_file(fd);
		ATF_REQUIRE_EQ(0, close(fd));
		fd = open(MNT, O_RDONLY | O_DIRECTORY);
		ATF_REQUIRE_MSG(fd >= 0, "open dir: %s", strerror(errno));
		ATF_REQUIRE_EQ(0, close(fd));
		resume(sfd);
		use_after_resume();
	}
	remount_and_check();
}
ATF_TC_CLEANUP(repeated_suspensions, tc)
{
	(void)tc;
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, access_closed_during_suspension);
	ATF_TP_ADD_TC(tp, access_open_across_resume);
	ATF_TP_ADD_TC(tp, repeated_suspensions);
	return (atf_no_error());
}
