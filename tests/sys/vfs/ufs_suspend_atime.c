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
 * resume.  The closes race the resume's walk over the mount's vnodes, so the
 * walk is given work ahead of the read files: a holder process keeps many
 * files made before them open and reads them during the suspension, and
 * the walk locks and converts each of those (they stay in use) before it
 * reaches the read files, whose closes have finished by then.  Each case
 * makes its own md(4)-backed UFS file system.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ufs/ffs/fs.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	MD_FILE		"md.unit"
#define	MNT		"mnt"
#define	NFILLER		2000
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
 * The defect closed_at_resume and repeated_suspensions pin shows only as
 * the INVARIANTS assertion in ffs_unlock_debug(): without INVARIANTS the
 * inode is left modified off the lazy list, which nothing they check sees.
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

/*
 * A soft updates UFS on a swap-backed md(4) device, with NFILLER files and
 * then NREAD files to read.
 */
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
	for (i = 0; i < NFILLER; i++) {
		path_of(path, sizeof(path), "filler", i);
		make_file(path);
	}
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

/*
 * The holder: a child that opens every filler file, reads and fstats each
 * when told (during the suspension), and closes them when told to finish
 * (after the resume).  Commands and acknowledgements are one byte on a
 * pair of pipes.
 */
struct holder {
	pid_t	pid;
	int	cmd;
	int	ack;
};

static void
holder_body(int cmd, int ack)
{
	struct rlimit rl;
	char c, path[64];
	int *fds, i;

	rl.rlim_cur = rl.rlim_max = NFILLER + 64;
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
		_exit(10);
	fds = calloc(NFILLER, sizeof(*fds));
	if (fds == NULL)
		_exit(11);
	for (i = 0; i < NFILLER; i++) {
		path_of(path, sizeof(path), "filler", i);
		if ((fds[i] = open(path, O_RDONLY)) < 0)
			_exit(12);
	}
	c = 'o';
	if (write(ack, &c, 1) != 1 || read(cmd, &c, 1) != 1)
		_exit(13);
	for (i = 0; i < NFILLER; i++)
		if (access_file(fds[i]) != 0)
			_exit(14);
	c = 'a';
	if (write(ack, &c, 1) != 1 || read(cmd, &c, 1) != 1)
		_exit(15);
	for (i = 0; i < NFILLER; i++)
		(void)close(fds[i]);
	_exit(0);
}

static void
holder_start(struct holder *h)
{
	int cmdp[2], ackp[2];
	char c;

	ATF_REQUIRE_EQ(0, pipe(cmdp));
	ATF_REQUIRE_EQ(0, pipe(ackp));
	h->pid = fork();
	ATF_REQUIRE(h->pid >= 0);
	if (h->pid == 0) {
		close(cmdp[1]);
		close(ackp[0]);
		holder_body(cmdp[0], ackp[1]);
	}
	close(cmdp[0]);
	close(ackp[1]);
	h->cmd = cmdp[1];
	h->ack = ackp[0];
	ATF_REQUIRE_MSG(read(h->ack, &c, 1) == 1 && c == 'o',
	    "the holder did not open the filler files");
}

static void
holder_access(struct holder *h)
{
	char c = 'r';

	ATF_REQUIRE_EQ(1, write(h->cmd, &c, 1));
	ATF_REQUIRE_MSG(read(h->ack, &c, 1) == 1 && c == 'a',
	    "the holder did not read the filler files");
}

static void
holder_finish(struct holder *h)
{
	char c = 'x';
	int status;

	ATF_REQUIRE_EQ(1, write(h->cmd, &c, 1));
	ATF_REQUIRE_EQ(h->pid, waitpid(h->pid, &status, 0));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "holder: status %#x", status);
	close(h->cmd);
	close(h->ack);
}

/* Whether process pid sleeps on the wait message wmesg. */
static bool
sleeps_on(pid_t pid, const char *wmesg)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };

	mib[3] = pid;
	len = sizeof(kp);
	if (sysctl(mib, nitems(mib), &kp, &len, NULL, 0) != 0 || len == 0)
		return (false);
	return (strcmp(kp.ki_wmesg, wmesg) == 0);
}

/*
 * Start a child per read file that opens, reads and fstats it and closes
 * it, and wait until every child's close waits for the resume.
 */
static void
start_readers(pid_t *pids)
{
	char path[64];
	int fd, i, tries;

	for (i = 0; i < NREAD; i++) {
		path_of(path, sizeof(path), "f", i);
		pids[i] = fork();
		ATF_REQUIRE(pids[i] >= 0);
		if (pids[i] == 0) {
			fd = open(path, O_RDONLY);
			if (fd < 0 || access_file(fd) != 0)
				_exit(1);
			_exit(close(fd) == 0 ? 0 : 2);
		}
	}
	for (i = 0; i < NREAD; i++) {
		for (tries = 0; tries < 2000; tries++) {
			if (sleeps_on(pids[i], "suspfs"))
				break;
			usleep(5000);
		}
		ATF_REQUIRE_MSG(tries < 2000,
		    "reader %d never waited for the resume in close", i);
	}
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

ATF_TC_WITH_CLEANUP(closed_at_resume);
ATF_TC_HEAD(closed_at_resume, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "files read during a suspension and closed as it ends can be "
	    "used after the resume");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "mdconfig newfs fsck_ffs");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(closed_at_resume, tc)
{
	struct holder h;
	pid_t pids[NREAD];
	int sfd;

	require_invariants();
	fixture();
	holder_start(&h);
	sfd = suspend();
	holder_access(&h);
	start_readers(pids);
	resume(sfd);
	reap_readers(pids);
	use_files();
	holder_finish(&h);
	remount_and_check();
}
ATF_TC_CLEANUP(closed_at_resume, tc)
{
	(void)tc;
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

ATF_TC_WITH_CLEANUP(repeated_suspensions);
ATF_TC_HEAD(repeated_suspensions, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "files read and closed across repeated suspensions can be used "
	    "after each resume");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "mdconfig newfs fsck_ffs");
	atf_tc_set_md_var(tc, "timeout", "900");
}
ATF_TC_BODY(repeated_suspensions, tc)
{
	struct holder h;
	pid_t pids[NREAD];
	int i, sfd;

	require_invariants();
	fixture();
	for (i = 0; i < 10; i++) {
		holder_start(&h);
		sfd = suspend();
		holder_access(&h);
		start_readers(pids);
		resume(sfd);
		reap_readers(pids);
		use_files();
		holder_finish(&h);
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
	ATF_TP_ADD_TC(tp, closed_at_resume);
	ATF_TP_ADD_TC(tp, open_across_resume);
	ATF_TP_ADD_TC(tp, repeated_suspensions);
	return (atf_no_error());
}
