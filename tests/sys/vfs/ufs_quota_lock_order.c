/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * UFS takes its per-mount "FFS Lock" (UFS_LOCK) before the mount interlock
 * ("struct mount mtx"): quotaon() and quotaoff_inchange() hold the first
 * while they update mnt_flag under the second.  The unmount of a soft
 * updates file system on a kernel with options QUOTA must keep that order:
 * turning quotas on and off and unmounting must leave no reversal between
 * the two in debug.witness.badstacks.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <ufs/ufs/quota.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	MD_FILE		"md.unit"
#define	MNT		"mnt"

static void
run(const char *cmd)
{
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
}

/* Whether WITNESS has recorded a reversal between the two lock names. */
static bool
witness_reversal(const char *a, const char *b)
{
	char line[512];
	FILE *fp;
	bool found = false;

	fp = popen("sysctl -n debug.witness.badstacks", "r");
	ATF_REQUIRE(fp != NULL);
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strstr(line, "Lock order reversal between") != NULL &&
		    strstr(line, a) != NULL && strstr(line, b) != NULL)
			found = true;
	}
	pclose(fp);
	return (found);
}

static void
require_quota_witness(void)
{
	size_t len;
	int on, watch;

	len = sizeof(on);
	if (sysctlbyname("kern.features.ufs_quota", &on, &len, NULL, 0) != 0)
		atf_tc_skip("kernel without options QUOTA");
	len = sizeof(watch);
	if (sysctlbyname("debug.witness.watch", &watch, &len, NULL, 0) != 0 ||
	    watch < 1)
		atf_tc_skip("WITNESS is not running");
	if (witness_reversal("\"struct mount mtx\"", "\"FFS Lock\""))
		atf_tc_skip("the reversal was recorded earlier in this boot");
}

/* A soft updates UFS on md(4), mounted with userquota; returns the path. */
static void
fixture(char *qfile, size_t qlen, char *mnt, size_t mlen)
{
	char cmd[256], cwd[PATH_MAX], unit[32];
	FILE *fp;
	int fd;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
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
	snprintf(cmd, sizeof(cmd), "mount -o userquota /dev/%s %s", unit, MNT);
	run(cmd);
	snprintf(mnt, mlen, "%s/%s", cwd, MNT);
	snprintf(qfile, qlen, "%s/quota.user", mnt);
	fd = open(qfile, O_CREAT | O_RDWR, 0600);
	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", qfile, strerror(errno));
	ATF_REQUIRE_EQ(0, close(fd));
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

ATF_TC_WITH_CLEANUP(quotaoff_then_unmount);
ATF_TC_HEAD(quotaoff_then_unmount, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "quotaon, quotaoff and the unmount of a soft updates UFS take "
	    "the FFS lock before the mount interlock");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "mdconfig newfs");
}
ATF_TC_BODY(quotaoff_then_unmount, tc)
{
	char mnt[PATH_MAX], qfile[PATH_MAX];

	require_quota_witness();
	fixture(qfile, sizeof(qfile), mnt, sizeof(mnt));
	ATF_REQUIRE_MSG(quotactl(mnt, QCMD(Q_QUOTAON, USRQUOTA), 0, qfile) == 0,
	    "Q_QUOTAON: %s", strerror(errno));
	ATF_REQUIRE_MSG(quotactl(mnt, QCMD(Q_QUOTAOFF, USRQUOTA), 0, NULL) ==
	    0, "Q_QUOTAOFF: %s", strerror(errno));
	run("umount " MNT);
	ATF_CHECK_MSG(!witness_reversal("\"struct mount mtx\"", "\"FFS Lock\""),
	    "WITNESS recorded a struct mount mtx / FFS Lock reversal");
}
ATF_TC_CLEANUP(quotaoff_then_unmount, tc)
{
	(void)tc;
	cleanup();
}

ATF_TC_WITH_CLEANUP(unmount_with_quota_on);
ATF_TC_HEAD(unmount_with_quota_on, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "the unmount of a soft updates UFS with quotas on turns them off "
	    "and keeps the FFS lock before the mount interlock");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "mdconfig newfs");
}
ATF_TC_BODY(unmount_with_quota_on, tc)
{
	char mnt[PATH_MAX], qfile[PATH_MAX];

	require_quota_witness();
	fixture(qfile, sizeof(qfile), mnt, sizeof(mnt));
	ATF_REQUIRE_MSG(quotactl(mnt, QCMD(Q_QUOTAON, USRQUOTA), 0, qfile) == 0,
	    "Q_QUOTAON: %s", strerror(errno));
	run("umount " MNT);
	ATF_CHECK_MSG(!witness_reversal("\"struct mount mtx\"", "\"FFS Lock\""),
	    "WITNESS recorded a struct mount mtx / FFS Lock reversal");
}
ATF_TC_CLEANUP(unmount_with_quota_on, tc)
{
	(void)tc;
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, quotaoff_then_unmount);
	ATF_TP_ADD_TC(tp, unmount_with_quota_on);
	return (atf_no_error());
}
