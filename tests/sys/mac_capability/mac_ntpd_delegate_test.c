/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * mac_ntpd(4)'s clock delegate under the capability plane.  While BSDTime
 * holds the SYS_GATE_SETTIME claim, the clock privileges pass the gate only
 * for the ntpd user running an image pinned in its switchboard program-limited
 * grant (service-authority.ucl).  The uid alone, as any root shell can assume
 * with su(1), is refused, and the delegate cannot be widened by sysctl.
 *
 * Every case runs only on a live plane: the claim must be held (root's
 * adjtime(2) is refused) and mac_ntpd loaded; otherwise it skips.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uid_t
ntpd_uid(void)
{
	struct passwd *pw;
	int uid;
	size_t len = sizeof(uid);

	if (sysctlbyname("security.mac.ntpd.uid", &uid, &len, NULL, 0) == -1)
		atf_tc_skip("mac_ntpd is not loaded");
	pw = getpwnam("ntpd");
	if (pw != NULL && pw->pw_uid != (uid_t)uid)
		atf_tc_skip("security.mac.ntpd.uid %d is not user ntpd", uid);
	return ((uid_t)uid);
}

/* A zero-length slew: needs PRIV_ADJTIME, changes nothing. */
static int
null_adjtime(void)
{
	struct timeval delta = { 0, 0 };

	return (adjtime(&delta, NULL) == -1 ? errno : 0);
}

static void
require_plane(void)
{

	if (geteuid() != 0)
		atf_tc_skip("needs root");
	if (null_adjtime() == 0)
		atf_tc_skip("the clock gate is not claimed (capability plane "
		    "off or BSDTime not running)");
}

ATF_TC(root_refused);
ATF_TC_HEAD(root_refused, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Root without the clock claim cannot slew or step the clock");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(root_refused, tc)
{
	struct timespec now;

	(void)ntpd_uid();
	require_plane();
	ATF_CHECK_EQ(EPERM, null_adjtime());
	ATF_REQUIRE(clock_gettime(CLOCK_REALTIME, &now) == 0);
	ATF_CHECK_ERRNO(EPERM, clock_settime(CLOCK_REALTIME, &now) == -1);
}

/*
 * A process that becomes the ntpd user (as su -m ntpd does) but runs this
 * test program, not a pinned image under the grant, is refused.  With the old
 * uid-only delegate this child passed.
 */
ATF_TC(ntpd_uid_without_grant_refused);
ATF_TC_HEAD(ntpd_uid_without_grant_refused, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The ntpd uid alone, outside the switchboard grant, is refused");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ntpd_uid_without_grant_refused, tc)
{
	uid_t uid;
	pid_t pid;
	int status;

	uid = ntpd_uid();
	require_plane();
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (setgid(uid) == -1 || setuid(uid) == -1)
			_exit(2);
		_exit(null_adjtime() == EPERM ? 0 : 1);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_MSG(WEXITSTATUS(status) != 2, "cannot become uid %u", uid);
	ATF_CHECK_MSG(WEXITSTATUS(status) == 0,
	    "uid %u passed the clock gate without the ntpd grant", uid);
}

ATF_TC(sysctl_cannot_widen);
ATF_TC_HEAD(sysctl_cannot_widen, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "security.mac.ntpd.uid is fixed while the clock gate is claimed");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sysctl_cannot_widen, tc)
{
	int other, uid;

	uid = (int)ntpd_uid();
	require_plane();
	other = 0;
	ATF_CHECK_ERRNO(EPERM, sysctlbyname("security.mac.ntpd.uid", NULL,
	    NULL, &other, sizeof(other)) == -1);
	other = uid + 1;
	ATF_CHECK_ERRNO(EPERM, sysctlbyname("security.mac.ntpd.uid", NULL,
	    NULL, &other, sizeof(other)) == -1);
	/* Rewriting the current value changes nothing and is accepted. */
	ATF_CHECK(sysctlbyname("security.mac.ntpd.uid", NULL, NULL, &uid,
	    sizeof(uid)) == 0);
}

static bool
ntpd_running(uid_t uid)
{
	struct kinfo_proc *kp;
	size_t len = 0, i;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_UID, (int)uid };
	bool found = false;

	if (sysctl(mib, 4, NULL, &len, NULL, 0) == -1 || len == 0)
		return (false);
	len += len / 4;
	if ((kp = malloc(len)) == NULL)
		return (false);
	if (sysctl(mib, 4, kp, &len, NULL, 0) == 0)
		for (i = 0; i < len / sizeof(*kp) && !found; i++)
			found = strcmp(kp[i].ki_comm, "ntpd") == 0;
	free(kp);
	return (found);
}

/*
 * The ntpd switchboard started holds the grant: it enables the kernel
 * phase-locked loop (ntp_adjtime MOD_STATUS, PRIV_NTP_ADJTIME) at startup.
 */
ATF_TC(granted_ntpd_disciplines);
ATF_TC_HEAD(granted_ntpd_disciplines, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ntpd started by switchboard under its grant runs the kernel PLL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(granted_ntpd_disciplines, tc)
{
	struct timex tx;

	require_plane();
	if (!ntpd_running(ntpd_uid()))
		atf_tc_skip("ntpd is not running as the ntpd user");
	memset(&tx, 0, sizeof(tx));
	ATF_REQUIRE(ntp_adjtime(&tx) != -1);
	ATF_CHECK_MSG((tx.status & STA_PLL) != 0,
	    "ntpd did not engage the kernel PLL (status %#x)", tx.status);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, root_refused);
	ATF_TP_ADD_TC(tp, ntpd_uid_without_grant_refused);
	ATF_TP_ADD_TC(tp, sysctl_cannot_widen);
	ATF_TP_ADD_TC(tp, granted_ntpd_disciplines);
	return (atf_no_error());
}
