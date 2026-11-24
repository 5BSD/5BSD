/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Access to the queue device for the DescriptorQueue tests: the plane and
 * test-kernel checks, and the open that fails rather than skips.
 * lib/libdq/tests compiles this file too (see its Makefile).
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "dqt.h"

void
dqt_require_plane(void)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 1 };

	len = sizeof(kp);
	if (sysctl(mib, nitems(mib), &kp, &len, NULL, 0) != 0)
		atf_tc_fail("kern.proc.pid.1: %s", strerror(errno));
	if (strcmp(kp.ki_comm, "capsule") != 0)
		atf_tc_fail("the capability plane is off: PID 1 is %s, not "
		    "capsule", kp.ki_comm);
	if (access(DQ_DEVICE, F_OK) != 0)
		atf_tc_fail("%s: %s", DQ_DEVICE, strerror(errno));
}

/*
 * A kernel built with options DQ_TEST_OPEN, and only such a kernel, has the
 * debug.dq.unverified_open sysctl.  On it the tests must have been given
 * test access by the loader (debug.dq.unverified_open="1"): a test kernel
 * booted without the setting is a rig that was not set up, and fails here
 * by name instead of in whatever the first refused open breaks.  A kernel
 * without the sysctl is not a test kernel and is opened as before.
 */
void
dqt_require_test_access(void)
{
	size_t len;
	int v;

	len = sizeof(v);
	if (sysctlbyname("debug.dq.unverified_open", &v, &len, NULL, 0) != 0) {
		if (errno == ENOENT)
			return;
		atf_tc_fail("debug.dq.unverified_open: %s", strerror(errno));
	}
	if (len != sizeof(v) || v != 1)
		atf_tc_fail("test kernel without test access: set "
		    "debug.dq.unverified_open=\"1\" in loader.conf "
		    "(it reads %d)", v);
}

/*
 * A fault knob of options DQ_FAULT_INJECTION (dq_faultinj.c).  A kernel
 * without the option is the main tier, where such a case cannot run: it
 * skips with DEFERRED_KNOB_TIER, which vm-provider.sh counts as a case
 * owed by the knob tier (KERNEL_TIER=test, GENERIC-TEST), not a pass.  On
 * a test kernel the knob must be there.
 */
void
dqt_require_fault_knob(const char *name)
{
	size_t len;
	u_int v;

	len = sizeof(v);
	if (sysctlbyname(name, &v, &len, NULL, 0) == 0)
		return;
	if (errno != ENOENT)
		atf_tc_fail("%s: %s", name, strerror(errno));
	len = sizeof(v);
	if (sysctlbyname("debug.dq.unverified_open", &v, &len, NULL, 0) == 0)
		atf_tc_fail("a test kernel without %s: options "
		    "DQ_FAULT_INJECTION is missing from GENERIC-TEST", name);
	atf_tc_skip("DEFERRED_KNOB_TIER: %s needs options "
	    "DQ_FAULT_INJECTION (GENERIC-TEST, KERNEL_TIER=test)", name);
}

/* Never skips: a queue device that is absent or refuses is a failure. */
int
dqt_open_queue(void)
{
	int q;

	dqt_require_test_access();
	q = dq_open();
	if (q == -1)
		atf_tc_fail("%s: %s", DQ_DEVICE, strerror(errno));
	return (q);
}

/* DQ_WAKE_NSITES and struct dq_faultinj_* of sys/dev/dq (test kernel). */
#define	DQT_WAKE_NSITES	11

uint64_t
dqt_drop_count(u_int site)
{
	uint64_t counts[DQT_WAKE_NSITES];
	size_t len;
	int idx;

	idx = ffs((int)site) - 1;
	ATF_REQUIRE(site != 0 && powerof2(site) && idx < DQT_WAKE_NSITES);
	len = sizeof(counts);
	ATF_REQUIRE_MSG(sysctlbyname("debug.dq.wakeups_dropped", counts, &len,
	    NULL, 0) == 0 && len == sizeof(counts),
	    "debug.dq.wakeups_dropped: %s", strerror(errno));
	return (counts[idx]);
}

void
dqt_drop_wait(u_int site, uint64_t count)
{
	struct {
		uint32_t	site;
		uint32_t	pad;
		uint64_t	count;
	} dw;

	dw.site = site;
	dw.pad = 0;
	dw.count = count;
	ATF_REQUIRE_MSG(sysctlbyname("debug.dq.wakeup_drop_wait", NULL, NULL,
	    &dw, sizeof(dw)) == 0, "debug.dq.wakeup_drop_wait: %s",
	    strerror(errno));
}

/* DQ_QUOTA_* of sys/dev/dq/dq_var.h: index quota - 1 (test kernel). */
#define	DQT_NQUOTAS	2

uint64_t
dqt_quota_sleeps(u_int quota)
{
	uint64_t counts[DQT_NQUOTAS];
	size_t len;

	ATF_REQUIRE(quota == DQT_QUOTA_OBJECT || quota == DQT_QUOTA_REQUESTER);
	len = sizeof(counts);
	ATF_REQUIRE_MSG(sysctlbyname("debug.dq.quota_sleeps", counts, &len,
	    NULL, 0) == 0 && len == sizeof(counts),
	    "debug.dq.quota_sleeps: %s", strerror(errno));
	return (counts[quota - 1]);
}

void
dqt_quota_sleep_wait(u_int quota, uint64_t count)
{
	struct {
		uint32_t	quota;
		uint32_t	pad;
		uint64_t	count;
	} qw;

	qw.quota = quota;
	qw.pad = 0;
	qw.count = count;
	ATF_REQUIRE_MSG(sysctlbyname("debug.dq.quota_sleep_wait", NULL, NULL,
	    &qw, sizeof(qw)) == 0, "debug.dq.quota_sleep_wait: %s",
	    strerror(errno));
}

bool
dqt_sleep_left(pid_t pid, const char *wmesg, uint64_t *left_ms)
{
	struct {
		int32_t		tid;
		uint32_t	pad;
		uint64_t	left_ms;
		char		wmesg[WMESGLEN + 1];
	} *ds;
	int mib[CTL_MAXNAME];
	size_t len, miblen;
	size_t i, n;
	bool found;

	miblen = nitems(mib) - 1;
	ATF_REQUIRE_MSG(sysctlnametomib("debug.dq.thread_sleeps", mib,
	    &miblen) == 0, "debug.dq.thread_sleeps: %s", strerror(errno));
	mib[miblen++] = (int)pid;
	len = 0;
	ATF_REQUIRE_MSG(sysctl(mib, (u_int)miblen, NULL, &len, NULL, 0) == 0,
	    "debug.dq.thread_sleeps.%d: %s", (int)pid, strerror(errno));
	len += 4 * sizeof(*ds);		/* threads that fall asleep meanwhile */
	ds = malloc(len);
	ATF_REQUIRE(ds != NULL);
	ATF_REQUIRE_MSG(sysctl(mib, (u_int)miblen, ds, &len, NULL, 0) == 0,
	    "debug.dq.thread_sleeps.%d: %s", (int)pid, strerror(errno));
	n = len / sizeof(*ds);
	found = false;
	for (i = 0; i < n && !found; i++) {
		if (strcmp(ds[i].wmesg, wmesg) == 0) {
			found = true;
			*left_ms = ds[i].left_ms;
		}
	}
	free(ds);
	return (found);
}
