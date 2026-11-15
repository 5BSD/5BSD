/*-
 * SPDX-License-Identifier: BSD-2-Clause
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
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

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
