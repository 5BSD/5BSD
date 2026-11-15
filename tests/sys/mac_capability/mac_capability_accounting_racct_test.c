/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The accounting service on a kernel booted with kern.racct.enable=0.
 *
 * With racct disabled no process has racct state (p_racct is NULL) and rctl
 * refuses to run.  The service refuses a connection with ENOSYS after the
 * privilege check, as rctl(2) refuses its system calls, and refuses every
 * operation the same way.  The cases need such a boot; on a kernel with
 * racct enabled they have nothing to check.
 */

#include <sys/types.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"

static void
require_racct_off(void)
{
	size_t len;
	int enabled;

	len = sizeof(enabled);
	ATF_REQUIRE(sysctlbyname("kern.racct.enable", &enabled, &len, NULL,
	    0) == 0);
	if (enabled != 0)
		atf_tc_skip("needs a boot with kern.racct.enable=0");
}

ATF_TC(connect_refused);
ATF_TC_HEAD(connect_refused, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "connecting to the accounting service fails with ENOSYS");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(connect_refused, tc)
{
	int fd;

	require_racct_off();
	fd = mac_capability_connect("accounting");
	ATF_CHECK_ERRNO(ENOSYS, fd == -1);
	if (fd >= 0)
		close(fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, connect_refused);
	return (atf_no_error());
}
