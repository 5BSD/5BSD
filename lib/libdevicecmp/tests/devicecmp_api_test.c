/*- SPDX-License-Identifier: BSD-2-Clause */
/*
 * Argument-validation tests for the system.Device client.  These exercise the
 * fail-closed input checks that return before any provider session is opened,
 * so they need no live plane.
 */
#include <errno.h>
#include <string.h>

#include <atf-c.h>

#include "devicecmp.h"

ATF_TC_WITHOUT_HEAD(null_args);
ATF_TC_BODY(null_args, tc)
{
	int fd = 0;
	uint32_t granted = 0xffffffff;

	ATF_REQUIRE_ERRNO(EINVAL,
	    devicecmp_open(NULL, NULL, DEVICECMP_RIGHT_READ, &granted, &fd) == -1);
	ATF_REQUIRE_ERRNO(EINVAL,
	    devicecmp_open(NULL, "null", DEVICECMP_RIGHT_READ, &granted, NULL) == -1);
}

ATF_TC_WITHOUT_HEAD(bad_rights);
ATF_TC_BODY(bad_rights, tc)
{
	int fd = 0;

	/* Zero rights and out-of-mask bits are both rejected up front. */
	ATF_REQUIRE_ERRNO(EINVAL,
	    devicecmp_open(NULL, "null", 0, NULL, &fd) == -1);
	ATF_CHECK(fd == -1);
	ATF_REQUIRE_ERRNO(EINVAL,
	    devicecmp_open(NULL, "null", 0x40000000U, NULL, &fd) == -1);
	ATF_CHECK(fd == -1);
}

ATF_TC_WITHOUT_HEAD(bad_name);
ATF_TC_BODY(bad_name, tc)
{
	char toolong[DEVICECMP_MAX_NAME + 8];
	int fd = 0;

	ATF_REQUIRE_ERRNO(EINVAL,
	    devicecmp_open(NULL, "", DEVICECMP_RIGHT_READ, NULL, &fd) == -1);
	ATF_CHECK(fd == -1);
	memset(toolong, 'a', sizeof(toolong) - 1);
	toolong[sizeof(toolong) - 1] = '\0';
	ATF_REQUIRE_ERRNO(EINVAL,
	    devicecmp_open(NULL, toolong, DEVICECMP_RIGHT_READ, NULL, &fd) == -1);
	ATF_CHECK(fd == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, null_args);
	ATF_TP_ADD_TC(tp, bad_rights);
	ATF_TP_ADD_TC(tp, bad_name);
	return (atf_no_error());
}
