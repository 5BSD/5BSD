/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include <notify_pressure.h>

#include "pressure.h"
ATF_TC_WITHOUT_HEAD(thresholds_and_recovery);
ATF_TC_BODY(thresholds_and_recovery, tc)
{
	struct pressure_filter f = { .level = NOTIFY_PRESSURE_UNKNOWN };
	ATF_CHECK_EQ(NOTIFY_PRESSURE_NORMAL,
	    pressure_update(&f, 0, 30, 10, 20));
	ATF_CHECK_EQ(NOTIFY_PRESSURE_WARNING,
	    pressure_update(&f, 0, 20, 10, 20));
	ATF_CHECK_EQ(NOTIFY_PRESSURE_CRITICAL,
	    pressure_update(&f, 0, 10, 10, 20));
	ATF_CHECK_EQ(NOTIFY_PRESSURE_CRITICAL,
	    pressure_update(&f, 0, 30, 10, 20));
	ATF_CHECK_EQ(NOTIFY_PRESSURE_CRITICAL,
	    pressure_update(&f, 0, 30, 10, 20));
	ATF_CHECK_EQ(NOTIFY_PRESSURE_NORMAL,
	    pressure_update(&f, 0, 30, 10, 20));
	ATF_CHECK_EQ(NOTIFY_PRESSURE_UNKNOWN,
	    pressure_update(&f, -1, 30, 10, 20));
	ATF_CHECK_EQ(NOTIFY_PRESSURE_CRITICAL,
	    pressure_update(&f, 0, 0, 10, 20));
	ATF_CHECK_EQ(NOTIFY_PRESSURE_UNKNOWN,
	    pressure_update(&f, 0, 30, 20, 10));
	ATF_CHECK_EQ(NOTIFY_PRESSURE_UNKNOWN,
	    pressure_update(&f, 0, 30, 0, 10));
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, thresholds_and_recovery);
	return (atf_no_error());
}
