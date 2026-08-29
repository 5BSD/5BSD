/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the calendar activation math (calendar_next/calendar_prev).
 * Pure wall-clock logic — no daemon or kqueue.  TZ is pinned to UTC so the
 * expected instants are deterministic and DST-free.
 */

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <atf-c.h>

#include "activation_calendar.h"

static time_t
mk(int y, int mon, int day, int h, int mi)
{
	struct tm tm;

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = y - 1900;
	tm.tm_mon = mon - 1;
	tm.tm_mday = day;
	tm.tm_hour = h;
	tm.tm_min = mi;
	tm.tm_isdst = -1;
	return (mktime(&tm));
}

static void
pin_utc(void)
{
	setenv("TZ", "UTC", 1);
	tzset();
}

static struct svc_calendar
cal(int mi, int h, int mday, int mon, int wday)
{
	struct svc_calendar c;

	c.minute = mi;
	c.hour = h;
	c.mday = mday;
	c.month = mon;
	c.wday = wday;
	return (c);
}

ATF_TC_WITHOUT_HEAD(daily_same_day);
ATF_TC_BODY(daily_same_day, tc)
{
	struct svc_calendar c;

	pin_utc();
	c = cal(30, 3, SVC_CAL_ANY, SVC_CAL_ANY, SVC_CAL_ANY);	/* 03:30 daily */
	/* Before today's 03:30 -> today 03:30. */
	ATF_CHECK_EQ(mk(2026, 6, 15, 3, 30),
	    calendar_next(&c, mk(2026, 6, 15, 1, 0)));
}

ATF_TC_WITHOUT_HEAD(daily_rolls_to_tomorrow);
ATF_TC_BODY(daily_rolls_to_tomorrow, tc)
{
	struct svc_calendar c;

	pin_utc();
	c = cal(30, 3, SVC_CAL_ANY, SVC_CAL_ANY, SVC_CAL_ANY);
	/* After today's 03:30 -> tomorrow 03:30. */
	ATF_CHECK_EQ(mk(2026, 6, 16, 3, 30),
	    calendar_next(&c, mk(2026, 6, 15, 4, 0)));
}

ATF_TC_WITHOUT_HEAD(exact_match_is_strictly_after);
ATF_TC_BODY(exact_match_is_strictly_after, tc)
{
	struct svc_calendar c;

	pin_utc();
	c = cal(30, 3, SVC_CAL_ANY, SVC_CAL_ANY, SVC_CAL_ANY);
	/* Standing exactly on a match returns the NEXT one, never the same. */
	ATF_CHECK_EQ(mk(2026, 6, 16, 3, 30),
	    calendar_next(&c, mk(2026, 6, 15, 3, 30)));
}

ATF_TC_WITHOUT_HEAD(hourly_top_of_hour);
ATF_TC_BODY(hourly_top_of_hour, tc)
{
	struct svc_calendar c;

	pin_utc();
	c = cal(0, SVC_CAL_ANY, SVC_CAL_ANY, SVC_CAL_ANY, SVC_CAL_ANY);
	ATF_CHECK_EQ(mk(2026, 6, 15, 2, 0),
	    calendar_next(&c, mk(2026, 6, 15, 1, 15)));
}

ATF_TC_WITHOUT_HEAD(every_minute);
ATF_TC_BODY(every_minute, tc)
{
	struct svc_calendar c;

	pin_utc();
	c = cal(SVC_CAL_ANY, SVC_CAL_ANY, SVC_CAL_ANY, SVC_CAL_ANY,
	    SVC_CAL_ANY);
	ATF_CHECK_EQ(mk(2026, 6, 15, 1, 16),
	    calendar_next(&c, mk(2026, 6, 15, 1, 15)));
}

ATF_TC_WITHOUT_HEAD(specific_month);
ATF_TC_BODY(specific_month, tc)
{
	struct svc_calendar c;
	time_t t;
	struct tm tm;

	pin_utc();
	/* 00:00 on the 1st of December. */
	c = cal(0, 0, 1, 12, SVC_CAL_ANY);
	t = calendar_next(&c, mk(2026, 6, 15, 12, 0));
	ATF_REQUIRE(t != (time_t)-1);
	ATF_CHECK_EQ(mk(2026, 12, 1, 0, 0), t);
	gmtime_r(&t, &tm);
	ATF_CHECK_EQ(11, tm.tm_mon);	/* December */
	ATF_CHECK_EQ(1, tm.tm_mday);
}

ATF_TC_WITHOUT_HEAD(friday_the_thirteenth_and_semantics);
ATF_TC_BODY(friday_the_thirteenth_and_semantics, tc)
{
	struct svc_calendar c;
	time_t t;
	struct tm tm;

	pin_utc();
	/* mday=13 AND wday=5 (Friday) — launchd AND semantics, not cron OR. */
	c = cal(0, 0, 13, SVC_CAL_ANY, 5);
	t = calendar_next(&c, mk(2026, 1, 1, 0, 0));
	ATF_REQUIRE(t != (time_t)-1);
	gmtime_r(&t, &tm);
	ATF_CHECK_EQ(13, tm.tm_mday);
	ATF_CHECK_EQ(5, tm.tm_wday);	/* Friday */
	ATF_CHECK(t > mk(2026, 1, 1, 0, 0));
}

ATF_TC_WITHOUT_HEAD(prev_daily);
ATF_TC_BODY(prev_daily, tc)
{
	struct svc_calendar c;

	pin_utc();
	c = cal(30, 3, SVC_CAL_ANY, SVC_CAL_ANY, SVC_CAL_ANY);
	/* Most recent 03:30 at/before 04:00 today is today's 03:30. */
	ATF_CHECK_EQ(mk(2026, 6, 15, 3, 30),
	    calendar_prev(&c, mk(2026, 6, 15, 4, 0)));
	/* Before today's 03:30, the previous one is yesterday's. */
	ATF_CHECK_EQ(mk(2026, 6, 14, 3, 30),
	    calendar_prev(&c, mk(2026, 6, 15, 1, 0)));
}

ATF_TC_WITHOUT_HEAD(prev_month_boundary_no_overshoot);
ATF_TC_BODY(prev_month_boundary_no_overshoot, tc)
{
	struct svc_calendar c;
	time_t t;
	struct tm tm;

	pin_utc();
	/* Regression: prev across a short month must not roll forward. */
	c = cal(0, 0, SVC_CAL_ANY, SVC_CAL_ANY, SVC_CAL_ANY);	/* midnight */
	t = calendar_prev(&c, mk(2026, 3, 1, 12, 0));
	ATF_REQUIRE(t != (time_t)-1);
	ATF_CHECK_EQ(mk(2026, 3, 1, 0, 0), t);
	gmtime_r(&t, &tm);
	ATF_CHECK_EQ(2, tm.tm_mon);	/* still March, not April */
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, daily_same_day);
	ATF_TP_ADD_TC(tp, daily_rolls_to_tomorrow);
	ATF_TP_ADD_TC(tp, exact_match_is_strictly_after);
	ATF_TP_ADD_TC(tp, hourly_top_of_hour);
	ATF_TP_ADD_TC(tp, every_minute);
	ATF_TP_ADD_TC(tp, specific_month);
	ATF_TP_ADD_TC(tp, friday_the_thirteenth_and_semantics);
	ATF_TP_ADD_TC(tp, prev_daily);
	ATF_TP_ADD_TC(tp, prev_month_boundary_no_overshoot);
	return (atf_no_error());
}
