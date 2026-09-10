/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Calendar activation math (launchd StartCalendarInterval).  Pure wall-clock
 * logic with no daemon or kqueue dependency, so it is unit-tested directly:
 * given a parsed svc_calendar and a reference time, return the next local
 * wall-clock instant at or after it that matches every specified field.
 *
 * Semantics follow launchd (not cron): every field that is set must match
 * (AND).  A set day-of-month AND a set day-of-week therefore means, e.g.,
 * "Friday the 13th", not cron's "Friday OR the 13th".  Unset fields
 * (SVC_CAL_ANY) match anything.  Seconds always match at :00.
 */

#include <time.h>

#include "activation_calendar.h"

/*
 * Upper bound on field-advance steps.  A normal schedule resolves in well
 * under 1500 steps (at most a day of minutes/hours plus a month of days);
 * pathological AND combinations (a specific weekday-and-monthday-and-month)
 * resolve within a few years of day steps.  The cap bounds an unsatisfiable
 * spec (e.g. month=2 with mday=30, which the parser does not cross-validate):
 * the search returns (time_t)-1 and the caller logs it rather than looping
 * forever.
 */
#define	CAL_MAX_STEPS	200000

static int
field_matches(int value, int field)
{
	return (field == SVC_CAL_ANY || value == field);
}

time_t
calendar_next(const struct svc_calendar *cal, time_t after)
{
	struct tm tm;
	time_t t;
	int steps;

	/* Start at the next whole minute strictly after `after`. */
	t = after + 60 - (after % 60);
	if (localtime_r(&t, &tm) == NULL)
		return ((time_t)-1);
	tm.tm_sec = 0;

	for (steps = 0; steps < CAL_MAX_STEPS; steps++) {
		/*
		 * Re-derive tm_wday/tm_yday and fold any field overflow from the
		 * previous advance.  isdst = -1 lets mktime pick the correct DST
		 * offset for the (possibly boundary-crossing) wall-clock time.
		 */
		tm.tm_isdst = -1;
		if (mktime(&tm) == (time_t)-1)
			return ((time_t)-1);

		if (!field_matches(tm.tm_mon + 1, cal->month)) {
			tm.tm_mon += 1;
			tm.tm_mday = 1;
			tm.tm_hour = 0;
			tm.tm_min = 0;
			continue;
		}
		if (!field_matches(tm.tm_mday, cal->mday) ||
		    !field_matches(tm.tm_wday, cal->wday)) {
			tm.tm_mday += 1;
			tm.tm_hour = 0;
			tm.tm_min = 0;
			continue;
		}
		if (!field_matches(tm.tm_hour, cal->hour)) {
			tm.tm_hour += 1;
			tm.tm_min = 0;
			continue;
		}
		if (!field_matches(tm.tm_min, cal->minute)) {
			tm.tm_min += 1;
			continue;
		}
		tm.tm_isdst = -1;
		return (mktime(&tm));
	}
	return ((time_t)-1);
}

/*
 * The most recent matching instant at or before `before`, or (time_t)-1 if
 * none within the search bound.  Used for persistent (anacron-style) catch-up:
 * a job whose previous occurrence is newer than the last recorded run was
 * missed while the manager (or machine) was down and is due immediately.
 */
time_t
calendar_prev(const struct svc_calendar *cal, time_t before)
{
	struct tm tm;
	time_t t;
	int steps;

	/* Start at the whole minute at or before `before`. */
	t = before - (before % 60);
	if (localtime_r(&t, &tm) == NULL)
		return ((time_t)-1);
	tm.tm_sec = 0;

	for (steps = 0; steps < CAL_MAX_STEPS; steps++) {
		tm.tm_isdst = -1;
		if (mktime(&tm) == (time_t)-1)
			return ((time_t)-1);

		if (!field_matches(tm.tm_mon + 1, cal->month)) {
			/* mday 0 normalises to the last day of the prior month. */
			tm.tm_mday = 0;
			tm.tm_hour = 23;
			tm.tm_min = 59;
			continue;
		}
		if (!field_matches(tm.tm_mday, cal->mday) ||
		    !field_matches(tm.tm_wday, cal->wday)) {
			tm.tm_mday -= 1;
			tm.tm_hour = 23;
			tm.tm_min = 59;
			continue;
		}
		if (!field_matches(tm.tm_hour, cal->hour)) {
			tm.tm_hour -= 1;
			tm.tm_min = 59;
			continue;
		}
		if (!field_matches(tm.tm_min, cal->minute)) {
			tm.tm_min -= 1;
			continue;
		}
		tm.tm_isdst = -1;
		return (mktime(&tm));
	}
	return ((time_t)-1);
}
