/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Calendar activation math (launchd StartCalendarInterval).  See
 * activation_calendar.c.  Pure functions with no daemon state, split out so
 * they can be unit-tested directly.
 */

#ifndef SWITCHBOARD_ACTIVATION_CALENDAR_H
#define SWITCHBOARD_ACTIVATION_CALENDAR_H

#include <time.h>

#include "switchboard_manifest.h"

/*
 * Next local wall-clock instant strictly after `after` matching every set
 * field of `cal` (AND across specified fields; unset = wildcard).  Returns
 * (time_t)-1 if unsatisfiable within the search bound.
 */
time_t	calendar_next(const struct svc_calendar *cal, time_t after);

/*
 * Most recent matching instant at or before `before`, for persistent catch-up.
 * (time_t)-1 if none within the bound.
 */
time_t	calendar_prev(const struct svc_calendar *cal, time_t before);

#endif /* SWITCHBOARD_ACTIVATION_CALENDAR_H */
