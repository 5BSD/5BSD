/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the Capsule plane-free boot decision (capsule_plane.h
 * capsule_plane_disabled): the exact set of capability_plane values that make
 * Capsule hand PID 1 to stock /sbin/init instead of booting the plane.
 */
#include <stdbool.h>

#include <atf-c.h>

#include "capsule_plane.h"

/* The accepted "disable the plane" spellings: NO/off case-insensitive, "0". */
ATF_TC_WITHOUT_HEAD(disabling_values);
ATF_TC_BODY(disabling_values, tc)
{

	ATF_CHECK(capsule_plane_disabled("NO"));
	ATF_CHECK(capsule_plane_disabled("no"));
	ATF_CHECK(capsule_plane_disabled("No"));
	ATF_CHECK(capsule_plane_disabled("off"));
	ATF_CHECK(capsule_plane_disabled("OFF"));
	ATF_CHECK(capsule_plane_disabled("0"));
}

/* Everything else keeps the plane, including near-misses and NULL. */
ATF_TC_WITHOUT_HEAD(plane_keeping_values);
ATF_TC_BODY(plane_keeping_values, tc)
{

	ATF_CHECK(!capsule_plane_disabled("YES"));
	ATF_CHECK(!capsule_plane_disabled("yes"));
	ATF_CHECK(!capsule_plane_disabled("1"));
	ATF_CHECK(!capsule_plane_disabled("00"));	/* only exact "0" disables */
	ATF_CHECK(!capsule_plane_disabled("nope"));
	ATF_CHECK(!capsule_plane_disabled("offline"));
	ATF_CHECK(!capsule_plane_disabled(""));
	ATF_CHECK(!capsule_plane_disabled(NULL));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, disabling_values);
	ATF_TP_ADD_TC(tp, plane_keeping_values);
	return (atf_no_error());
}
