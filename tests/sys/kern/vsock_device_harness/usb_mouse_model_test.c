/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <limits.h>
#include <stdint.h>

#include <atf-c.h>

#include "usb_mouse_model.h"

ATF_TC_WITHOUT_HEAD(axis_boundaries);
ATF_TC_BODY(axis_boundaries, tc)
{

	ATF_CHECK_EQ(umouse_scale_axis(0, 65535), 0);
	ATF_CHECK_EQ(umouse_scale_axis(65535, 65535), INT16_MAX);
	ATF_CHECK_EQ(umouse_scale_axis(32767, 65535), 16383);
	ATF_CHECK_EQ(umouse_scale_axis(32768, 65535), 16383);
}

ATF_TC_WITHOUT_HEAD(axis_clamps_outside_framebuffer);
ATF_TC_BODY(axis_clamps_outside_framebuffer, tc)
{

	ATF_CHECK_EQ(umouse_scale_axis(-1, 640), 0);
	ATF_CHECK_EQ(umouse_scale_axis(INT_MIN, 640), 0);
	ATF_CHECK_EQ(umouse_scale_axis(641, 640), INT16_MAX);
	ATF_CHECK_EQ(umouse_scale_axis(INT_MAX, 640), INT16_MAX);
	ATF_CHECK_EQ(umouse_scale_axis(1, 0), 0);
	ATF_CHECK_EQ(umouse_scale_axis(1, -1), 0);
}

ATF_TC_WITHOUT_HEAD(axis_monotonic_and_in_range);
ATF_TC_BODY(axis_monotonic_and_in_range, tc)
{
	int16_t previous;

	previous = 0;
	for (int coordinate = -2; coordinate <= 1002; coordinate++) {
		int16_t value;

		value = umouse_scale_axis(coordinate, 1000);
		ATF_CHECK(value >= 0);
		ATF_CHECK(value <= INT16_MAX);
		ATF_CHECK(value >= previous);
		previous = value;
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, axis_boundaries);
	ATF_TP_ADD_TC(tp, axis_clamps_outside_framebuffer);
	ATF_TP_ADD_TC(tp, axis_monotonic_and_in_range);
	return (atf_no_error());
}
