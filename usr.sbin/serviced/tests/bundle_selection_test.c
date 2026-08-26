/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <atf-c.h>

#include "bundle_selection.h"

#define CHECK(expected, current_id, current_sequence, current_system, \
    candidate_id, candidate_sequence, candidate_system) \
	ATF_CHECK_EQ((expected), bundle_selection_compare((current_id), \
	    (current_sequence), (current_system), (candidate_id), \
	    (candidate_sequence), (candidate_system)))

ATF_TC_WITHOUT_HEAD(order_independent_highest_sequence);
ATF_TC_BODY(order_independent_highest_sequence, tc)
{

	CHECK(BUNDLE_SELECTION_REPLACE_CURRENT, "org.test.app", 1, true,
	    "org.test.app", 2, true);
	CHECK(BUNDLE_SELECTION_KEEP_CURRENT, "org.test.app", 2, true,
	    "org.test.app", 1, true);
	CHECK(BUNDLE_SELECTION_REPLACE_CURRENT, "org.test.app", 1, false,
	    "org.test.app", UINT64_MAX, false);
}

ATF_TC_WITHOUT_HEAD(conflicts_fail_closed);
ATF_TC_BODY(conflicts_fail_closed, tc)
{

	CHECK(BUNDLE_SELECTION_SEQUENCE_CONFLICT, "org.test.app", 7, true,
	    "org.test.app", 7, true);
	CHECK(BUNDLE_SELECTION_ORIGIN_CONFLICT, "org.test.app", 7, true,
	    "org.test.app", 8, false);
	CHECK(BUNDLE_SELECTION_ORIGIN_CONFLICT, "org.test.app", 7, false,
	    "org.test.app", 8, true);
}

ATF_TC_WITHOUT_HEAD(distinct_and_invalid_inputs);
ATF_TC_BODY(distinct_and_invalid_inputs, tc)
{

	CHECK(BUNDLE_SELECTION_DISTINCT, "org.test.one", 1, true,
	    "org.test.two", 1, false);
	CHECK(BUNDLE_SELECTION_INVALID, NULL, 1, true, "org.test.app", 2, true);
	CHECK(BUNDLE_SELECTION_INVALID, "", 1, true, "org.test.app", 2, true);
	CHECK(BUNDLE_SELECTION_INVALID, "org.test.app", 0, true,
	    "org.test.app", 2, true);
	CHECK(BUNDLE_SELECTION_INVALID, "org.test.app", 1, true, NULL, 2, true);
	CHECK(BUNDLE_SELECTION_INVALID, "org.test.app", 1, true, "", 2, true);
	CHECK(BUNDLE_SELECTION_INVALID, "org.test.app", 1, true,
	    "org.test.app", 0, true);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, order_independent_highest_sequence);
	ATF_TP_ADD_TC(tp, conflicts_fail_closed);
	ATF_TP_ADD_TC(tp, distinct_and_invalid_inputs);
	return (atf_no_error());
}
