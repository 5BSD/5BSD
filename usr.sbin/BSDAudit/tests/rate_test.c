/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "auditcmp_rate.h"
#include "auditcmp_test.h"

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct auditcmp_rate rate;
	struct timespec now = { .tv_sec = 1, .tv_nsec = 0 };
	struct timespec invalid = { .tv_sec = 1, .tv_nsec = 1000000000L };

	ATF_CHECK_ERRNO(EINVAL,
	    auditcmp_rate_init(NULL, 1, 1, &now) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    auditcmp_rate_init(&rate, 0, 1, &now) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    auditcmp_rate_init(&rate, 1, 0, &now) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    auditcmp_rate_init(&rate, 1, 1, &invalid) == -1);
}

ATF_TC_WITHOUT_HEAD(burst_and_refill);
ATF_TC_BODY(burst_and_refill, tc)
{
	struct auditcmp_rate rate;
	struct timespec now = { .tv_sec = 10, .tv_nsec = 0 };
	unsigned int i;

	ATF_REQUIRE_EQ(0, auditcmp_rate_init(&rate, 100, 200, &now));
	for (i = 0; i < 200; i++)
		ATF_CHECK(auditcmp_rate_allow_at(&rate, &now));
	ATF_CHECK(!auditcmp_rate_allow_at(&rate, &now));
	now.tv_nsec = 9999999;
	ATF_CHECK(!auditcmp_rate_allow_at(&rate, &now));
	now.tv_nsec = 10000000;
	ATF_CHECK(auditcmp_rate_allow_at(&rate, &now));
	ATF_CHECK(!auditcmp_rate_allow_at(&rate, &now));
	now.tv_sec++;
	ATF_CHECK(auditcmp_rate_allow_at(&rate, &now));
	ATF_CHECK_EQ(99, rate.tokens);
}

ATF_TC_WITHOUT_HEAD(fractional_and_clock_regression);
ATF_TC_BODY(fractional_and_clock_regression, tc)
{
	struct auditcmp_rate rate;
	struct timespec now = { .tv_sec = 20, .tv_nsec = 0 };
	struct timespec earlier;

	ATF_REQUIRE_EQ(0, auditcmp_rate_init(&rate, 3, 1, &now));
	ATF_REQUIRE(auditcmp_rate_allow_at(&rate, &now));
	now.tv_nsec = 200000000;
	ATF_CHECK(!auditcmp_rate_allow_at(&rate, &now));
	now.tv_nsec = 333333333;
	ATF_CHECK(!auditcmp_rate_allow_at(&rate, &now));
	now.tv_nsec = 333333334;
	ATF_CHECK(auditcmp_rate_allow_at(&rate, &now));
	earlier = now;
	earlier.tv_nsec--;
	ATF_CHECK(!auditcmp_rate_allow_at(&rate, &earlier));
}

ATF_TC_WITHOUT_HEAD(saturates_at_burst);
ATF_TC_BODY(saturates_at_burst, tc)
{
	struct auditcmp_rate rate;
	struct timespec now = { .tv_sec = 1, .tv_nsec = 0 };
	unsigned int i;

	ATF_REQUIRE_EQ(0, auditcmp_rate_init(&rate, UINT64_MAX, 4, &now));
	ATF_REQUIRE(auditcmp_rate_allow_at(&rate, &now));
	now.tv_sec = 100;
	for (i = 0; i < 4; i++)
		ATF_CHECK(auditcmp_rate_allow_at(&rate, &now));
	ATF_CHECK(!auditcmp_rate_allow_at(&rate, &now));
}

/*
 * A1 regression: the admission limiter lives in the parent, keyed by provider
 * label, so it must persist across connections.  Exhaust a label's parent bucket
 * and then "reconnect" (resolve the same label again, as a fresh accept would):
 * the bucket must be the same, still-exhausted one — the burst is NOT refilled by
 * reconnecting.  A distinct label keeps its own independent, full bucket.
 */
ATF_TC_WITHOUT_HEAD(per_label_bucket_survives_reconnect);
ATF_TC_BODY(per_label_bucket_survives_reconnect, tc)
{
	struct label_rate *table;
	struct auditcmp_rate *first, *again, *other;
	struct timespec now = { .tv_sec = 100, .tv_nsec = 0 };
	unsigned int i;

	(void)tc;
	table = auditcmp_test_accept_table();
	ATF_REQUIRE(table != NULL);

	/* First connection for a label: AUDITCMP_ACCEPT_RATE_BURST (16) tokens. */
	first = auditcmp_test_accept_lookup(table, "system.Log", &now);
	ATF_REQUIRE(first != NULL);
	for (i = 0; i < 16; i++)
		ATF_CHECK(auditcmp_rate_allow_at(first, &now));
	ATF_CHECK(!auditcmp_rate_allow_at(first, &now));	/* burst exhausted */

	/*
	 * Reconnecting for the same label at the same instant resolves to the
	 * SAME bucket, which is still exhausted.  A per-session bucket would have
	 * been re-initialised to a full burst here; the parent bucket is not.
	 */
	again = auditcmp_test_accept_lookup(table, "system.Log", &now);
	ATF_CHECK_EQ(first, again);
	ATF_CHECK(!auditcmp_rate_allow_at(again, &now));

	/* A different label is isolated: its own bucket starts full. */
	other = auditcmp_test_accept_lookup(table, "system.Network", &now);
	ATF_REQUIRE(other != NULL);
	ATF_CHECK(other != first);
	ATF_CHECK(auditcmp_rate_allow_at(other, &now));

	free(table);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, burst_and_refill);
	ATF_TP_ADD_TC(tp, fractional_and_clock_regression);
	ATF_TP_ADD_TC(tp, saturates_at_burst);
	ATF_TP_ADD_TC(tp, per_label_bucket_survives_reconnect);
	return (atf_no_error());
}
