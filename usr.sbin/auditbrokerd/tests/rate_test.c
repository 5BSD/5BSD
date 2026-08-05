/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

#include "auditcmp_rate.h"

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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, burst_and_refill);
	ATF_TP_ADD_TC(tp, fractional_and_clock_regression);
	ATF_TP_ADD_TC(tp, saturates_at_burst);
	return (atf_no_error());
}
