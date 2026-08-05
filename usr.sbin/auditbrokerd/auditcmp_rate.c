/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "auditcmp_rate.h"

#define	NSEC_PER_SEC	1000000000ULL

static bool
timespec_valid(const struct timespec *value)
{

	return (value != NULL && value->tv_sec >= 0 && value->tv_nsec >= 0 &&
	    value->tv_nsec < (long)NSEC_PER_SEC);
}

int
auditcmp_rate_init(struct auditcmp_rate *rate, uint64_t per_second,
    uint64_t burst, const struct timespec *now)
{

	if (rate == NULL || per_second == 0 || burst == 0 ||
	    !timespec_valid(now))
		return (errno = EINVAL, -1);
	rate->rate_per_second = per_second;
	rate->burst = burst;
	rate->tokens = burst;
	rate->remainder = 0;
	rate->refill = *now;
	return (0);
}

bool
auditcmp_rate_allow_at(struct auditcmp_rate *rate, const struct timespec *now)
{
	uint64_t seconds, nanoseconds, elapsed, quotient, remainder;
	__uint128_t scaled;

	if (rate == NULL || rate->rate_per_second == 0 || rate->burst == 0 ||
	    !timespec_valid(now) ||
	    now->tv_sec < rate->refill.tv_sec ||
	    (now->tv_sec == rate->refill.tv_sec &&
	    now->tv_nsec < rate->refill.tv_nsec))
		return (false);
	seconds = (uint64_t)(now->tv_sec - rate->refill.tv_sec);
	if (now->tv_nsec >= rate->refill.tv_nsec) {
		nanoseconds = (uint64_t)(now->tv_nsec - rate->refill.tv_nsec);
	} else {
		if (seconds == 0)
			return (false);
		seconds--;
		nanoseconds = NSEC_PER_SEC -
		    (uint64_t)(rate->refill.tv_nsec - now->tv_nsec);
	}
	if (seconds > UINT64_MAX / NSEC_PER_SEC)
		elapsed = UINT64_MAX;
	else {
		elapsed = seconds * NSEC_PER_SEC;
		elapsed = nanoseconds > UINT64_MAX - elapsed ?
		    UINT64_MAX : elapsed + nanoseconds;
	}
	scaled = (__uint128_t)elapsed * rate->rate_per_second +
	    rate->remainder;
	quotient = scaled / NSEC_PER_SEC > UINT64_MAX ? UINT64_MAX :
	    (uint64_t)(scaled / NSEC_PER_SEC);
	remainder = (uint64_t)(scaled % NSEC_PER_SEC);
	if (quotient != 0) {
		rate->tokens = quotient >= rate->burst - rate->tokens ?
		    rate->burst : rate->tokens + quotient;
		rate->remainder = rate->tokens == rate->burst ? 0 : remainder;
		rate->refill = *now;
	} else {
		rate->remainder = remainder;
		rate->refill = *now;
	}
	if (rate->tokens == 0)
		return (false);
	rate->tokens--;
	return (true);
}
