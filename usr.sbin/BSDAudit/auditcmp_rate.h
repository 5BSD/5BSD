/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AUDITCMP_RATE_H_
#define	_AUDITCMP_RATE_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct auditcmp_rate {
	uint64_t	 rate_per_second;
	uint64_t	 burst;
	uint64_t	 tokens;
	uint64_t	 remainder;
	struct timespec	 refill;
};

int	auditcmp_rate_init(struct auditcmp_rate *, uint64_t, uint64_t,
	    const struct timespec *);
bool	auditcmp_rate_allow_at(struct auditcmp_rate *,
	    const struct timespec *);

#endif
