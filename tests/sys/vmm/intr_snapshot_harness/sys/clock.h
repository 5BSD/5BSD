/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Userspace harness shadow of the kernel <sys/clock.h>.  The real header
 * hides 'struct clocktime' and the ct<->ts conversion prototypes behind
 * _KERNEL, so mirror just what vrtc.c consumes.  The test program supplies
 * clock_ts_to_ct()/clock_ct_to_ts() over libc's gmtime_r()/timegm().
 */
#ifndef _KMOCK_SYS_CLOCK_H_
#define	_KMOCK_SYS_CLOCK_H_

#include <sys/types.h>
#include <sys/time.h>

#define	POSIX_BASE_YEAR	1970

struct clocktime {
	int	year;		/* year (4 digit year) */
	int	mon;		/* month (1 - 12) */
	int	day;		/* day (1 - 31) */
	int	hour;		/* hour (0 - 23) */
	int	min;		/* minute (0 - 59) */
	int	sec;		/* second (0 - 59) */
	int	dow;		/* day of week (0 - 6; 0 = Sunday) */
	long	nsec;		/* nano seconds */
};

int clock_ct_to_ts(const struct clocktime *, struct timespec *);
void clock_ts_to_ct(const struct timespec *, struct clocktime *);

#endif /* !_KMOCK_SYS_CLOCK_H_ */
