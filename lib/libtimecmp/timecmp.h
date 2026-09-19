/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libtimecmp: client to system.Time (BSDTime).  A holder of a system.Time
 * channel reads the wall clock, and -- if the provider's per-label policy
 * grants it -- steps or slews it, instead of calling clock_settime(2) /
 * adjtime(2) directly (which need PRIV_SETTIMEOFDAY the sandboxed caller lacks).
 */
#ifndef _TIMECMP_H_
#define	_TIMECMP_H_

#include <time.h>

#include "timecmp_protocol.h"

struct timecmp_client;

__BEGIN_DECLS

/* Open (and close) a session to system.Time. */
int	timecmp_client_open(struct timecmp_client **);
void	timecmp_client_close(struct timecmp_client *);

/* Read the current CLOCK_REALTIME through the broker. */
int	timecmp_get(struct timecmp_client *, struct timespec *);

/*
 * Step CLOCK_REALTIME to an absolute time (clock_settime).  Fails EPERM if the
 * caller's label is not granted set authority by the provider policy.
 */
int	timecmp_set(struct timecmp_client *, const struct timespec *);

/*
 * Slew the clock by a signed delta (adjtime).  `old`, if non-NULL, receives the
 * correction that was still pending.  Same policy gate as set.
 */
int	timecmp_adjust(struct timecmp_client *, const struct timeval *delta,
	    struct timeval *old);

__END_DECLS

#endif /* _TIMECMP_H_ */
