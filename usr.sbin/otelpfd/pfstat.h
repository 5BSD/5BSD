/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Conversion of pf(4) status (DIOCGETSTATUS) into OTLP metrics.
 */

#ifndef _PFSTAT_H_
#define	_PFSTAT_H_

#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <time.h>

#include "otelexport.h"

#define	PFSTAT_PROFILE	"pf"

/*
 * Emit one sample of st, read at wall time ts and uptime (CLOCK_UPTIME
 * seconds), as metric snapshots on e.  Returns the number of snapshots
 * emitted, or -1 if the exporter failed.
 */
int	pfstat_emit(struct oe_exporter *e, const struct pf_status *st,
	    const struct timespec *ts, time_t uptime);

#endif /* !_PFSTAT_H_ */
