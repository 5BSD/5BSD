/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libdtotel — bridge from a libdtrace consumer to a libotelexport
 * exporter.  Shared by bsdinstruments(8) and dtrace(1) so both turn
 * the same D output into the same OpenTelemetry records:
 *
 *  - printf/trace output becomes log records, one per output line,
 *    with stack()/ustack() frames attached to the line of the same
 *    probe firing;
 *  - aggregations become metric snapshots;
 *  - records whose text starts with "\037otel." are structured
 *    records (clock anchors, spans, context) rather than log lines.
 *
 * Probe time.  libdtrace hands every record the probe's high
 * resolution timestamp (the D "timestamp" clock), not wall time.  The
 * clock program (dtotel_clock_program()) prints walltimestamp and
 * timestamp from the same firing at BEGIN and once a second; the
 * bridge keeps their difference and stamps each record with
 * timestamp + offset, i.e. the probe's own wall time.  Records seen
 * before the first anchor fall back to the consumer's clock.  The
 * consumer's read time is always kept as the observed time.
 */

#ifndef _DTOTEL_H_
#define	_DTOTEL_H_

#include <dtrace.h>

#include "otelexport.h"

/* Prefix of every structured record; see dtotel(3) in dtotel.c. */
#define	DTOTEL_RECORD_PREFIX	"\037otel."

struct dtotel;

struct dtotel_config {
	dtrace_hdl_t	*dtp;
	struct oe_exporter *exporter;	/* borrowed */
	const char	*profile;	/* profile/script name for records */
	const char	*source;	/* D source (agg key names); NULL ok */
};

struct dtotel	*dtotel_open(const struct dtotel_config *);
void		 dtotel_close(struct dtotel *);

/* Install the buffered-output handler on the handle. */
int		 dtotel_handle(struct dtotel *);

/*
 * D source of the clock program.  Compile and enable it along with
 * the user's program (before it, so its BEGIN fires first).
 */
const char	*dtotel_clock_program(void);

/* Mark the start of the accumulation window (call at dtrace_go()). */
void		 dtotel_started(struct dtotel *);

/* Emit the event still being accumulated, if any. */
void		 dtotel_flush(struct dtotel *);

/* Snapshot and walk the aggregations, emitting metric snapshots. */
int		 dtotel_aggregate(struct dtotel *);

/* Forward kernel drop counts to the exporter. */
void		 dtotel_drops(struct dtotel *, uint64_t);

/* Nonzero once an exporter call failed. */
int		 dtotel_error(const struct dtotel *);

/* The handlers themselves, for consumers that chain them. */
int		 dtotel_buffered(const dtrace_bufdata_t *, void *);

#endif /* !_DTOTEL_H_ */
