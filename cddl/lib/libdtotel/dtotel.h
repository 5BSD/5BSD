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
 *    records (clock anchors, spans, context, trace context) rather
 *    than log lines; span records become OTLP spans;
 *  - drops, runtime errors, exit() and HyperTrace guest lifetimes
 *    become counters and named log events.
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

/*
 * HyperTrace.  Records of guest probes (a non-zero VMID in the
 * enabled probe description) belong to the guest, not the host: each
 * guest gets its own exporter, and with it its own OTel resource,
 * created on demand by the consumer's callback from the guest's
 * identity.  "attrs" are resource attributes the guest supplied with
 * "\037otel.resource" records (for example host.name); a change
 * replaces the guest's exporter.
 */
struct dtotel_guest {
	uint16_t	 vmid;
	uint64_t	 epoch;		/* host-supplied VM lifetime token */
	const char	*name;		/* VM name */
	const struct oe_attr *attrs;
	size_t		 nattrs;
};

typedef struct oe_exporter *dtotel_guest_exporter_f(void *,
    const struct dtotel_guest *);

struct dtotel_config {
	dtrace_hdl_t	*dtp;
	struct oe_exporter *exporter;	/* borrowed; the host's records */
	const char	*profile;	/* profile/script name for records */
	const char	*source;	/* D source (agg key names); NULL ok */
	/* NULL: guest records go to the host exporter. */
	dtotel_guest_exporter_f *guest_exporter;
	void		*guest_arg;
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

/*
 * End of one probe firing, for consumers whose probe callback sees
 * every firing (dtrace(1)): without "quiet", a firing that printed
 * nothing still produces a record naming its probe, as dtrace(1)'s
 * default output does.
 */
void		 dtotel_firing_end(struct dtotel *, const dtrace_probedata_t *,
		    int quiet);

/*
 * Snapshot and walk the aggregations, emitting metric snapshots (and
 * the drop and error counters, see dtotel_report()).
 */
int		 dtotel_aggregate(struct dtotel *);

/*
 * Count drops of a kind (dtrace_dropkind_t, from a drop handler).  They
 * are exported by dtotel_report() as the cumulative monotonic Sum
 * "<scope>.drops" with the attribute dtrace.drop.kind.
 */
void		 dtotel_drops(struct dtotel *, int kind, uint64_t n);

/*
 * A DTrace runtime error (from an error handler): an ERROR log record
 * with event name "dtrace.error" and the probe, fault, address, action
 * and DIF offset as attributes, counted in "<scope>.errors" with the
 * attribute dtrace.fault.
 */
void		 dtotel_error_record(struct dtotel *, const dtrace_errdata_t *);

/* The D program called exit(status): a "dtrace.exit" log record. */
void		 dtotel_exit(struct dtotel *, int status);

/*
 * Emit the drop and error counters when they changed since the last
 * report, or with "force" whenever any was ever counted.  Consumers
 * call it about once a second; dtotel_aggregate() forces it.
 */
void		 dtotel_report(struct dtotel *, int force);

/*
 * Record (or refresh) a guest's identity as the consumer learns it,
 * e.g. when a guest program is received.  A new epoch for a known
 * VMID starts a new resource.
 */
int		 dtotel_guest(struct dtotel *, uint16_t vmid, uint64_t epoch,
		    const char *name);

/*
 * Flush the guest exporters (the host's belongs to the consumer):
 * file output writes their pending batches at the same points as the
 * host's.  -1 if any flush failed.
 */
int		 dtotel_flush_guests(struct dtotel *);

/* Flush, shut down and release the guest exporters. */
int		 dtotel_shutdown(struct dtotel *);

/* Nonzero once an exporter call failed. */
int		 dtotel_error(const struct dtotel *);

/* The handlers themselves, for consumers that chain them. */
int		 dtotel_buffered(const dtrace_bufdata_t *, void *);

#endif /* !_DTOTEL_H_ */
