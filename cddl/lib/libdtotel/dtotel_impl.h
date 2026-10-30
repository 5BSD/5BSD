/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libdtotel internals shared by dtotel.c and dtotel_agg.c.
 */

#ifndef _DTOTEL_IMPL_H_
#define	_DTOTEL_IMPL_H_

#include <time.h>

#include "dtotel.h"

#define	DTOTEL_MAX_AGG_KEYS	16
#define	DTOTEL_PROF_INTERVAL	10	/* seconds between firing profiles */

/* Aggregation key names parsed from the D source. */
struct dtotel_keynames {
	char		*aggname;
	char		*names[DTOTEL_MAX_AGG_KEYS];
	int		 n;
	struct dtotel_keynames *next;
};

struct dtotel_frames {
	struct oe_frame	*frames;
	size_t		 n, cap;
};

/* Identity of one probe firing: its records share all three. */
struct dtotel_firing {
	int		 valid;
	processorid_t	 cpu;
	uint64_t	 hrtime;
	dtrace_epid_t	 epid;
};

#define	DTOTEL_JAIL_CACHE	32
#define	DTOTEL_GUEST_ATTRS	8

struct dtotel_guest_state {
	uint16_t	 vmid;
	uint64_t	 epoch;
	char		*name;
	struct oe_attr	 attrs[DTOTEL_GUEST_ATTRS];	/* owned strings */
	size_t		 nattrs;
	struct oe_exporter *exporter;	/* NULL until first needed */
	struct dtotel_guest_state *next;
};

struct dtotel_jail {
	int		 jid;
	char		*name;		/* NULL: unknown or not visible */
};

struct dtotel_series;
struct dtotel_prof;
struct dtotel_exseries;

/* Drop kinds (dtrace_dropkind_t) and fault kinds (DTRACEFLT_*) counted. */
#define	DTOTEL_NDROPKINDS	10
#define	DTOTEL_NFAULTS		12	/* 0..9, library, other */

/* Attributes of the pending log record (typed print(), action). */
#define	DTOTEL_BODY_KV		34

struct dtotel {
	dtrace_hdl_t	*dtp;
	struct oe_exporter *exporter;
	char		*profile;
	struct dtotel_keynames *keynames;
	struct timespec	 start;		/* accumulation window start */
	int		 error;

	/* Probe clock: wall = hrtime + offset once anchored. */
	int		 anchored;
	int64_t		 clock_offset;

	/* Secret salt for span and trace ids derived from D keys. */
	uint8_t		 salt[16];
	int		 warned_span;

	/* The event being accumulated. */
	char		*body;
	char		*probe;
	struct timespec	 body_ts;
	struct timespec	 body_observed;
	struct dtotel_firing body_firing;
	uint16_t	 body_vmid;
	struct dtotel_frames kstack;
	struct dtotel_frames ustack;
	int		 in_ustack;
	int		 line_open;	/* last chunk ended mid-line */
	struct dtotel_firing out_firing; /* last firing with any output */
	struct oe_context body_ctx;
	char		*body_exec;	/* execname from a context record */
	pid_t		 body_pid;

	/* A context record that arrived before its firing's text. */
	struct dtotel_firing ctx_firing;
	struct oe_context ctx;
	char		*ctx_exec;
	pid_t		 ctx_pid;

	struct dtotel_jail jails[DTOTEL_JAIL_CACHE];
	int		 njails;

	/* HyperTrace guests. */
	dtotel_guest_exporter_f *guest_exporter;
	void		*guest_arg;
	struct dtotel_guest_state *guests;
	int		 warned_guest;

	/* Series of the latest snapshot (dtotel_agg.c). */
	struct dtotel_series **series;
	struct timespec	 last_snap;
	int		 nsnaps;

	/* Cumulative drop and error counts, exported as metrics. */
	uint64_t	 drops[DTOTEL_NDROPKINDS];
	uint64_t	 faults[DTOTEL_NFAULTS];
	int		 counters_dirty;
	int		 counters_seen;	/* any count was ever made */

	/* The pending record's action and typed attributes. */
	const char	*body_action;	/* static string or NULL */
	struct oe_kv	 body_kv[DTOTEL_BODY_KV];
	char		*body_kvstr[2 * DTOTEL_BODY_KV];	/* owned */
	size_t		 body_nkv;

	/* Trace context of the pending record, or of its firing. */
	uint8_t		 body_trace[OE_TRACE_ID_LEN];
	uint8_t		 body_span[OE_SPAN_ID_LEN];
	uint8_t		 body_tflags;
	struct dtotel_firing tp_firing;	/* a trace record before its line */
	uint8_t		 tp_trace[OE_TRACE_ID_LEN];
	uint8_t		 tp_span[OE_SPAN_ID_LEN];
	uint8_t		 tp_flags;

	/* Profiles (dtotel_prof.c). */
	int		 profiles;
	struct dtotel_prof *prof;	/* NULL until the first sample */
	int		 prof_interval;	/* seconds between firing profiles */

	/* Exemplars waiting for the next snapshot (dtotel_agg.c). */
	struct dtotel_exseries **exseries;
	size_t		 nexseries;
	uint64_t	 exdropped;
	int		 warned_exemplar;
	/* The latest exemplar, for a trace record of its firing. */
	struct dtotel_firing ex_firing;
	struct oe_exemplar *ex_last;
};

/* The exporter for records of a VMID (0: the host). */
struct oe_exporter *dtotel_exporter_for(struct dtotel *, uint16_t vmid,
    const char *target);

const char *dtotel_jail_name(struct dtotel *, int jid);

struct dtotel_keynames *dtotel_parse_keynames(const char *);
void	 dtotel_free_keynames(struct dtotel_keynames *);
void	 dtotel_series_free(struct dtotel *);

/* Profiles (dtotel_prof.c). */
/* The pending stack-only firing as a profile sample. */
void	 dtotel_prof_firing(struct dtotel *);
/*
 * A stack-keyed count()/sum() aggregation record: 1 when it became a
 * profile sample (the caller makes no metric point of it), else 0.
 */
int	 dtotel_prof_agg(struct dtotel *, const dtrace_aggdata_t *,
	    const char *aggname, const struct dtotel_keynames *, int is_sum,
	    int64_t value);
/* An aggregation key rendered as a metric attribute value. */
void	 dtotel_key_string(struct dtotel *, const dtrace_recdesc_t *,
	    caddr_t base, struct oe_buf *);
/*
 * Emit the accumulated profiles: with "aggs", the aggregation profiles
 * of the snapshot just walked too.
 */
void	 dtotel_prof_emit(struct dtotel *, int aggs);
/* Emit the firing profiles when their interval has passed. */
void	 dtotel_prof_tick(struct dtotel *);
void	 dtotel_prof_free(struct dtotel *);

/* Exemplars (dtotel_agg.c). */
void	 dtotel_exemplar_record(struct dtotel *, char *rec,
	    const dtrace_bufdata_t *, const struct dtotel_firing *,
	    const struct timespec *observed);
void	 dtotel_exemplar_trace(struct dtotel *, const struct dtotel_firing *,
	    const uint8_t *trace, const uint8_t *span);
void	 dtotel_exemplars_free(struct dtotel *);

/* Shared helpers of dtotel.c. */
int	 dtotel_same_firing(const struct dtotel_firing *,
	    const struct dtotel_firing *);
uint16_t dtotel_record_vmid(const dtrace_bufdata_t *, const char **target);
void	 dtotel_probe_walltime(const struct dtotel *,
	    const struct dtotel_firing *, const struct timespec *observed,
	    struct timespec *ts);
void	 dtotel_parse_frame(const char *line, struct oe_frame *);

#endif /* !_DTOTEL_IMPL_H_ */
