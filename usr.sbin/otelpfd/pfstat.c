/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * pf(4) status to OTLP metrics.  The source is struct pf_status from
 * DIOCGETSTATUS, the same structure "pfctl -s info" prints; nothing is
 * parsed from text.
 *
 * Current values (states, source nodes, fragments, running) are gauges;
 * event counters are cumulative monotonic sums starting when pf was
 * enabled or its counters were cleared (pf_status.since).  Metric names
 * follow the "<scope>.<profile>.<name>" scheme of libotelexport, so
 * they read otelpfd.pf.<name>; address family and direction use the
 * semantic-convention attributes network.type (ipv4, ipv6) and
 * network.io.direction (receive for pf "in", transmit for "out").
 */

#include <stdint.h>
#include <string.h>

#include "pfstat.h"

static const char *const reason_names[] = PFRES_NAMES;
static const char *const limit_names[] = LCNT_NAMES;
static const char *const op_names[] = { "search", "insert", "removal" };
static const char *const af_names[] = { "ipv4", "ipv6" };
static const char *const dir_names[] = { "receive", "transmit" };

_Static_assert(nitems(reason_names) == PFRES_MAX + 1, "PFRES_NAMES");
_Static_assert(nitems(limit_names) == LCNT_MAX + 1, "LCNT_NAMES");
_Static_assert(FCNT_MAX == 3 && SCNT_MAX == 3 && NCNT_MAX == 3,
    "operation counters");

#define	MAXPOINTS	32
#define	MAXATTRS	3

struct sample {
	struct oe_exporter	*e;
	const struct timespec	*ts;
	struct timespec		 start;
	struct oe_datapoint	 dp[MAXPOINTS];
	struct oe_attr		 attrs[MAXPOINTS][MAXATTRS];
	size_t			 n;
	int			 emitted;
	int			 failed;
};

static void
point(struct sample *s, uint64_t value, const char *k1, const char *v1,
    const char *k2, const char *v2, const char *k3, const char *v3)
{
	struct oe_datapoint *dp;
	struct oe_attr *a;

	dp = &s->dp[s->n];
	a = s->attrs[s->n];
	memset(dp, 0, sizeof(*dp));
	dp->attrs = a;
	if (k1 != NULL) {
		a[dp->nattrs].name = k1;
		a[dp->nattrs++].value = v1;
	}
	if (k2 != NULL) {
		a[dp->nattrs].name = k2;
		a[dp->nattrs++].value = v2;
	}
	if (k3 != NULL) {
		a[dp->nattrs].name = k3;
		a[dp->nattrs++].value = v3;
	}
	/* OTLP asInt is int64; pf counters never get near 2^63. */
	dp->scalar = value > INT64_MAX ? INT64_MAX : (int64_t)value;
	s->n++;
}

static void
flush(struct sample *s, const char *name, enum oe_agg_kind kind)
{
	struct oe_snapshot sn;

	memset(&sn, 0, sizeof(sn));
	sn.ts = *s->ts;
	sn.profile = PFSTAT_PROFILE;
	sn.name = name;
	sn.kind = kind;
	sn.points = s->dp;
	sn.npoints = s->n;
	if (kind == OE_AGG_COUNT)
		sn.start = s->start;
	if (oe_snapshot(s->e, &sn) != 0)
		s->failed = 1;
	s->emitted++;
	s->n = 0;
}

static void
gauge(struct sample *s, const char *name, uint64_t value)
{

	point(s, value, NULL, NULL, NULL, NULL, NULL, NULL);
	flush(s, name, OE_AGG_MAX);
}

int
pfstat_emit(struct oe_exporter *e, const struct pf_status *st,
    const struct timespec *ts, time_t uptime)
{
	struct sample s;
	int af, dir, i;

	memset(&s, 0, sizeof(s));
	s.e = e;
	s.ts = ts;
	/*
	 * since is in uptime seconds; it is zero, or ahead of the given
	 * uptime for a replayed status, when the start is unknown.
	 */
	if (st->since > 0 && st->since <= uptime && ts->tv_sec > uptime -
	    st->since) {
		s.start.tv_sec = ts->tv_sec - (uptime - st->since);
		s.start.tv_nsec = 0;
	}

	gauge(&s, "running", st->running != 0);
	gauge(&s, "states", st->states);
	gauge(&s, "states_halfopen", st->states_halfopen);
	gauge(&s, "src_nodes", st->src_nodes);
	gauge(&s, "fragments", st->fragments);
	gauge(&s, "syncookies_active", st->syncookies_active != 0);

	for (i = 0; i < FCNT_MAX; i++)
		point(&s, st->fcounters[i], "operation", op_names[i], NULL,
		    NULL, NULL, NULL);
	flush(&s, "state_operations", OE_AGG_COUNT);
	for (i = 0; i < SCNT_MAX; i++)
		point(&s, st->scounters[i], "operation", op_names[i], NULL,
		    NULL, NULL, NULL);
	flush(&s, "src_node_operations", OE_AGG_COUNT);
	for (i = 0; i < NCNT_MAX; i++)
		point(&s, st->ncounters[i], "operation", op_names[i], NULL,
		    NULL, NULL, NULL);
	flush(&s, "fragment_operations", OE_AGG_COUNT);

	for (i = 0; i < PFRES_MAX; i++)
		point(&s, st->counters[i], "reason", reason_names[i], NULL,
		    NULL, NULL, NULL);
	flush(&s, "reasons", OE_AGG_COUNT);
	for (i = 0; i < LCNT_MAX; i++)
		point(&s, st->lcounters[i], "limit", limit_names[i], NULL,
		    NULL, NULL, NULL);
	flush(&s, "limits", OE_AGG_COUNT);

	for (af = 0; af < 2; af++)
		for (dir = 0; dir < 2; dir++) {
			point(&s, st->pcounters[af][dir][PF_PASS],
			    "network.type", af_names[af],
			    "network.io.direction", dir_names[dir], "action",
			    "pass");
			point(&s, st->pcounters[af][dir][PF_DROP],
			    "network.type", af_names[af],
			    "network.io.direction", dir_names[dir], "action",
			    "block");
		}
	flush(&s, "packets", OE_AGG_COUNT);
	for (af = 0; af < 2; af++)
		for (dir = 0; dir < 2; dir++)
			point(&s, st->bcounters[af][dir], "network.type",
			    af_names[af], "network.io.direction",
			    dir_names[dir], NULL, NULL);
	flush(&s, "bytes", OE_AGG_COUNT);

	return (s.failed ? -1 : s.emitted);
}
