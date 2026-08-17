/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Line-oriented stdout exporter.  Prints the event's text body;
 * stack frames indent below event lines.  Aggregation snapshots
 * print as a tabular dump.  The simplest exporter — no batching,
 * no retry, no network.
 */

#include <stdio.h>
#include <stdlib.h>

#include "otelexport.h"

struct oe_text {
	struct oe_exporter e;
	FILE		*out;
};

static int
text_start(struct oe_exporter *e __unused)
{

	return (0);
}

static int
text_event(struct oe_exporter *e, const struct oe_event *ev)
{
	struct oe_text *t = (struct oe_text *)e;
	char frame[256];
	size_t i;

	if (ev->body == NULL || ev->body[0] == '\0')
		return (0);
	fprintf(t->out, "%s\n", ev->body);
	for (i = 0; i < ev->nstack; i++) {
		oe_frame_format(&ev->stack[i], frame, sizeof(frame));
		fprintf(t->out, "    [k] %s\n", frame);
	}
	for (i = 0; i < ev->nustack; i++) {
		oe_frame_format(&ev->ustack[i], frame, sizeof(frame));
		fprintf(t->out, "    [u] %s\n", frame);
	}
	return (0);
}

static const char *
agg_kind_name(enum oe_agg_kind kind)
{

	switch (kind) {
	case OE_AGG_COUNT:	return ("count");
	case OE_AGG_SUM:	return ("sum");
	case OE_AGG_MIN:	return ("min");
	case OE_AGG_MAX:	return ("max");
	case OE_AGG_AVG:	return ("avg");
	case OE_AGG_STDDEV:	return ("stddev");
	case OE_AGG_QUANTIZE:	return ("quantize");
	case OE_AGG_LQUANTIZE:	return ("lquantize");
	case OE_AGG_LLQUANTIZE:	return ("llquantize");
	}
	return ("unknown");
}

static int
text_snapshot(struct oe_exporter *e, const struct oe_snapshot *sn)
{
	struct oe_text *t = (struct oe_text *)e;
	const struct oe_datapoint *dp;
	size_t i, j;

	fprintf(t->out, "\n--- aggregation: @%s (%s) profile=%s ---\n",
	    sn->name, agg_kind_name(sn->kind), sn->profile);
	for (i = 0; i < sn->npoints; i++) {
		dp = &sn->points[i];
		fprintf(t->out, "  [");
		for (j = 0; j < dp->nattrs; j++)
			fprintf(t->out, "%s%s", j > 0 ? ", " : "",
			    dp->attrs[j].value);
		if (dp->is_histogram) {
			fprintf(t->out, "]\n");
			for (j = 0; j < dp->nbuckets; j++) {
				if (dp->buckets[j].count == 0)
					continue;
				fprintf(t->out, "    <= %jd: %jd\n",
				    (intmax_t)dp->buckets[j].upper,
				    (intmax_t)dp->buckets[j].count);
			}
		} else
			fprintf(t->out, "] %jd\n", (intmax_t)dp->scalar);
	}
	fprintf(t->out, "\n");
	return (0);
}

static int
text_flush(struct oe_exporter *e)
{
	struct oe_text *t = (struct oe_text *)e;

	fflush(t->out);
	return (0);
}

static int
text_shutdown(struct oe_exporter *e)
{

	return (text_flush(e));
}

static void
text_free(struct oe_exporter *e)
{

	free(e);
}

static const struct oe_exporter_ops text_ops = {
	.start = text_start,
	.event = text_event,
	.snapshot = text_snapshot,
	.flush = text_flush,
	.shutdown = text_shutdown,
	.free = text_free,
};

struct oe_exporter *
oe_text_new(FILE *out)
{
	struct oe_text *t;

	t = calloc(1, sizeof(*t));
	if (t == NULL)
		return (NULL);
	t->e.ops = &text_ops;
	t->out = out;
	return (&t->e);
}
