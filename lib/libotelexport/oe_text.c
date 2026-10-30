/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Line-oriented text exporter.  Prints the event's text body;
 * stack frames indent below event lines.  Aggregation snapshots
 * print as a tabular dump.  The simplest exporter — no batching,
 * no retry, no network; output goes to a sink (stream or rotating
 * file).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "otelexport.h"

struct oe_text {
	struct oe_exporter e;
	struct oe_sink	*sink;
	struct oe_sink	*owned;		/* wrapper sink for oe_text_new() */
};

static int
text_start(struct oe_exporter *e __unused)
{

	return (0);
}

/* Write a finished buffer as one sink record. */
static int
text_put(struct oe_text *t, struct oe_buf *b)
{
	int ret;

	ret = b->error ? -1 : oe_sink_write(t->sink, b->data, b->len);
	oe_buf_free(b);
	return (ret);
}

static int
text_event(struct oe_exporter *e, const struct oe_event *ev)
{
	struct oe_text *t = (struct oe_text *)e;
	struct oe_buf b;
	char frame[256];
	size_t i;

	if (ev->body == NULL || ev->body[0] == '\0')
		return (0);
	/* One record per event so rotation never splits its stacks. */
	oe_buf_init(&b);
	oe_buf_appendf(&b, "%s\n", ev->body);
	for (i = 0; i < ev->nstack; i++) {
		oe_frame_format(&ev->stack[i], frame, sizeof(frame));
		oe_buf_appendf(&b, "    [k] %s\n", frame);
	}
	for (i = 0; i < ev->nustack; i++) {
		oe_frame_format(&ev->ustack[i], frame, sizeof(frame));
		oe_buf_appendf(&b, "    [u] %s\n", frame);
	}
	return (text_put(t, &b));
}

/* "span <name> <duration> [status] trace=... span=... [parent=...]" */
static int
text_span(struct oe_exporter *e, const struct oe_span *sp)
{
	struct oe_text *t = (struct oe_text *)e;
	struct oe_buf b;
	char hex[2 * OE_TRACE_ID_LEN + 1];
	int64_t dur;

	dur = ((int64_t)sp->end.tv_sec - sp->start.tv_sec) * 1000000000 +
	    (sp->end.tv_nsec - sp->start.tv_nsec);
	oe_buf_init(&b);
	oe_buf_appendf(&b, "span %s %jdus", sp->name, (intmax_t)(dur / 1000));
	if (sp->status == OE_STATUS_ERROR)
		oe_buf_appendf(&b, " error%s%s", sp->status_message != NULL ?
		    ": " : "", sp->status_message != NULL ?
		    sp->status_message : "");
	oe_id_hex(sp->trace_id, OE_TRACE_ID_LEN, hex);
	oe_buf_appendf(&b, " trace=%s", hex);
	oe_id_hex(sp->span_id, OE_SPAN_ID_LEN, hex);
	oe_buf_appendf(&b, " span=%s", hex);
	if (!oe_id_is_zero(sp->parent_span_id, OE_SPAN_ID_LEN)) {
		oe_id_hex(sp->parent_span_id, OE_SPAN_ID_LEN, hex);
		oe_buf_appendf(&b, " parent=%s", hex);
	}
	oe_buf_appendstr(&b, "\n");
	return (text_put(t, &b));
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
	struct oe_buf b;
	size_t i, j;

	oe_buf_init(&b);
	oe_buf_appendf(&b, "\n--- aggregation: @%s (%s) profile=%s ---\n",
	    sn->name, agg_kind_name(sn->kind), sn->profile);
	for (i = 0; i < sn->npoints; i++) {
		dp = &sn->points[i];
		oe_buf_appendstr(&b, "  [");
		for (j = 0; j < dp->nattrs; j++)
			oe_buf_appendf(&b, "%s%s", j > 0 ? ", " : "",
			    dp->attrs[j].value);
		if (dp->is_histogram && dp->exp != NULL) {
			/* Power-of-two buckets: (-2^(k+1), -2^k], 0, [2^k, 2^(k+1)). */
			oe_buf_appendstr(&b, "]\n");
			for (j = dp->exp->negative.n; j > 0; j--)
				if (dp->exp->negative.counts[j - 1] != 0)
					oe_buf_appendf(&b, "    -2^%d: %ju\n",
					    (int)(dp->exp->negative.offset +
					    (int32_t)j - 1),
					    (uintmax_t)dp->exp->negative.counts[j - 1]);
			if (dp->exp->zero_count != 0)
				oe_buf_appendf(&b, "    0: %ju\n",
				    (uintmax_t)dp->exp->zero_count);
			for (j = 0; j < dp->exp->positive.n; j++)
				if (dp->exp->positive.counts[j] != 0)
					oe_buf_appendf(&b, "    2^%d: %ju\n",
					    (int)(dp->exp->positive.offset +
					    (int32_t)j),
					    (uintmax_t)dp->exp->positive.counts[j]);
		} else if (dp->is_histogram) {
			oe_buf_appendstr(&b, "]\n");
			for (j = 0; j < dp->nbuckets; j++) {
				if (dp->buckets[j].count == 0)
					continue;
				oe_buf_appendf(&b, "    <= %jd: %jd\n",
				    (intmax_t)dp->buckets[j].upper,
				    (intmax_t)dp->buckets[j].count);
			}
		} else if (dp->is_double)
			oe_buf_appendf(&b, "] %.6g\n", dp->dvalue);
		else if (dp->has_stats)
			oe_buf_appendf(&b, "] count=%ju sum=%.17g\n",
			    (uintmax_t)dp->count, dp->sum);
		else
			oe_buf_appendf(&b, "] %jd\n", (intmax_t)dp->scalar);
	}
	oe_buf_appendstr(&b, "\n");
	return (text_put(t, &b));
}

static int
text_flush(struct oe_exporter *e)
{
	struct oe_text *t = (struct oe_text *)e;

	return (oe_sink_flush(t->sink));
}

static int
text_shutdown(struct oe_exporter *e)
{

	return (text_flush(e));
}

static void
text_free(struct oe_exporter *e)
{
	struct oe_text *t = (struct oe_text *)e;

	(void)oe_sink_close(t->owned);
	free(t);
}

static const struct oe_exporter_ops text_ops = {
	.start = text_start,
	.event = text_event,
	.snapshot = text_snapshot,
	.flush = text_flush,
	.shutdown = text_shutdown,
	.free = text_free,
	.span = text_span,
};

struct oe_exporter *
oe_text_sink_new(struct oe_sink *sink)
{
	struct oe_text *t;

	t = calloc(1, sizeof(*t));
	if (t == NULL)
		return (NULL);
	t->e.ops = &text_ops;
	t->sink = sink;
	return (&t->e);
}

struct oe_exporter *
oe_text_new(FILE *out)
{
	struct oe_sink_config sc;
	struct oe_exporter *e;
	struct oe_sink *sink;

	memset(&sc, 0, sizeof(sc));
	sc.fp = out;
	if ((sink = oe_sink_open(&sc)) == NULL)
		return (NULL);
	if ((e = oe_text_sink_new(sink)) == NULL) {
		(void)oe_sink_close(sink);
		return (NULL);
	}
	((struct oe_text *)e)->owned = sink;
	return (e);
}
