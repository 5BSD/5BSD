/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * JSONL exporter — one JSON object per event or span on its own
 * line, so output pipes cleanly into jq, Loki, Vector, Splunk,
 * fluentd.  Spans carry "type":"span"; events have no "type" (the
 * original shape) so existing consumers keep working.  Both carry an
 * "attributes" object with the semantic-convention context.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "otelexport.h"
#include "oe_otlpenc.h"

struct oe_jsonl {
	struct oe_exporter e;
	struct oe_sink	*sink;
	struct oe_sink	*owned;		/* wrapper sink for oe_jsonl_new() */
	char		*profile;
};

static int
jsonl_start(struct oe_exporter *e __unused)
{

	return (0);
}

static void
jsonl_stack_array(struct oe_buf *b, const char *key,
    const struct oe_frame *frames, size_t n)
{
	char frame[256];
	size_t i;

	if (n == 0)
		return;
	oe_buf_appendf(b, ",\"%s\":[", key);
	for (i = 0; i < n; i++) {
		oe_frame_format(&frames[i], frame, sizeof(frame));
		if (i > 0)
			oe_buf_appendstr(b, ",");
		oe_buf_appendstr(b, "\"");
		oe_buf_appendjson(b, frame);
		oe_buf_appendstr(b, "\"");
	}
	oe_buf_appendstr(b, "]");
}

static const char *
kind_name(enum oe_span_kind kind)
{

	switch (kind) {
	case OE_SPAN_SERVER:	return ("server");
	case OE_SPAN_CLIENT:	return ("client");
	case OE_SPAN_PRODUCER:	return ("producer");
	case OE_SPAN_CONSUMER:	return ("consumer");
	case OE_SPAN_INTERNAL:	break;
	}
	return ("internal");
}

/* Append a typed attribute as a JSON member value. */
static void
jsonl_attr(struct oe_buf *b, const struct oe_kv *kv, int *first)
{

	oe_buf_appendstr(b, *first ? "\"" : ",\"");
	*first = 0;
	oe_buf_appendjson(b, kv->key);
	switch (kv->type) {
	case OE_VAL_INT:
		oe_buf_appendf(b, "\":%jd", (intmax_t)kv->i);
		break;
	case OE_VAL_BOOL:
		oe_buf_appendf(b, "\":%s", kv->i != 0 ? "true" : "false");
		break;
	case OE_VAL_DOUBLE:
		/* Non-finite doubles have no JSON number form. */
		if (kv->d != kv->d || kv->d > 1.7976931348623157e308 ||
		    kv->d < -1.7976931348623157e308)
			oe_buf_appendstr(b, "\":null");
		else
			oe_buf_appendf(b, "\":%.17g", kv->d);
		break;
	case OE_VAL_STRING:
		oe_buf_appendstr(b, "\":\"");
		oe_buf_appendjson(b, kv->s != NULL ? kv->s : "");
		oe_buf_appendstr(b, "\"");
		break;
	}
}

/* The context attributes as an "attributes" object member. */
static void
jsonl_context(struct oe_buf *b, pid_t pid, const char *execname,
    const struct oe_context *ctx, const struct oe_kv *extra, size_t nextra)
{
	struct oe_kv kv[OE_CONTEXT_MAXKV];
	char jid[16];
	size_t i, n;
	int first = 1;

	n = oe_context_kvs(pid, execname, ctx, kv, jid);
	oe_buf_appendstr(b, ",\"attributes\":{");
	for (i = 0; i < n; i++)
		jsonl_attr(b, &kv[i], &first);
	for (i = 0; i < nextra; i++)
		jsonl_attr(b, &extra[i], &first);
	oe_buf_appendstr(b, "}");
}

static int
jsonl_event(struct oe_exporter *e, const struct oe_event *ev)
{
	struct oe_jsonl *j = (struct oe_jsonl *)e;
	struct oe_buf b;
	char timestr[64];
	int ret;

	if (ev->body == NULL || ev->body[0] == '\0')
		return (0);

	oe_iso8601(&ev->ts, timestr, sizeof(timestr));
	oe_buf_init(&b);
	oe_buf_appendstr(&b, "{\"time\":\"");
	oe_buf_appendjson(&b, timestr);
	if (ev->observed.tv_sec != 0 || ev->observed.tv_nsec != 0) {
		/* "time" is the probe's clock, "observed" the reader's. */
		oe_iso8601(&ev->observed, timestr, sizeof(timestr));
		oe_buf_appendstr(&b, "\",\"observed\":\"");
		oe_buf_appendjson(&b, timestr);
	}
	oe_buf_appendstr(&b, "\",\"profile\":\"");
	oe_buf_appendjson(&b, ev->profile);
	if (ev->probe != NULL && ev->probe[0] != '\0') {
		oe_buf_appendstr(&b, "\",\"probe\":\"");
		oe_buf_appendjson(&b, ev->probe);
	}
	oe_buf_appendstr(&b, "\",\"body\":\"");
	oe_buf_appendjson(&b, ev->body);
	oe_buf_appendstr(&b, "\"");
	jsonl_stack_array(&b, "stack", ev->stack, ev->nstack);
	jsonl_stack_array(&b, "ustack", ev->ustack, ev->nustack);
	jsonl_context(&b, ev->pid, ev->execname, &ev->ctx, NULL, 0);
	oe_buf_appendstr(&b, "}\n");

	ret = b.error ? -1 : oe_sink_write(j->sink, b.data, b.len);
	oe_buf_free(&b);
	return (ret);
}

static int
jsonl_span(struct oe_exporter *e, const struct oe_span *sp)
{
	static const char *const status[] = { "unset", "ok", "error" };
	struct oe_jsonl *j = (struct oe_jsonl *)e;
	struct oe_buf b;
	char start[64], end[64], hex[2 * OE_TRACE_ID_LEN + 1];
	int64_t dur;
	int ret;

	oe_iso8601(&sp->start, start, sizeof(start));
	oe_iso8601(&sp->end, end, sizeof(end));
	dur = ((int64_t)sp->end.tv_sec - sp->start.tv_sec) * 1000000000 +
	    (sp->end.tv_nsec - sp->start.tv_nsec);
	oe_buf_init(&b);
	oe_buf_appendstr(&b, "{\"time\":\"");
	oe_buf_appendjson(&b, start);
	oe_buf_appendstr(&b, "\",\"type\":\"span\",\"profile\":\"");
	oe_buf_appendjson(&b, sp->profile);
	oe_buf_appendstr(&b, "\",\"name\":\"");
	oe_buf_appendjson(&b, sp->name);
	oe_id_hex(sp->trace_id, OE_TRACE_ID_LEN, hex);
	oe_buf_appendf(&b, "\",\"trace_id\":\"%s\"", hex);
	oe_id_hex(sp->span_id, OE_SPAN_ID_LEN, hex);
	oe_buf_appendf(&b, ",\"span_id\":\"%s\"", hex);
	if (!oe_id_is_zero(sp->parent_span_id, OE_SPAN_ID_LEN)) {
		oe_id_hex(sp->parent_span_id, OE_SPAN_ID_LEN, hex);
		oe_buf_appendf(&b, ",\"parent_span_id\":\"%s\"", hex);
	}
	oe_buf_appendstr(&b, ",\"end\":\"");
	oe_buf_appendjson(&b, end);
	oe_buf_appendf(&b, "\",\"duration_ns\":%jd,\"kind\":\"%s\","
	    "\"status\":\"%s\"", (intmax_t)dur, kind_name(sp->kind),
	    status[sp->status]);
	if (sp->status_message != NULL) {
		oe_buf_appendstr(&b, ",\"status_message\":\"");
		oe_buf_appendjson(&b, sp->status_message);
		oe_buf_appendstr(&b, "\"");
	}
	if (sp->probe != NULL && sp->probe[0] != '\0') {
		oe_buf_appendstr(&b, ",\"probe\":\"");
		oe_buf_appendjson(&b, sp->probe);
		oe_buf_appendstr(&b, "\"");
	}
	jsonl_context(&b, sp->pid, sp->execname, &sp->ctx, sp->attrs,
	    sp->nattrs);
	oe_buf_appendstr(&b, "}\n");
	ret = b.error ? -1 : oe_sink_write(j->sink, b.data, b.len);
	oe_buf_free(&b);
	return (ret);
}

static int
jsonl_snapshot(struct oe_exporter *e __unused,
    const struct oe_snapshot *sn __unused)
{

	return (0);
}

static int
jsonl_flush(struct oe_exporter *e)
{
	struct oe_jsonl *j = (struct oe_jsonl *)e;

	return (oe_sink_flush(j->sink));
}

static int
jsonl_shutdown(struct oe_exporter *e)
{

	return (jsonl_flush(e));
}

static void
jsonl_free(struct oe_exporter *e)
{
	struct oe_jsonl *j = (struct oe_jsonl *)e;

	(void)oe_sink_close(j->owned);
	free(j->profile);
	free(j);
}

static const struct oe_exporter_ops jsonl_ops = {
	.start = jsonl_start,
	.event = jsonl_event,
	.snapshot = jsonl_snapshot,
	.flush = jsonl_flush,
	.shutdown = jsonl_shutdown,
	.free = jsonl_free,
	.span = jsonl_span,
};

struct oe_exporter *
oe_jsonl_sink_new(struct oe_sink *sink, const char *profile)
{
	struct oe_jsonl *j;

	j = calloc(1, sizeof(*j));
	if (j == NULL)
		return (NULL);
	j->e.ops = &jsonl_ops;
	j->sink = sink;
	j->profile = strdup(profile != NULL ? profile : "");
	if (j->profile == NULL) {
		free(j);
		return (NULL);
	}
	return (&j->e);
}

struct oe_exporter *
oe_jsonl_new(FILE *out, const char *profile)
{
	struct oe_sink_config sc;
	struct oe_exporter *e;
	struct oe_sink *sink;

	memset(&sc, 0, sizeof(sc));
	sc.fp = out;
	if ((sink = oe_sink_open(&sc)) == NULL)
		return (NULL);
	if ((e = oe_jsonl_sink_new(sink, profile)) == NULL) {
		(void)oe_sink_close(sink);
		return (NULL);
	}
	((struct oe_jsonl *)e)->owned = sink;
	return (e);
}
