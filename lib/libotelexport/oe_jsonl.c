/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * JSONL exporter — one JSON object per event on its own line, so
 * output pipes cleanly into jq, Loki, Vector, Splunk, fluentd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "otelexport.h"

struct oe_jsonl {
	struct oe_exporter e;
	FILE		*out;
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
	oe_buf_appendstr(&b, "\",\"profile\":\"");
	oe_buf_appendjson(&b, ev->profile);
	oe_buf_appendstr(&b, "\",\"body\":\"");
	oe_buf_appendjson(&b, ev->body);
	oe_buf_appendstr(&b, "\"");
	jsonl_stack_array(&b, "stack", ev->stack, ev->nstack);
	jsonl_stack_array(&b, "ustack", ev->ustack, ev->nustack);
	oe_buf_appendstr(&b, "}\n");

	ret = b.error ? -1 : 0;
	if (ret == 0)
		fwrite(b.data, 1, b.len, j->out);
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

	fflush(j->out);
	return (0);
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
};

struct oe_exporter *
oe_jsonl_new(FILE *out, const char *profile)
{
	struct oe_jsonl *j;

	j = calloc(1, sizeof(*j));
	if (j == NULL)
		return (NULL);
	j->e.ops = &jsonl_ops;
	j->out = out;
	j->profile = strdup(profile != NULL ? profile : "");
	if (j->profile == NULL) {
		free(j);
		return (NULL);
	}
	return (&j->e);
}
