/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * OTLP JSON Lines file exporter.  Writes the same requests the
 * OTLP/HTTP exporter POSTs, one Export*ServiceRequest object per
 * line, which is the format of the OpenTelemetry Collector's file
 * exporter and otlpjsonfile receiver.  Log records and spans batch up
 * to batch_size per line; snapshots (and any pending records) are
 * written on every flush.  The exporter is synchronous: it runs
 * on the caller's thread and reports write errors from the call
 * that hit them.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "otelexport.h"
#include "oe_otlpenc.h"

#define	OTLPFILE_DEFAULT_BATCH	200
#define	OTLPFILE_NSIGNALS	3

struct oe_otlpfile {
	struct oe_exporter e;
	struct oe_sink	*sink;
	struct oe_otlpenc enc;
	int		 batch_size;
	char		**frags[OTLPFILE_NSIGNALS];
	size_t		 nfrags[OTLPFILE_NSIGNALS];
	size_t		 capfrags[OTLPFILE_NSIGNALS];
};

static int
otlpfile_start(struct oe_exporter *e __unused)
{

	return (0);
}

/* Write one signal's pending fragments as one request line. */
static int
otlpfile_write(struct oe_otlpfile *f, enum oe_signal sig)
{
	char *req;
	size_t len;
	int ret;

	if (f->nfrags[sig] == 0)
		return (0);
	req = oe_enc_request(&f->enc, sig, f->frags[sig], f->nfrags[sig], 0,
	    &len);
	oe_frags_free(f->frags[sig], f->nfrags[sig]);
	f->frags[sig] = NULL;
	f->nfrags[sig] = f->capfrags[sig] = 0;
	if (req == NULL) {
		fprintf(stderr, "otlpjson: out of memory\n");
		return (-1);
	}
	/* The request has no raw newlines: strings are JSON-escaped. */
	req[len] = '\n';
	ret = oe_sink_write(f->sink, req, len + 1);
	free(req);
	return (ret);
}

static int
otlpfile_queue(struct oe_otlpfile *f, enum oe_signal sig, char *rec)
{

	if (rec == NULL || oe_frags_append(&f->frags[sig], &f->nfrags[sig],
	    &f->capfrags[sig], rec) != 0) {
		free(rec);
		fprintf(stderr, "otlpjson: out of memory\n");
		return (-1);
	}
	if (f->nfrags[sig] >= (size_t)f->batch_size)
		return (otlpfile_write(f, sig));
	return (0);
}

static int
otlpfile_event(struct oe_exporter *e, const struct oe_event *ev)
{
	struct oe_otlpfile *f = (struct oe_otlpfile *)e;

	if (ev->body == NULL || ev->body[0] == '\0')
		return (0);
	return (otlpfile_queue(f, OE_SIGNAL_LOGS,
	    oe_enc_log_record(&f->enc, ev)));
}

static int
otlpfile_snapshot(struct oe_exporter *e, const struct oe_snapshot *sn)
{
	struct oe_otlpfile *f = (struct oe_otlpfile *)e;

	if (sn->npoints == 0)
		return (0);
	return (otlpfile_queue(f, OE_SIGNAL_METRICS,
	    oe_enc_metric(&f->enc, sn)));
}

static int
otlpfile_span(struct oe_exporter *e, const struct oe_span *sp)
{
	struct oe_otlpfile *f = (struct oe_otlpfile *)e;

	return (otlpfile_queue(f, OE_SIGNAL_TRACES, oe_enc_span(&f->enc, sp)));
}

static int
otlpfile_flush(struct oe_exporter *e)
{
	struct oe_otlpfile *f = (struct oe_otlpfile *)e;
	int i, ret;

	ret = 0;
	for (i = 0; i < OTLPFILE_NSIGNALS; i++)
		if (otlpfile_write(f, (enum oe_signal)i) != 0)
			ret = -1;
	if (oe_sink_flush(f->sink) != 0)
		ret = -1;
	return (ret);
}

static int
otlpfile_shutdown(struct oe_exporter *e)
{

	return (otlpfile_flush(e));
}

static void
otlpfile_free(struct oe_exporter *e)
{
	struct oe_otlpfile *f = (struct oe_otlpfile *)e;
	int i;

	for (i = 0; i < OTLPFILE_NSIGNALS; i++)
		oe_frags_free(f->frags[i], f->nfrags[i]);
	oe_enc_fini(&f->enc);
	free(f);
}

static const struct oe_exporter_ops otlpfile_ops = {
	.start = otlpfile_start,
	.event = otlpfile_event,
	.snapshot = otlpfile_snapshot,
	.flush = otlpfile_flush,
	.shutdown = otlpfile_shutdown,
	.free = otlpfile_free,
	.span = otlpfile_span,
};

struct oe_exporter *
oe_otlpjson_new(const struct oe_otlpjson_config *cfg)
{
	struct oe_otlpfile *f;

	f = calloc(1, sizeof(*f));
	if (f == NULL)
		return (NULL);
	f->e.ops = &otlpfile_ops;
	f->sink = cfg->sink;
	f->batch_size = cfg->batch_size > 0 ? cfg->batch_size :
	    OTLPFILE_DEFAULT_BATCH;
	if (oe_enc_init(&f->enc, cfg->resource, cfg->scope_name) != 0) {
		free(f);
		return (NULL);
	}
	return (&f->e);
}
