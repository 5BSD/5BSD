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
	int		 own_sink;	/* closed by shutdown/free */
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
	req = oe_enc_request(&f->enc, sig, f->frags[sig], f->nfrags[sig],
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

/*
 * A profile is a whole ExportProfilesServiceRequest (its dictionary is
 * request-wide): one line of its own, written at once.
 */
static int
otlpfile_profile(struct oe_exporter *e, const struct oe_profile *pr)
{
	struct oe_otlpfile *f = (struct oe_otlpfile *)e;
	char *req;
	size_t len;
	int ret;

	if (pr->nsamples == 0)
		return (0);
	if ((req = oe_enc_profile(&f->enc, pr, &len)) == NULL) {
		fprintf(stderr, "otlpjson: out of memory\n");
		return (-1);
	}
	req[len] = '\n';
	ret = oe_sink_write(f->sink, req, len + 1);
	free(req);
	return (ret);
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
	struct oe_otlpfile *f = (struct oe_otlpfile *)e;
	int ret;

	ret = otlpfile_flush(e);
	if (f->own_sink) {
		if (oe_sink_close(f->sink) != 0)
			ret = -1;
		f->sink = NULL;
		f->own_sink = 0;
	}
	return (ret);
}

static void
otlpfile_free(struct oe_exporter *e)
{
	struct oe_otlpfile *f = (struct oe_otlpfile *)e;
	int i;

	if (f->own_sink)
		(void)oe_sink_close(f->sink);
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
	.profile = otlpfile_profile,
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

/* ---------------------------------------------------------------- */
/* The otel.conf(5) file target					*/

struct oe_sink *
oe_env_sink_open(const struct oe_env *env)
{
	struct oe_sink_config sc;

	if (env->file_path == NULL) {
		fprintf(stderr, "otelexport: no file target configured\n");
		return (NULL);
	}
	memset(&sc, 0, sizeof(sc));
	sc.path = env->file_path;
	sc.durable = 1;
	sc.mode = OE_FILE_TARGET_MODE;
	sc.follow = 1;
	return (oe_sink_open(&sc));
}

struct oe_exporter *
oe_exporter_open(const struct oe_env *env, const struct oe_otlp_config *cfg)
{
	struct oe_otlp_config ocfg;
	struct oe_otlpjson_config jcfg;
	struct oe_otlpfile *f;
	struct oe_exporter *e;
	struct oe_sink *sink;

	if (env->file_path == NULL) {
		ocfg = *cfg;
		oe_otlp_config_env(&ocfg, env);
		return (oe_otlp_new(&ocfg));
	}
	if ((sink = oe_env_sink_open(env)) == NULL)
		return (NULL);
	memset(&jcfg, 0, sizeof(jcfg));
	jcfg.sink = sink;
	jcfg.profile = cfg->profile;
	jcfg.resource = cfg->resource;
	jcfg.batch_size = cfg->batch_size;
	jcfg.scope_name = cfg->scope_name;
	if ((e = oe_otlpjson_new(&jcfg)) == NULL) {
		(void)oe_sink_close(sink);
		return (NULL);
	}
	f = (struct oe_otlpfile *)e;
	f->own_sink = 1;
	return (e);
}
