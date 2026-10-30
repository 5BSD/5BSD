/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * A complete OpenTelemetry export session for a DTrace consumer:
 * the "-x otel*" options, the exporter and output sink they select,
 * the OTel resource (detected host, OTEL_* environment, otel.conf(5)
 * for -x otel=otlp through oe_config_load(), including its file
 * target), one
 * exporter per HyperTrace guest with the guest's own resource, the
 * probe clock program, and orderly shutdown.  dtrace(1) uses it so
 * its own source carries only the hooks.
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dtrace.h>

#include "dtotel_impl.h"
#include "dtotel_session.h"

struct dtotel_session {
	struct dtotel_options opts;
	struct oe_env	 env;
	struct oe_host_info host;
	struct oe_resource resource;
	char		*service_name;
	char		*service_version;
	char		*scope;
	char		*profile;
	struct oe_sink	*sink;
	struct oe_exporter *exporter;
	struct dtotel	*bridge;
	struct timespec	 last_tick;
	int		 closed;
};

static int
seterr(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
	return (-1);
}

/* A positive number with an optional unit suffix (k/m/g or s/m/h/d). */
static int
scaled(const char *v, const char *units, const uint64_t *mults,
    uint64_t *out)
{
	unsigned long long n;
	const char *u;
	char *end;

	if (!isdigit((unsigned char)v[0]))	/* also rejects "" and "-1" */
		return (-1);
	errno = 0;
	n = strtoull(v, &end, 10);
	if (errno != 0 || n == 0)
		return (-1);
	if (*end != '\0') {
		if (end[1] != '\0' ||
		    (u = strchr(units, tolower((unsigned char)*end))) == NULL ||
		    n > UINT64_MAX / mults[u - units])
			return (-1);
		n *= mults[u - units];
	}
	*out = n;
	return (0);
}

int
dtotel_option(struct dtotel_options *o, const char *name, const char *value,
    char *err, size_t errlen)
{
	static const uint64_t sizes[] = { 1024, 1024 * 1024,
	    1024 * 1024 * 1024 };
	static const uint64_t times[] = { 1, 60, 3600, 86400 };
	uint64_t n;

	if (strncmp(name, "otel", 4) != 0)
		return (0);
	if (strcmp(name, "otel") == 0) {
		if (value == NULL)
			return (seterr(err, errlen, "-x otel needs a format: "
			    "otlp, otlp-json or json"));
		if (strcmp(value, "otlp") == 0)
			o->format = DTOTEL_OTLP;
		else if (strcmp(value, "otlp-json") == 0)
			o->format = DTOTEL_OTLPJSON;
		else if (strcmp(value, "json") == 0)
			o->format = DTOTEL_JSON;
		else
			return (seterr(err, errlen, "-x otel=%s: expected otlp, "
			    "otlp-json or json", value));
		return (1);
	}
	if (value == NULL || value[0] == '\0')
		return (seterr(err, errlen, "-x %s needs a value", name));
	if (strcmp(name, "otelendpoint") == 0)
		o->endpoint = value;
	else if (strcmp(name, "otelspool") == 0)
		o->spool = value;
	else if (strcmp(name, "otelspoolmax") == 0) {
		if (scaled(value, "kmg", sizes, &o->spool_max) != 0)
			goto badnum;
	} else if (strcmp(name, "otelrotatesize") == 0) {
		if (scaled(value, "kmg", sizes, &o->rotate_size) != 0)
			goto badnum;
	} else if (strcmp(name, "otelrotatetime") == 0) {
		if (scaled(value, "smhd", times, &n) != 0)
			goto badnum;
		o->rotate_interval = (time_t)n;
	} else if (strcmp(name, "otelrotatekeep") == 0) {
		if (scaled(value, "", NULL, &n) != 0 || n > 999)
			return (seterr(err, errlen, "-x otelrotatekeep expects "
			    "1 to 999"));
		o->rotate_keep = (unsigned)n;
	} else
		return (seterr(err, errlen, "unknown OpenTelemetry option "
		    "-x %s", name));
	return (1);
badnum:
	return (seterr(err, errlen, "-x %s expects a positive number with an "
	    "optional unit suffix", name));
}

int
dtotel_options_check(const struct dtotel_options *o, const char *output,
    char *err, size_t errlen)
{

	if (o->format == DTOTEL_OFF) {
		if (o->endpoint != NULL || o->spool != NULL ||
		    o->spool_max != 0 || o->rotate_size != 0 ||
		    o->rotate_interval != 0 || o->rotate_keep != 0)
			return (seterr(err, errlen, "-x otel* options need "
			    "-x otel"));
		return (0);
	}
	if (o->format == DTOTEL_OTLP) {
		if (output != NULL)
			return (seterr(err, errlen, "-x otel=otlp sends to the "
			    "collector; use -x otel=otlp-json to write a file"));
		if (o->rotate_size != 0 || o->rotate_interval != 0 ||
		    o->rotate_keep != 0)
			return (seterr(err, errlen, "-x otelrotate* options "
			    "need a file (-o)"));
		if (o->spool == NULL && o->spool_max != 0)
			return (seterr(err, errlen, "-x otelspoolmax needs "
			    "-x otelspool"));
		return (0);
	}
	if (o->endpoint != NULL || o->spool != NULL || o->spool_max != 0)
		return (seterr(err, errlen, "-x otelendpoint and -x otelspool "
		    "apply to -x otel=otlp only"));
	if (output == NULL && (o->rotate_size != 0 ||
	    o->rotate_interval != 0 || o->rotate_keep != 0))
		return (seterr(err, errlen, "-x otelrotate* options need a "
		    "file (-o)"));
	return (0);
}

/* An exporter of the session's format with the given resource. */
static struct oe_exporter *
make_exporter(struct dtotel_session *s, const struct oe_resource *r,
    const char *spool, const struct oe_attr *jsonres, size_t njsonres)
{
	struct oe_otlp_config ocfg;
	struct oe_otlpjson_config jcfg;

	/* -x otel=otlp with the otel.conf(5) file target writes a file. */
	switch (s->opts.format == DTOTEL_OTLP && s->sink != NULL ?
	    DTOTEL_OTLPJSON : s->opts.format) {
	case DTOTEL_JSON:
		if (jsonres != NULL)
			return (oe_jsonl_resource_new(s->sink, s->profile,
			    jsonres, njsonres));
		return (oe_jsonl_sink_new(s->sink, s->profile));
	case DTOTEL_OTLPJSON:
		memset(&jcfg, 0, sizeof(jcfg));
		jcfg.sink = s->sink;
		jcfg.profile = s->profile;
		jcfg.resource = r;
		jcfg.scope_name = s->scope;
		return (oe_otlpjson_new(&jcfg));
	default:
		break;
	}
	memset(&ocfg, 0, sizeof(ocfg));
	/* -x otelendpoint > OTEL_* > otel.conf(5) > default, resolved. */
	oe_otlp_config_env(&ocfg, &s->env);
	ocfg.profile = s->profile;
	ocfg.resource = r;
	ocfg.max_retries = -1;
	ocfg.spool_path = spool;
	ocfg.scope_name = s->scope;
	return (oe_otlp_new(&ocfg));
}

/*
 * A HyperTrace guest's exporter.  Its resource keeps the service but
 * describes the guest: host.name is the VM name unless the guest
 * supplied one, the host's own host.id and OS attributes are left
 * out, and hypertrace.vm.name/id/epoch plus hypertrace.host.name tie
 * it to the VM and its hypervisor.  An OTLP spool gets a per-guest
 * file next to the host's.
 */
#define	GUEST_MAXATTR	(DTOTEL_GUEST_ATTRS + 64)

static struct oe_exporter *
guest_exporter(void *arg, const struct dtotel_guest *g)
{
	struct dtotel_session *s = arg;
	struct oe_resource r;
	struct oe_attr attrs[GUEST_MAXATTR];
	char vmid[16], epoch[32], spool[PATH_MAX];
	size_t i, n;

	r = s->resource;
	r.host_name = g->name;
	r.host_id = NULL;
	r.host_arch = NULL;
	r.os_name = NULL;
	r.os_full_name = NULL;
	r.os_version = NULL;
	r.os_description = NULL;
	n = 0;
	for (i = 0; i < s->env.nresource_attrs && n < GUEST_MAXATTR - 4 -
	    g->nattrs; i++)
		attrs[n++] = s->env.resource_attrs[i];
	snprintf(vmid, sizeof(vmid), "%u", (unsigned)g->vmid);
	snprintf(epoch, sizeof(epoch), "%ju", (uintmax_t)g->epoch);
	attrs[n].name = "hypertrace.vm.name";
	attrs[n++].value = g->name;
	attrs[n].name = "hypertrace.vm.id";
	attrs[n++].value = vmid;
	attrs[n].name = "hypertrace.vm.epoch";
	attrs[n++].value = epoch;
	attrs[n].name = "hypertrace.host.name";
	attrs[n++].value = s->host.host_name;
	/* The guest's own attributes come last and win. */
	for (i = 0; i < g->nattrs; i++)
		attrs[n++] = g->attrs[i];
	r.custom = attrs;
	r.ncustom = n;
	if (s->env.spool_path != NULL)
		snprintf(spool, sizeof(spool), "%s.vm%u", s->env.spool_path,
		    (unsigned)g->vmid);
	return (make_exporter(s, &r, s->env.spool_path != NULL ? spool : NULL,
	    attrs + (n - g->nattrs - 4), g->nattrs + 4));
}

struct dtotel_session *
dtotel_session_open(const struct dtotel_session_config *cfg, char *err,
    size_t errlen)
{
	struct dtotel_session *s;
	struct oe_sink_config sc;
	struct dtotel_config dcfg;
	struct oe_config_request req;

	s = calloc(1, sizeof(*s));
	if (s == NULL) {
		seterr(err, errlen, "out of memory");
		return (NULL);
	}
	s->opts = *cfg->options;
	memset(&req, 0, sizeof(req));
	req.scope = cfg->scope_name;
	req.endpoint = s->opts.endpoint;
	req.spool = s->opts.spool;
	req.spool_max = s->opts.spool_max;
	req.system = s->opts.format == DTOTEL_OTLP;
	if (oe_config_load(&s->env, &req, err, errlen) != 0) {
		free(s);
		return (NULL);
	}
	oe_host_detect(&s->host);
	oe_resource_init(&s->resource, &s->env, &s->host, cfg->service_name,
	    cfg->service_version);
	s->service_name = strdup(s->resource.service_name);
	s->service_version = strdup(cfg->service_version);
	s->scope = strdup(cfg->scope_name);
	s->profile = strdup(cfg->profile != NULL ? cfg->profile : "");
	if (s->service_name == NULL || s->service_version == NULL ||
	    s->scope == NULL || s->profile == NULL) {
		seterr(err, errlen, "out of memory");
		goto fail;
	}
	s->resource.service_name = s->service_name;
	s->resource.service_version = s->service_version;
	if (s->opts.format == DTOTEL_OTLP && s->env.file_path != NULL) {
		/*
		 * otel.conf(5) selects the file target and neither -x
		 * otelendpoint nor OTEL_EXPORTER_OTLP_ENDPOINT overrides
		 * it: OTLP JSON Lines to <export.directory>/<scope>.jsonl.
		 */
		if ((s->sink = oe_env_sink_open(&s->env)) == NULL) {
			seterr(err, errlen, "cannot open the OpenTelemetry "
			    "file target %s", s->env.file_path);
			goto fail;
		}
	} else if (s->opts.format != DTOTEL_OTLP) {
		memset(&sc, 0, sizeof(sc));
		sc.path = cfg->output;
		sc.rotate_size = s->opts.rotate_size;
		sc.rotate_interval = s->opts.rotate_interval;
		sc.rotate_keep = s->opts.rotate_keep;
		sc.durable = cfg->output != NULL;
		if ((s->sink = oe_sink_open(&sc)) == NULL) {
			seterr(err, errlen, "cannot open the OpenTelemetry "
			    "output");
			goto fail;
		}
	}
	s->exporter = make_exporter(s, &s->resource, s->env.spool_path, NULL,
	    0);
	if (s->exporter == NULL) {
		seterr(err, errlen, "cannot create the OpenTelemetry exporter");
		goto fail;
	}
	memset(&dcfg, 0, sizeof(dcfg));
	dcfg.dtp = cfg->dtp;
	dcfg.exporter = s->exporter;
	dcfg.profile = s->profile;
	dcfg.source = cfg->source;
	if (cfg->hypertrace) {
		dcfg.guest_exporter = guest_exporter;
		dcfg.guest_arg = s;
	}
	if ((s->bridge = dtotel_open(&dcfg)) == NULL) {
		seterr(err, errlen, "out of memory");
		goto fail;
	}
	if (dtotel_handle(s->bridge) != 0 || oe_start(s->exporter) != 0) {
		seterr(err, errlen, "cannot start the OpenTelemetry exporter");
		goto fail;
	}
	return (s);
fail:
	s->closed = 1;
	(void)dtotel_session_close(s, 0);
	return (NULL);
}

struct dtotel *
dtotel_session_bridge(struct dtotel_session *s)
{

	return (s->bridge);
}

int
dtotel_session_clock(struct dtotel_session *s, dtrace_hdl_t *dtp, char *err,
    size_t errlen)
{
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;

	(void)s;
	/*
	 * Zero-probe descriptions are tolerated: a handle without the
	 * profile provider still anchors at BEGIN.
	 */
	prog = dtrace_program_strcompile(dtp, dtotel_clock_program(),
	    DTRACE_PROBESPEC_NAME, DTRACE_C_ZDEFS, 0, NULL);
	if (prog == NULL)
		return (seterr(err, errlen, "cannot compile the probe clock "
		    "program: %s", dtrace_errmsg(dtp, dtrace_errno(dtp))));
	if (dtrace_program_exec(dtp, prog, &info) != 0)
		return (seterr(err, errlen, "cannot enable the probe clock "
		    "program: %s", dtrace_errmsg(dtp, dtrace_errno(dtp))));
	return (0);
}

int
dtotel_session_tick(struct dtotel_session *s)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec - s->last_tick.tv_sec < 1)
		return (0);
	s->last_tick = now;
	/*
	 * Ticks fall between consumption passes, so the pending record
	 * is complete: hand it on now rather than at the next firing,
	 * which may be long in coming.
	 */
	dtotel_flush(s->bridge);
	/* Drop and error counters, when they changed. */
	dtotel_report(s->bridge, 0);
	if (dtotel_error(s->bridge))
		return (-1);
	/* OTLP/HTTP batches on its own sender thread. */
	if (s->sink == NULL)
		return (0);
	return (dtotel_session_flush(s));
}

int
dtotel_session_flush(struct dtotel_session *s)
{
	int ret;

	dtotel_flush(s->bridge);
	ret = oe_flush(s->exporter);
	/* HyperTrace guests' records are written at the same points. */
	if (dtotel_flush_guests(s->bridge) != 0)
		ret = -1;
	return (ret);
}

int
dtotel_session_close(struct dtotel_session *s, int finish)
{
	int ret = 0;

	if (s == NULL)
		return (0);
	if (finish && !s->closed) {
		dtotel_flush(s->bridge);
		if (dtotel_aggregate(s->bridge) != 0)
			ret = -1;
	}
	if (s->bridge != NULL) {
		if (dtotel_shutdown(s->bridge) != 0 ||
		    dtotel_error(s->bridge))
			ret = -1;
		dtotel_close(s->bridge);
	}
	if (s->exporter != NULL) {
		if (oe_shutdown(s->exporter) != 0)
			ret = -1;
		oe_exporter_free(s->exporter);
	}
	if (s->sink != NULL && oe_sink_close(s->sink) != 0)
		ret = -1;
	oe_env_free(&s->env);
	free(s->service_name);
	free(s->service_version);
	free(s->scope);
	free(s->profile);
	free(s);
	return (ret);
}
