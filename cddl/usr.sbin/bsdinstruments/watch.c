/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The watch run loop: ties a rendered profile, libdtrace, and an
 * exporter together.
 *
 * Two backend paths share compile/exec/go/work/stop:
 *
 * 1. Text — libdtrace writes its formatted printf output directly to
 *    the output stream via dtrace_work(fp).  ANSI color when that
 *    stream is a terminal.  The exporter is a pass-through; libdtrace
 *    owns the stream, and the sink only rotates and syncs it.
 *
 * 2. Structured — libdtotel intercepts libdtrace's formatted output
 *    through dtrace_handle_buffered() and delivers typed events to
 *    the exporter (JSONL, OTLP, OTLP JSON Lines, collapsed), stamped
 *    with the probe's own wall time; aggregations are walked as typed
 *    records and emitted as snapshots.
 */

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <dtrace.h>
#include <tracecmp.h>

#include "otelexport.h"
#include "dtotel.h"
#include "bsdinstruments.h"

/* File outputs are flushed (and fsynced) at least this often. */
#define	WATCH_FLUSH_INTERVAL	1

static volatile sig_atomic_t got_signal;

static void
signal_handler(int sig __unused)
{

	got_signal = 1;
}

static void
install_signal_handlers(void)
{
	struct sigaction sa;

	got_signal = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

static int
drop_handler(const dtrace_dropdata_t *drop, void *arg)
{
	struct dtotel *d = arg;

	/*
	 * Log the drop and keep running — matches dtrace(1)'s
	 * behavior when probe rates exceed the consumer's drain rate.
	 * Without this handler libdtrace aborts on the first drop.
	 */
	fprintf(stderr, "bsdinstruments: dropped %ju record(s) (%s)\n",
	    (uintmax_t)drop->dtdda_drops, drop->dtdda_msg);
	if (d != NULL)
		dtotel_drops(d, drop->dtdda_drops);
	return (DTRACE_HANDLE_OK);
}

/* ---------------------------------------------------------------- */
/* Consumer callbacks for dtrace_work()				 	*/

static int
chew(const dtrace_probedata_t *data __unused, void *arg __unused)
{

	return (DTRACE_CONSUME_THIS);
}

static int
chewrec(const dtrace_probedata_t *data __unused,
    const dtrace_recdesc_t *rec, void *arg __unused)
{

	if (rec == NULL)
		return (DTRACE_CONSUME_NEXT);
	if (rec->dtrd_action == DTRACEACT_EXIT)
		return (DTRACE_CONSUME_NEXT);
	return (DTRACE_CONSUME_THIS);
}

/* ---------------------------------------------------------------- */
/* Run loop							 	*/

static int
setopt_or_warn(dtrace_hdl_t *dtp, const char *opt, const char *value)
{

	if (dtrace_setopt(dtp, opt, value) != 0) {
		fprintf(stderr, "bsdinstruments: failed to set %s=%s: %s\n",
		    opt, value != NULL ? value : "(null)",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (-1);
	}
	return (0);
}

static int
compile_and_enable(dtrace_hdl_t *dtp, const char *source, const char *what)
{
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;

	prog = dtrace_program_strcompile(dtp, source, DTRACE_PROBESPEC_NAME,
	    DTRACE_C_ZDEFS, 0, NULL);
	if (prog == NULL) {
		fprintf(stderr, "bsdinstruments: %s failed to compile: %s\n",
		    what, dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (-1);
	}
	if (dtrace_program_exec(dtp, prog, &info) != 0) {
		fprintf(stderr, "bsdinstruments: failed to enable probes: "
		    "%s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (-1);
	}
	return (0);
}

static struct oe_exporter *
make_exporter(const struct profile *p, const struct watch_opts *wo,
    struct oe_sink *sink, const struct oe_resource *resource,
    const struct oe_env *env)
{
	struct oe_otlp_config ocfg;
	struct oe_otlpjson_config jcfg;
	const char *endpoint;

	switch (wo->format) {
	case FORMAT_TEXT:
		return (oe_text_sink_new(sink));
	case FORMAT_JSON:
		return (oe_jsonl_sink_new(sink, p->name));
	case FORMAT_COLLAPSED:
		return (oe_collapsed_sink_new(sink));
	case FORMAT_OTLPJSON:
		memset(&jcfg, 0, sizeof(jcfg));
		jcfg.sink = sink;
		jcfg.profile = p->name;
		jcfg.resource = resource;
		jcfg.scope_name = "bsdinstruments";
		return (oe_otlpjson_new(&jcfg));
	case FORMAT_OTEL:
		break;
	}
	/*
	 * Precedence: --endpoint, then the environment (and any lower
	 * configuration layer oe_env_load() folds in), then the
	 * built-in default.
	 */
	endpoint = wo->endpoint != NULL ? wo->endpoint :
	    env->endpoint != NULL ? env->endpoint : WATCH_DEFAULT_ENDPOINT;
	memset(&ocfg, 0, sizeof(ocfg));
	ocfg.endpoint = endpoint;
	ocfg.profile = p->name;
	ocfg.resource = resource;
	ocfg.max_retries = -1;
	ocfg.timeout = env->timeout_ms > 0 ?
	    (double)env->timeout_ms / 1000.0 : 0;
	ocfg.headers = env->headers;
	ocfg.nheaders = env->nheaders;
	ocfg.compression = env->compression;
	ocfg.spool_path = wo->spool;
	ocfg.spool_max = wo->spool_max;
	ocfg.scope_name = "bsdinstruments";
	return (oe_otlp_new(&ocfg));
}

int
watch_run(const struct profile *p, const char *rendered,
    const struct watch_opts *wo)
{
	struct oe_exporter *exporter;
	struct oe_resource resource;
	struct oe_host_info host;
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_env env;
	struct dtotel_config dcfg;
	struct dtotel *dt;
	struct timespec now, last_flush;
	dtrace_hdl_t *dtp;
	dtrace_workstatus_t status;
	FILE *out;
	size_t i;
	int done, err_ret, is_text, use_color;

	err_ret = 1;
	exporter = NULL;
	sink = NULL;
	dt = NULL;
	dtp = NULL;
	is_text = wo->format == FORMAT_TEXT;

	/*
	 * The resource follows the OTel resource conventions: detected
	 * host and OS attributes, a per-run service.instance.id, and
	 * service.name from OTEL_SERVICE_NAME, else a service.name in
	 * OTEL_RESOURCE_ATTRIBUTES, else the program name.  Other
	 * OTEL_RESOURCE_ATTRIBUTES entries override detected values.
	 */
	oe_env_load(&env);
	oe_host_detect(&host);
	memset(&resource, 0, sizeof(resource));
	oe_resource_host(&resource, &host);
	resource.service_name = "bsdinstruments";
	for (i = 0; i < env.nresource_attrs; i++)
		if (strcmp(env.resource_attrs[i].name, "service.name") == 0)
			resource.service_name = env.resource_attrs[i].value;
	if (env.service_name != NULL)
		resource.service_name = env.service_name;
	resource.service_version = BSDINSTRUMENTS_VERSION;
	resource.custom = env.resource_attrs;
	resource.ncustom = env.nresource_attrs;

	/*
	 * Every format but otel writes to a sink: standard output by
	 * default, or a rotating, durable file with --output.  Open it
	 * before tracing starts so a bad path fails fast.
	 */
	if (wo->format != FORMAT_OTEL) {
		memset(&sc, 0, sizeof(sc));
		sc.path = wo->output;
		sc.rotate_size = wo->rotate_size;
		sc.rotate_interval = wo->rotate_interval;
		sc.rotate_keep = wo->rotate_keep;
		sc.durable = wo->output != NULL;
		if ((sink = oe_sink_open(&sc)) == NULL)
			goto out;
	}
	exporter = make_exporter(p, wo, sink, &resource, &env);
	if (exporter == NULL) {
		fprintf(stderr, "bsdinstruments: failed to create "
		    "exporter\n");
		goto out;
	}

	dtp = wo->broker ? tracecmp_dtrace_open(0, &done) :
	    dtrace_open(DTRACE_VERSION, 0, &done);
	if (dtp == NULL) {
		fprintf(stderr, "bsdinstruments: %s failed: %s\n",
		    wo->broker ? "BSDTrace delegation" : "local DTrace open",
		    dtrace_errmsg(NULL, done));
		goto out;
	}

	/*
	 * libdtrace defaults.  switchrate=50ms (vs dtrace(1)'s 1s)
	 * keeps --duration short profiles responsive.  Structured
	 * output gets 16m per-CPU buffers for headroom before kernel
	 * drops at high probe rates.
	 */
	if (setopt_or_warn(dtp, "bufsize", wo->bufsize != NULL ?
	    wo->bufsize : (is_text ? "4m" : "16m")) != 0 ||
	    setopt_or_warn(dtp, "aggsize", "4m") != 0 ||
	    setopt_or_warn(dtp, "switchrate", wo->switchrate != NULL ?
	    wo->switchrate : "50ms") != 0 ||
	    setopt_or_warn(dtp, "quiet", NULL) != 0)
		goto out;

	if (!is_text) {
		memset(&dcfg, 0, sizeof(dcfg));
		dcfg.dtp = dtp;
		dcfg.exporter = exporter;
		dcfg.profile = p->name;
		dcfg.source = rendered;
		if ((dt = dtotel_open(&dcfg)) == NULL) {
			fprintf(stderr, "bsdinstruments: out of memory\n");
			goto out;
		}
		if (dtotel_handle(dt) != 0)
			goto out;
	}
	if (dtrace_handle_drop(dtp, drop_handler, dt) != 0) {
		fprintf(stderr, "bsdinstruments: failed to install drop "
		    "handler: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}

	/*
	 * The clock program goes first so its BEGIN anchor precedes
	 * the profile's own records; text output has no timestamps
	 * and never sees it.
	 */
	if (!is_text && compile_and_enable(dtp, dtotel_clock_program(),
	    "the probe clock program") != 0)
		goto out;
	{
		char what[512];

		snprintf(what, sizeof(what), "profile '%s'", p->name);
		if (compile_and_enable(dtp, rendered, what) != 0)
			goto out;
	}

	if (oe_start(exporter) != 0)
		goto out;

	install_signal_handlers();

	use_color = is_text && wo->output == NULL &&
	    isatty(STDOUT_FILENO);
	if (is_text) {
		/*
		 * Line-buffer standard output so each printf line shows
		 * up immediately.  Wrap live event output in cyan when
		 * it is a terminal; piped or file output stays plain.
		 */
		if (wo->output == NULL)
			setvbuf(stdout, NULL, _IOLBF, 0);
		if (use_color) {
			fputs("\033[36m", stdout);
			fflush(stdout);
		}
	}

	if (dtrace_go(dtp) != 0) {
		if (use_color)
			fputs("\033[0m", stdout);
		fprintf(stderr, "bsdinstruments: failed to start trace: "
		    "%s\n", dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}
	if (dt != NULL)
		dtotel_started(dt);
	clock_gettime(CLOCK_MONOTONIC, &last_flush);

	done = 0;
	while (!done && !got_signal) {
		dtrace_sleep(dtp);
		out = is_text ? oe_sink_stream(sink) : NULL;
		status = dtrace_work(dtp, out, chew, chewrec, NULL);
		switch (status) {
		case DTRACE_WORKSTATUS_OKAY:
			break;
		case DTRACE_WORKSTATUS_DONE:
			done = 1;
			break;
		case DTRACE_WORKSTATUS_ERROR:
			fprintf(stderr, "bsdinstruments: libdtrace work() "
			    "failed: %s\n",
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
			done = 1;
			break;
		}
		if (dt != NULL && dtotel_error(dt))
			break;
		/*
		 * Keep file output current and durable: rotate text
		 * output libdtrace wrote behind the sink's back, write
		 * out partial OTLP JSON batches, fsync.
		 */
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (sink != NULL && now.tv_sec - last_flush.tv_sec >=
		    WATCH_FLUSH_INTERVAL) {
			last_flush = now;
			if ((is_text && oe_sink_poll(sink) != 0) ||
			    (wo->output != NULL && oe_flush(exporter) != 0))
				break;
		}
	}

	(void)dtrace_stop(dtp);

	/*
	 * One more work pass after stop, as dtrace(1) does: stopping
	 * fires dtrace:::END, and the STOPPED status makes this final
	 * pass force-drain the buffers — without it END-probe printf
	 * output and the tail of the event stream are lost.
	 */
	out = is_text ? oe_sink_stream(sink) : NULL;
	if (!is_text || out != NULL)
		(void)dtrace_work(dtp, out, chew, chewrec, NULL);

	/* Flush any pending structured event. */
	if (dt != NULL)
		dtotel_flush(dt);

	/* Snapshot aggregations. */
	if (use_color) {
		/* Magenta for the aggregation table. */
		fputs("\033[0m\033[35m", stdout);
		fflush(stdout);
	}
	if (dt != NULL)
		(void)dtotel_aggregate(dt);
	else if (out != NULL) {
		if (dtrace_aggregate_snap(dtp) != 0)
			fprintf(stderr, "bsdinstruments: aggregation snapshot "
			    "failed: %s\n",
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		else if (dtrace_aggregate_print(dtp, out, NULL) != 0)
			fprintf(stderr, "bsdinstruments: aggregation print "
			    "failed: %s\n",
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	}
	if (use_color) {
		fputs("\033[0m", stdout);
		fflush(stdout);
	}

	err_ret = 0;
	if (oe_flush(exporter) != 0 || oe_shutdown(exporter) != 0)
		err_ret = 1;
	if (dt != NULL && dtotel_error(dt))
		err_ret = 1;

out:
	if (dtp != NULL)
		dtrace_close(dtp);
	dtotel_close(dt);
	if (exporter != NULL)
		oe_exporter_free(exporter);
	if (sink != NULL && oe_sink_close(sink) != 0)
		err_ret = 1;
	oe_env_free(&env);
	return (err_ret);
}
