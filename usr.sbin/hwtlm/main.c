/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * hwtlm — hardware telemetry with OpenTelemetry output.
 * Subcommands: list (capabilities), watch (interval sampling),
 * exec (energy cost of running a command).
 */

#include <sys/wait.h>

#include <ctype.h>
#include <err.h>
#include <getopt.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "otelexport.h"
#include "hwtlm.h"

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

static void __dead2
usage(void)
{

	fprintf(stderr,
	    "usage: hwtlm <subcommand> [args]\n"
	    "\n"
	    "Subcommands:\n"
	    "  list    Show system hardware telemetry capabilities.\n"
	    "  watch   Sample hardware telemetry and stream it.\n"
	    "  exec    Run a command and report its energy and thermal "
	    "impact.\n"
	    "\n"
	    "See hwtlm(8) or `hwtlm <subcommand> -h` for details.\n");
	exit(2);
}

static enum hw_format
parse_format(const char *arg)
{

	if (strcmp(arg, "text") == 0)
		return (HW_FORMAT_TEXT);
	if (strcmp(arg, "json") == 0)
		return (HW_FORMAT_JSON);
	if (strcmp(arg, "otel") == 0)
		return (HW_FORMAT_OTEL);
	errx(2, "--format must be text, json, or otel");
}

/* ---------------------------------------------------------------- */
/* OTLP metric emission						 	*/

struct otel_ctx {
	struct oe_exporter *exporter;
	struct oe_env	 env;
	char		 hostname[256], arch[64], osrel[64];
};

static struct oe_exporter *
otel_open(struct otel_ctx *ctx, const char *cli_endpoint, double interval)
{
	struct oe_resource resource;
	struct oe_otlp_config ocfg;
	const char *endpoint;

	oe_env_load(&ctx->env);
	oe_host_name(ctx->hostname, sizeof(ctx->hostname));
	oe_host_arch(ctx->arch, sizeof(ctx->arch));
	oe_os_version(ctx->osrel, sizeof(ctx->osrel));
	memset(&resource, 0, sizeof(resource));
	resource.service_name = ctx->env.service_name != NULL ?
	    ctx->env.service_name : "hwtlm";
	resource.host_name = ctx->hostname;
	resource.host_arch = ctx->arch;
	resource.os_name = "freebsd";
	resource.os_version = ctx->osrel;
	resource.service_version = HWTLM_VERSION;
	resource.custom = ctx->env.resource_attrs;
	resource.ncustom = ctx->env.nresource_attrs;

	endpoint = cli_endpoint;
	if (strcmp(endpoint, "http://localhost:4318") == 0 &&
	    ctx->env.endpoint != NULL)
		endpoint = ctx->env.endpoint;

	memset(&ocfg, 0, sizeof(ocfg));
	ocfg.endpoint = endpoint;
	ocfg.profile = "hardware";
	ocfg.resource = &resource;
	ocfg.batch_size = 50;
	ocfg.flush_interval = interval;
	ocfg.max_retries = -1;
	ocfg.timeout = ctx->env.timeout_ms > 0 ?
	    (double)ctx->env.timeout_ms / 1000.0 : 0;
	ocfg.headers = ctx->env.headers;
	ocfg.nheaders = ctx->env.nheaders;
	ocfg.compression = ctx->env.compression;
	ctx->exporter = oe_otlp_new(&ocfg);
	if (ctx->exporter != NULL && oe_start(ctx->exporter) != 0) {
		oe_exporter_free(ctx->exporter);
		ctx->exporter = NULL;
	}
	if (ctx->exporter != NULL)
		fprintf(stderr, "Exporting to %s/v1/metrics\n", endpoint);
	return (ctx->exporter);
}

static void
otel_close(struct otel_ctx *ctx)
{

	if (ctx->exporter != NULL) {
		oe_shutdown(ctx->exporter);
		oe_exporter_free(ctx->exporter);
		ctx->exporter = NULL;
	}
	oe_env_free(&ctx->env);
}

static void
emit_gauge(struct oe_exporter *exporter, const struct timespec *ts,
    const char *profile, const char *name, enum oe_agg_kind kind,
    const char *attrname, const char *attrvalue, int64_t value)
{
	struct oe_snapshot sn;
	struct oe_datapoint dp;
	struct oe_attr attr;

	attr.name = attrname;
	attr.value = attrvalue;
	memset(&dp, 0, sizeof(dp));
	dp.attrs = &attr;
	dp.nattrs = 1;
	dp.scalar = value;
	memset(&sn, 0, sizeof(sn));
	sn.ts = *ts;
	sn.profile = profile;
	sn.name = name;
	sn.kind = kind;
	sn.points = &dp;
	sn.npoints = 1;
	oe_snapshot(exporter, &sn);
}

static void
emit_otlp_sample(struct oe_exporter *exporter,
    const struct rapl_sample *samples, int nsamples,
    const struct sys_snapshot *snap, int percore)
{
	const struct core_snap *core;
	char name[64], cpu_id[16];
	double tmin, tavg, tmax;
	int fmin, favg, fmax, i, j;

	for (i = 0; i < nsamples; i++) {
		snprintf(name, sizeof(name), "%s_milliwatts",
		    rapl_domain_name(samples[i].domain));
		emit_gauge(exporter, &snap->ts, "power", name, OE_AGG_AVG,
		    "rapl_domain", rapl_domain_name(samples[i].domain),
		    (int64_t)(samples[i].watts * 1000));
	}

	if (percore) {
		for (i = 0; i < snap->ncores; i++) {
			core = &snap->cores[i];
			snprintf(cpu_id, sizeof(cpu_id), "%d", core->cpu);
			if (core->have_temp)
				emit_gauge(exporter, &snap->ts, "cpu",
				    "temp", OE_AGG_AVG, "cpu_id", cpu_id,
				    (int64_t)core->temp);
			if (core->have_freq)
				emit_gauge(exporter, &snap->ts, "cpu",
				    "freq_mhz", OE_AGG_AVG, "cpu_id",
				    cpu_id, core->freq);
			if (core->have_cstate) {
				for (j = 0; j < core->cstate.nlevels &&
				    j < core->cstate.npct; j++) {
					char lname[24], mname[48];
					const char *p;
					char *q;

					/* cstate_<name>_pct, lowercased. */
					q = lname;
					for (p = core->cstate.levels[j].name;
					    *p != '\0' && q < lname +
					    sizeof(lname) - 1; p++)
						*q++ = (char)tolower(
						    (unsigned char)*p);
					*q = '\0';
					snprintf(mname, sizeof(mname),
					    "cstate_%s_pct", lname);
					emit_gauge(exporter, &snap->ts,
					    "cpu", mname, OE_AGG_AVG,
					    "cpu_id", cpu_id,
					    (int64_t)core->cstate.pct[j]);
				}
			}
		}
	} else {
		if (snap_temp_stats(snap, &tmin, &tavg, &tmax) > 0)
			emit_gauge(exporter, &snap->ts, "system",
			    "cpu_temp_max", OE_AGG_MAX, "source", "cpu",
			    (int64_t)tmax);
		if (snap_freq_stats(snap, &fmin, &favg, &fmax) > 0)
			emit_gauge(exporter, &snap->ts, "system",
			    "cpu_freq_max_mhz", OE_AGG_MAX, "source", "cpu",
			    fmax);
		if (snap->have_gpu_freq)
			emit_gauge(exporter, &snap->ts, "system",
			    "gpu_freq_mhz", OE_AGG_AVG, "source", "gpu",
			    snap->gpu_freq);
	}
	oe_flush(exporter);
}

/* ---------------------------------------------------------------- */
/* hwtlm list							 	*/

static void __dead2
list_usage(void)
{

	fprintf(stderr,
	    "usage: hwtlm list [--format text|json] [--per-core]\n");
	exit(2);
}

static void
list_text(struct rapl *r, const struct sys_snapshot *snap, int cpucount,
    int percore)
{
	enum rapl_domain domains[RAPL_NDOMAINS];
	const struct core_snap *first, *core;
	double tdp, minp, maxp, tmin, tavg, tmax;
	size_t namewidth, k;
	int fmin, favg, fmax, i, j, n;

	if (r != NULL)
		printf("CPU:           %s\n", rapl_microarch(r));
	printf("Logical CPUs:  %d\n\n", cpucount);

	if (r != NULL) {
		printf("Energy unit:   %.6f J\n", rapl_energy_unit(r));
		if (rapl_power_info(r, &tdp, &minp, &maxp) == 0) {
			printf("Package TDP:   %.1f W\n", tdp);
			if (minp > 0)
				printf("Min power:     %.1f W\n", minp);
			if (maxp > 0)
				printf("Max power:     %.1f W\n", maxp);
		}
		printf("\nRAPL domains:\n");
		n = rapl_domains(r, domains);
		namewidth = 10;
		for (i = 0; i < n; i++)
			if (strlen(rapl_domain_name(domains[i])) > namewidth)
				namewidth =
				    strlen(rapl_domain_name(domains[i]));
		printf("  %-*s  DESCRIPTION\n", (int)namewidth, "DOMAIN");
		printf("  ");
		for (k = 0; k < namewidth + 32; k++)
			printf("-");
		printf("\n");
		for (i = 0; i < n; i++)
			printf("  %-*s  %s\n", (int)namewidth,
			    rapl_domain_name(domains[i]),
			    rapl_domain_label(domains[i]));
		printf("\n");
	} else
		printf("RAPL:          not available (Intel only, needs "
		    "cpuctl)\n\n");

	if (percore) {
		printf("Per-core temperatures:\n");
		for (i = 0; i < snap->ncores; i++) {
			core = &snap->cores[i];
			if (core->have_temp)
				printf("  CPU %2d: %4.0f C\n", core->cpu,
				    core->temp);
		}
		if (snap->any_throttled)
			printf("  (thermal throttling has been logged since "
			    "boot)\n");
		printf("\n");
	} else if (snap_temp_stats(snap, &tmin, &tavg, &tmax) > 0) {
		printf("Core temps:    %.0f C min / %.0f C avg / %.0f C "
		    "max\n", tmin, tavg, tmax);
		if (snap->have_tjmax)
			printf("TjMax:         %.0f C\n", snap->tjmax);
		if (snap->any_throttled)
			printf("Throttled:     YES\n");
	} else
		printf("Core temps:    not available (try: kldload "
		    "coretemp)\n");
	if (snap->have_acpi)
		printf("ACPI thermal:  %.1f C\n", snap->acpi_temp);
	printf("\n");

	if (percore) {
		printf("Per-core frequencies:\n");
		for (i = 0; i < snap->ncores; i++) {
			core = &snap->cores[i];
			if (core->have_freq)
				printf("  CPU %2d: %d MHz\n", core->cpu,
				    core->freq);
		}
		printf("\n");
	} else if (snap_freq_stats(snap, &fmin, &favg, &fmax) > 0)
		printf("Core freq:     %d MHz min / %d MHz avg / %d MHz "
		    "max\n", fmin, favg, fmax);

	first = snap_first_cstate(snap);
	if (first != NULL) {
		printf("C-states:      ");
		for (j = 0; j < first->cstate.nlevels; j++)
			printf("%s%s (%dus)", j > 0 ? "  " : "",
			    first->cstate.levels[j].name,
			    first->cstate.levels[j].latency_us);
		printf("\n");
		if (first->cstate.have_lowest)
			printf("Lowest:        %s\n", first->cstate.lowest);
		if (percore) {
			printf("\nPer-core C-state residency:\n");
			printf("  %-4s", "CPU");
			for (j = 0; j < first->cstate.nlevels; j++)
				printf("  %5s%% ",
				    first->cstate.levels[j].name);
			printf("\n");
			for (i = 0; i < snap->ncores; i++) {
				core = &snap->cores[i];
				if (!core->have_cstate)
					continue;
				printf("  %3d ", core->cpu);
				for (j = 0; j < first->cstate.nlevels; j++) {
					if (j < core->cstate.npct)
						printf("  %5.1f  ",
						    core->cstate.pct[j]);
					else
						printf("  %5s  ", "--");
				}
				printf("\n");
			}
		}
		printf("\n");
	}

	if (snap->have_gpu_freq) {
		printf("GPU freq:      %ld MHz\n", snap->gpu_freq);
		if (snap->gpu_throttled)
			printf("GPU throttle:  YES\n");
	}
	printf("\n");
}

static void
list_json(struct rapl *r, const struct sys_snapshot *snap, int cpucount,
    int percore)
{
	enum rapl_domain domains[RAPL_NDOMAINS];
	const struct core_snap *first, *core;
	struct oe_buf b;
	double tdp, minp, maxp, tmin, tavg, tmax;
	int fmin, favg, fmax, i, j, n;

	oe_buf_init(&b);
	oe_buf_appendf(&b, "{\"logical_cpus\":%d", cpucount);
	if (r != NULL) {
		oe_buf_appendstr(&b, ",\"cpu\":\"");
		oe_buf_appendjson(&b, rapl_microarch(r));
		oe_buf_appendf(&b, "\",\"energy_unit\":%g",
		    rapl_energy_unit(r));
		n = rapl_domains(r, domains);
		oe_buf_appendstr(&b, ",\"rapl_domains\":[");
		for (i = 0; i < n; i++)
			oe_buf_appendf(&b,
			    "%s{\"name\":\"%s\",\"label\":\"%s\"}",
			    i > 0 ? "," : "",
			    rapl_domain_name(domains[i]),
			    rapl_domain_label(domains[i]));
		oe_buf_appendstr(&b, "]");
		if (rapl_power_info(r, &tdp, &minp, &maxp) == 0)
			oe_buf_appendf(&b, ",\"tdp_watts\":%.1f", tdp);
	} else
		oe_buf_appendstr(&b, ",\"rapl_available\":false");

	if (snap_temp_stats(snap, &tmin, &tavg, &tmax) > 0) {
		oe_buf_appendf(&b, ",\"temp_min\":%.1f,\"temp_avg\":%.1f,"
		    "\"temp_max\":%.1f", tmin, tavg, tmax);
		if (snap->have_tjmax)
			oe_buf_appendf(&b, ",\"tjmax\":%.1f", snap->tjmax);
		oe_buf_appendf(&b, ",\"throttled\":%s",
		    snap->any_throttled ? "true" : "false");
	}
	if (snap->have_acpi)
		oe_buf_appendf(&b, ",\"acpi_temp\":%.1f", snap->acpi_temp);
	if (snap_freq_stats(snap, &fmin, &favg, &fmax) > 0)
		oe_buf_appendf(&b, ",\"freq_min_mhz\":%d,"
		    "\"freq_avg_mhz\":%d,\"freq_max_mhz\":%d", fmin, favg,
		    fmax);

	first = snap_first_cstate(snap);
	if (first != NULL) {
		oe_buf_appendstr(&b, ",\"cstates\":[");
		for (j = 0; j < first->cstate.nlevels; j++) {
			oe_buf_appendf(&b, "%s{\"name\":\"",
			    j > 0 ? "," : "");
			oe_buf_appendjson(&b, first->cstate.levels[j].name);
			oe_buf_appendf(&b, "\",\"latency_us\":%d}",
			    first->cstate.levels[j].latency_us);
		}
		oe_buf_appendstr(&b, "]");
	}

	if (snap->have_gpu_freq)
		oe_buf_appendf(&b, ",\"gpu_freq_mhz\":%ld,"
		    "\"gpu_throttled\":%s", snap->gpu_freq,
		    snap->gpu_throttled ? "true" : "false");

	if (percore) {
		oe_buf_appendstr(&b, ",\"cores\":[");
		for (i = 0; i < snap->ncores; i++) {
			core = &snap->cores[i];
			oe_buf_appendf(&b, "%s{\"cpu\":%d",
			    i > 0 ? "," : "", core->cpu);
			if (core->have_temp)
				oe_buf_appendf(&b, ",\"temp\":%.1f",
				    core->temp);
			if (core->have_freq)
				oe_buf_appendf(&b, ",\"freq_mhz\":%d",
				    core->freq);
			if (core->have_cstate && core->cstate.npct > 0) {
				oe_buf_appendstr(&b, ",\"cstate\":{");
				for (j = 0; j < core->cstate.nlevels &&
				    j < core->cstate.npct; j++) {
					oe_buf_appendf(&b, "%s\"",
					    j > 0 ? "," : "");
					oe_buf_appendjson(&b,
					    core->cstate.levels[j].name);
					oe_buf_appendf(&b, "\":%.2f",
					    core->cstate.pct[j]);
				}
				oe_buf_appendstr(&b, "}");
			}
			oe_buf_appendstr(&b, "}");
		}
		oe_buf_appendstr(&b, "]");
	}
	oe_buf_appendstr(&b, "}");
	printf("%s\n", b.data != NULL ? b.data : "{}");
	oe_buf_free(&b);
}

int
cmd_hw_list(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "format", required_argument, NULL, 'F' },
		{ "per-core", no_argument, NULL, 'c' },
		{ NULL, 0, NULL, 0 }
	};
	struct sys_snapshot snap;
	struct rapl *r;
	enum hw_format format;
	int ch, cpucount, percore;

	format = HW_FORMAT_TEXT;
	percore = 0;
	while ((ch = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
		switch (ch) {
		case 'F':
			format = parse_format(optarg);
			break;
		case 'c':
			percore = 1;
			break;
		default:
			list_usage();
		}
	}
	if (optind != argc)
		list_usage();
	if (format == HW_FORMAT_OTEL)
		errx(2, "--format otel is only supported by `hwtlm watch`");

	cpucount = sys_cpu_count();
	r = rapl_open();
	if (sys_snapshot(&snap, cpucount) != 0)
		err(1, "snapshot");
	if (format == HW_FORMAT_JSON)
		list_json(r, &snap, cpucount, percore);
	else
		list_text(r, &snap, cpucount, percore);
	sys_snapshot_free(&snap);
	rapl_close(r);
	return (0);
}

/* ---------------------------------------------------------------- */
/* hwtlm watch							 	*/

static void __dead2
watch_usage(void)
{

	fprintf(stderr,
	    "usage: hwtlm watch [--interval seconds] [--duration seconds]\n"
	    "           [--per-core] [--format text|json|otel] "
	    "[--endpoint url]\n");
	exit(2);
}

int
cmd_hw_watch(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "interval", required_argument, NULL, 'i' },
		{ "duration", required_argument, NULL, 'd' },
		{ "per-core", no_argument, NULL, 'c' },
		{ "format", required_argument, NULL, 'F' },
		{ "endpoint", required_argument, NULL, 'e' },
		{ NULL, 0, NULL, 0 }
	};
	struct otel_ctx octx;
	struct rapl_sample samples[RAPL_NDOMAINS];
	struct sys_snapshot snap;
	struct timespec start, now;
	struct rapl *r;
	struct oe_exporter *exporter;
	enum hw_format format;
	const char *endpoint;
	double interval, duration, elapsed_total, elapsed;
	char *end;
	int ch, cpucount, nsamples, percore, rapl_failed;

	interval = 1.0;
	duration = 0;
	percore = 0;
	rapl_failed = 0;
	format = HW_FORMAT_TEXT;
	endpoint = "http://localhost:4318";
	while ((ch = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
		switch (ch) {
		case 'i':
			interval = strtod(optarg, &end);
			if (end == optarg || *end != '\0' ||
			    !isfinite(interval) || interval <= 0 ||
			    interval > 3600)
				errx(2, "--interval must be a number of "
				    "seconds between 0 and 3600");
			break;
		case 'd':
			duration = strtod(optarg, &end);
			if (end == optarg || *end != '\0' ||
			    !isfinite(duration) || duration <= 0)
				errx(2, "--duration must be a positive "
				    "number of seconds");
			break;
		case 'c':
			percore = 1;
			break;
		case 'F':
			format = parse_format(optarg);
			break;
		case 'e':
			endpoint = optarg;
			break;
		default:
			watch_usage();
		}
	}
	if (optind != argc)
		watch_usage();

	cpucount = sys_cpu_count();
	r = rapl_open();

	memset(&octx, 0, sizeof(octx));
	exporter = NULL;
	if (format == HW_FORMAT_OTEL) {
		exporter = otel_open(&octx, endpoint, interval);
		if (exporter == NULL) {
			rapl_close(r);
			return (1);
		}
	}

	if (format == HW_FORMAT_TEXT) {
		if (r != NULL)
			fprintf(stderr, "CPU: %s (%d logical CPUs)\n",
			    rapl_microarch(r), cpucount);
		else
			fprintf(stderr, "%d logical CPUs (RAPL not "
			    "available)\n", cpucount);
		fprintf(stderr, "Interval: %.1fs\n\n", interval);
		if (!percore)
			fmt_text_header(r);
	}

	install_signal_handlers();
	clock_gettime(CLOCK_MONOTONIC, &start);

	/* Prime the RAPL counters so the first row has a real delta. */
	nsamples = 0;
	if (r != NULL)
		(void)rapl_sample(r, samples, &elapsed);

	while (!got_signal) {
		usleep((useconds_t)(interval * 1e6));
		if (got_signal)
			break;
		nsamples = 0;
		if (r != NULL) {
			nsamples = rapl_sample(r, samples, &elapsed);
			if (nsamples < 0) {
				fprintf(stderr, "hwtlm watch: RAPL read "
				    "failed\n");
				rapl_failed = 1;
				break;
			}
		}
		if (sys_snapshot(&snap, cpucount) != 0)
			break;
		switch (format) {
		case HW_FORMAT_OTEL:
			emit_otlp_sample(exporter, samples, nsamples, &snap,
			    percore);
			break;
		case HW_FORMAT_JSON:
			if (percore)
				fmt_percore_json_line(r, samples, nsamples,
				    &snap);
			else
				fmt_json_line(r, samples, nsamples, &snap);
			break;
		case HW_FORMAT_TEXT:
			if (percore)
				fmt_percore_text(r, samples, nsamples,
				    &snap);
			else
				fmt_text_row(r, samples, nsamples, &snap);
			break;
		}
		fflush(stdout);
		sys_snapshot_free(&snap);
		if (duration > 0) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			elapsed_total = (double)(now.tv_sec - start.tv_sec) +
			    (double)(now.tv_nsec - start.tv_nsec) / 1e9;
			if (elapsed_total >= duration)
				break;
		}
	}

	if (exporter != NULL)
		otel_close(&octx);
	rapl_close(r);
	/* A truncated run must be distinguishable from success. */
	return (rapl_failed ? 1 : 0);
}

/* ---------------------------------------------------------------- */
/* hwtlm exec							 	*/

static void __dead2
exec_usage(void)
{

	fprintf(stderr,
	    "usage: hwtlm exec [--format text|json] [--per-core] -- "
	    "command [args]\n");
	exit(2);
}

/*
 * Run the child, accumulating RAPL energy deltas while it runs.
 * The energy-status counters are only 32 bits wide (~11 minutes to
 * wrap at 100 W with the 2^-16 J server unit), so a single
 * before/after delta silently loses 2^32 counts per wrap on long
 * runs — resample every ~30 s instead.  A 30 s interval cannot
 * itself wrap twice (that would need a >2 kW package).
 *
 * On success *have_counters reflects whether accum[] holds valid
 * raw energy deltas per domain.
 */
static int
run_child(char **args, struct rapl *r, int *have_counters,
    uint64_t accum[RAPL_NDOMAINS])
{
	enum rapl_domain domains[RAPL_NDOMAINS];
	uint64_t prev[RAPL_NDOMAINS], cur[RAPL_NDOMAINS];
	pid_t pid, n;
	int i, ndomains, status, ticks;

	memset(accum, 0, RAPL_NDOMAINS * sizeof(accum[0]));
	memset(prev, 0, sizeof(prev));
	memset(cur, 0, sizeof(cur));
	ndomains = 0;
	if (*have_counters && r != NULL) {
		ndomains = rapl_domains(r, domains);
		if (rapl_read_counters(r, prev) != 0)
			*have_counters = 0;
	} else
		*have_counters = 0;

	pid = fork();
	if (pid == -1) {
		warn("fork");
		return (127);
	}
	if (pid == 0) {
		execvp(args[0], args);
		warn("%s", args[0]);
		_exit(127);
	}

	if (!*have_counters) {
		if (waitpid(pid, &status, 0) < 0)
			return (127);
	} else {
		ticks = 0;
		for (;;) {
			n = waitpid(pid, &status, WNOHANG);
			if (n == pid)
				break;
			if (n < 0)
				return (127);
			usleep(250000);
			if (++ticks < 120)	/* ~30 s */
				continue;
			ticks = 0;
			if (rapl_read_counters(r, cur) == 0) {
				for (i = 0; i < ndomains; i++)
					accum[domains[i]] +=
					    rapl_counter_delta(
					    cur[domains[i]],
					    prev[domains[i]]);
				memcpy(prev, cur, sizeof(prev));
			}
		}
		/* Fold in the final partial interval. */
		if (rapl_read_counters(r, cur) == 0) {
			for (i = 0; i < ndomains; i++)
				accum[domains[i]] += rapl_counter_delta(
				    cur[domains[i]], prev[domains[i]]);
		}
	}

	if (WIFEXITED(status))
		return (WEXITSTATUS(status));
	if (WIFSIGNALED(status))
		return (128 + WTERMSIG(status));
	return (127);
}

int
cmd_hw_exec(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "format", required_argument, NULL, 'F' },
		{ "per-core", no_argument, NULL, 'c' },
		{ NULL, 0, NULL, 0 }
	};
	struct sys_snapshot before, after;
	struct rapl_sample results[RAPL_NDOMAINS];
	enum rapl_domain domains[RAPL_NDOMAINS];
	struct timespec t0, t1;
	struct rapl *r;
	struct oe_buf b;
	uint64_t accum[RAPL_NDOMAINS];
	double elapsed, total_joules;
	enum hw_format format;
	size_t namewidth;
	int ch, cpucount, exitcode, have_counters, i, j, ndomains, nresults;
	int percore;

	format = HW_FORMAT_TEXT;
	percore = 0;
	while ((ch = getopt_long(argc, argv, "+hF:c", opts, NULL)) != -1) {
		switch (ch) {
		case 'F':
			format = parse_format(optarg);
			break;
		case 'c':
			percore = 1;
			break;
		default:
			exec_usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		exec_usage();
	if (format == HW_FORMAT_OTEL)
		errx(2, "--format otel is only supported by `hwtlm watch`");

	cpucount = sys_cpu_count();
	r = rapl_open();

	memset(accum, 0, sizeof(accum));
	have_counters = r != NULL;
	if (sys_snapshot(&before, cpucount) != 0)
		err(1, "snapshot");
	clock_gettime(CLOCK_MONOTONIC, &t0);

	exitcode = run_child(argv, r, &have_counters, accum);

	clock_gettime(CLOCK_MONOTONIC, &t1);
	if (sys_snapshot(&after, cpucount) != 0)
		err(1, "snapshot");
	elapsed = (double)(t1.tv_sec - t0.tv_sec) +
	    (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

	nresults = 0;
	if (have_counters) {
		ndomains = rapl_domains(r, domains);
		for (i = 0; i < ndomains; i++) {
			results[nresults].domain = domains[i];
			results[nresults].joules = rapl_joules(r,
			    domains[i], accum[domains[i]]);
			results[nresults].watts = elapsed > 0 ?
			    results[nresults].joules / elapsed : 0;
			nresults++;
		}
	}

	if (format == HW_FORMAT_JSON) {
		oe_buf_init(&b);
		oe_buf_appendstr(&b, "{\"command\":\"");
		for (i = 0; i < argc; i++) {
			if (i > 0)
				oe_buf_appendstr(&b, " ");
			oe_buf_appendjson(&b, argv[i]);
		}
		oe_buf_appendf(&b, "\",\"elapsed_seconds\":%.6f,"
		    "\"exit_code\":%d", elapsed, exitcode);
		if (percore) {
			oe_buf_appendstr(&b, ",\"cores\":[");
			for (i = 0; i < after.ncores; i++) {
				const struct core_snap *ca = &after.cores[i];
				const struct core_snap *cb =
				    i < before.ncores ? &before.cores[i] :
				    NULL;

				oe_buf_appendf(&b, "%s{\"cpu\":%d",
				    i > 0 ? "," : "", ca->cpu);
				if (cb != NULL && cb->have_temp)
					oe_buf_appendf(&b,
					    ",\"temp_before\":%.1f",
					    cb->temp);
				if (ca->have_temp)
					oe_buf_appendf(&b,
					    ",\"temp_after\":%.1f",
					    ca->temp);
				if (cb != NULL && cb->have_freq)
					oe_buf_appendf(&b,
					    ",\"freq_before\":%d", cb->freq);
				if (ca->have_freq)
					oe_buf_appendf(&b,
					    ",\"freq_after\":%d", ca->freq);
				oe_buf_appendstr(&b, "}");
			}
			oe_buf_appendstr(&b, "]");
		} else {
			double bmin, bavg, bmax, amin, aavg, amax;

			if (snap_temp_stats(&before, &bmin, &bavg,
			    &bmax) > 0)
				oe_buf_appendf(&b, ",\"temp_before\":%.1f",
				    bmax);
			if (snap_temp_stats(&after, &amin, &aavg, &amax) > 0)
				oe_buf_appendf(&b, ",\"temp_after\":%.1f",
				    amax);
		}
		if (nresults > 0) {
			oe_buf_appendstr(&b, ",\"domains\":[");
			for (i = 0; i < nresults; i++)
				oe_buf_appendf(&b, "%s{\"%s\":{\"joules\":"
				    "%.6f,\"watts\":%.6f}}",
				    i > 0 ? "," : "",
				    rapl_domain_name(results[i].domain),
				    results[i].joules, results[i].watts);
			oe_buf_appendstr(&b, "]");
		}
		oe_buf_appendstr(&b, "}");
		printf("%s\n", b.data != NULL ? b.data : "{}");
		oe_buf_free(&b);
	} else {
		if (r != NULL)
			fprintf(stderr, "\nCPU: %s\n", rapl_microarch(r));
		fprintf(stderr, "Elapsed: %.3fs\n", elapsed);
		if (exitcode != 0)
			fprintf(stderr, "Exit code: %d\n", exitcode);

		if (percore) {
			fprintf(stderr, "\n");
			for (i = 0; i < after.ncores; i++) {
				const struct core_snap *ca = &after.cores[i];
				const struct core_snap *cb =
				    i < before.ncores ? &before.cores[i] :
				    NULL;
				double bt, at, d;

				if (!ca->have_temp)
					continue;
				at = ca->temp;
				bt = cb != NULL && cb->have_temp ? cb->temp :
				    at;
				d = at - bt;
				fprintf(stderr, "CPU %2d: %4.0f C -> %4.0f "
				    "C (%s%.0f C)\n", ca->cpu, bt, at,
				    d >= 0 ? "+" : "", d);
			}
		} else {
			double bmin, bavg, bmax, amin, aavg, amax;

			if (snap_temp_stats(&before, &bmin, &bavg,
			    &bmax) > 0 && snap_temp_stats(&after, &amin,
			    &aavg, &amax) > 0) {
				double d = amax - bmax;

				fprintf(stderr, "Temp: %.0f C -> %.0f C "
				    "(%s%.0f C)\n", bmax, amax,
				    d >= 0 ? "+" : "", d);
			}
		}
		fprintf(stderr, "\n");

		if (nresults > 0) {
			namewidth = 10;
			for (i = 0; i < nresults; i++)
				if (strlen(rapl_domain_name(
				    results[i].domain)) > namewidth)
					namewidth = strlen(rapl_domain_name(
					    results[i].domain));
			printf("%-*s  %-12s  %-14s\n", (int)namewidth,
			    "DOMAIN", "ENERGY (J)", "AVG POWER (W)");
			for (j = 0; j < (int)namewidth + 32; j++)
				printf("-");
			printf("\n");
			total_joules = 0;
			for (i = 0; i < nresults; i++) {
				printf("%-*s  %10.3f  %12.3f\n",
				    (int)namewidth,
				    rapl_domain_name(results[i].domain),
				    results[i].joules, results[i].watts);
				if (results[i].domain == RAPL_PACKAGE)
					total_joules = results[i].joules;
			}
			printf("\n");
			if (total_joules > 0)
				printf("Total package energy: %.3f J\n",
				    total_joules);
		} else
			printf("(RAPL not available — no energy data)\n");
	}

	sys_snapshot_free(&before);
	sys_snapshot_free(&after);
	rapl_close(r);
	return (exitcode);
}

/* ---------------------------------------------------------------- */

int
main(int argc, char **argv)
{

	if (argc < 2)
		usage();
	if (strcmp(argv[1], "--version") == 0) {
		printf("%s\n", HWTLM_VERSION);
		return (0);
	}
	argc--;
	argv++;
	if (strcmp(argv[0], "list") == 0)
		return (cmd_hw_list(argc, argv));
	if (strcmp(argv[0], "watch") == 0)
		return (cmd_hw_watch(argc, argv));
	if (strcmp(argv[0], "exec") == 0)
		return (cmd_hw_exec(argc, argv));
	usage();
}
