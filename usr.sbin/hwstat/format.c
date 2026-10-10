/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Text and JSONL formatting for hwstat snapshots.
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "otelexport.h"
#include "hwstat.h"

void
fmt_metrics_json(const struct sys_snapshot *snap)
{
	struct oe_buf b;
	size_t i;
	double busy;
	int n, cpu;

	busy = 0;
	n = 0;
	for (cpu = 0; cpu < snap->ncores; cpu++) {
		if (snap->cores[cpu].have_usage) {
			busy += 100.0 - snap->cores[cpu].usage[4];
			n++;
		}
	}
	if (n > 0)
		printf(",\"cpu_busy_pct\":%.2f", busy / n);
	printf(",\"metric_sources\":[");
	for (i = 0; i < snap->nsources; i++) {
		oe_buf_init(&b);
		oe_buf_appendjson(&b, snap->sources[i].name);
		printf("%s{\"source\":\"%s\",\"status\":\"%s\"}",
		    i == 0 ? "" : ",", b.data != NULL ? b.data : "",
		    snap->sources[i].status);
		oe_buf_free(&b);
	}
	printf("],\"metrics\":[");
	for (i = 0; i < snap->nmetrics; i++) {
		oe_buf_init(&b);
		oe_buf_appendjson(&b, snap->metrics[i].source);
		printf("%s{\"source\":\"%s\",\"name\":\"%s\",\"value\":%" PRId64 "}",
		    i == 0 ? "" : ",", b.data != NULL ? b.data : "",
		    snap->metrics[i].name, snap->metrics[i].value);
		oe_buf_free(&b);
	}
	printf("]");
}

void
fmt_metrics_text(const struct sys_snapshot *snap)
{
	size_t i;

	for (i = 0; i < snap->nsources; i++)
		printf("  %s: %s\n", snap->sources[i].name, snap->sources[i].status);
	for (i = 0; i < snap->nmetrics; i++)
		printf("  %s %s: %" PRId64 "\n", snap->metrics[i].source,
		    snap->metrics[i].name, snap->metrics[i].value);
}

void
fmt_thermal_json(const struct sys_snapshot *snap)
{
	struct oe_buf b;
	int i;

	fmt_metrics_json(snap);
	if (snap->have_acpi)
		printf(",\"acpi_temp\":%.1f", snap->acpi_temp);
	if (snap->nthermal == 0)
		return;
	oe_buf_init(&b);
	printf(",\"temperatures\":[");
	for (i = 0; i < snap->nthermal; i++) {
		oe_buf_free(&b);
		oe_buf_init(&b);
		oe_buf_appendjson(&b, snap->thermal[i].name);
		printf("%s{\"source\":\"%s\",\"celsius\":%.1f}",
		    i == 0 ? "" : ",", b.data != NULL ? b.data : "",
		    snap->thermal[i].celsius);
	}
	oe_buf_free(&b);
	printf("]");
}

void
fmt_thermal_text(const struct sys_snapshot *snap)
{
	int i;

	fmt_metrics_text(snap);
	for (i = 0; i < snap->nthermal; i++)
		printf("  %s: %.1f C\n", snap->thermal[i].name,
		    snap->thermal[i].celsius);
}

static void
time_hms(const struct timespec *ts, char *buf, size_t len)
{
	struct tm tm;

	localtime_r(&ts->tv_sec, &tm);
	strftime(buf, len, "%H:%M:%S", &tm);
}

void
fmt_text_header(const struct rapl *r)
{
	enum rapl_domain domains[RAPL_NDOMAINS];
	char col[24];
	int i, n, width;

	n = r != NULL ? rapl_domains(r, domains) : 0;
	printf("%-12s", "TIME");
	for (i = 0; i < n; i++) {
		snprintf(col, sizeof(col), "%s (W)",
		    rapl_domain_name(domains[i]));
		printf("  %-14s", col);
	}
	printf("  %-10s  %-11s  %-6s\n", "TEMP (C)", "FREQ (MHz)", "BUSY%");
	width = 12 + n * 16 + 10 + 11 + 4 + 8;
	for (i = 0; i < width; i++)
		printf("-");
	printf("\n");
}

void
fmt_text_row(const struct rapl *r __unused, const struct rapl_sample *samples,
    int nsamples, const struct sys_snapshot *snap)
{
	char timestr[16], col[24];
	double tmin, tavg, tmax, busy;
	int fmin, favg, fmax, i, n;

	time_hms(&snap->ts, timestr, sizeof(timestr));
	printf("%-12s", timestr);
	for (i = 0; i < nsamples; i++) {
		snprintf(col, sizeof(col), "%8.3f", samples[i].watts);
		printf("  %-14s", col);
	}
	if (snap_temp_stats(snap, &tmin, &tavg, &tmax) > 0) {
		snprintf(col, sizeof(col), "%5.0f", tmax);
		printf("  %-10s", col);
	} else
		printf("  %-10s", "--");
	if (snap_freq_stats(snap, &fmin, &favg, &fmax) > 0) {
		snprintf(col, sizeof(col), "%5d", fmax);
		printf("  %-11s", col);
	} else
		printf("  %-11s", "--");
	busy = 0;
	n = 0;
	for (i = 0; i < snap->ncores; i++) {
		if (snap->cores[i].have_usage) {
			busy += 100.0 - snap->cores[i].usage[4];
			n++;
		}
	}
	if (n > 0)
		printf("  %6.1f", busy / n);
	else
		printf("  %6s", "--");
	printf("\n");
	fmt_thermal_text(snap);
}

void
fmt_percore_text(const struct rapl *r __unused,
    const struct rapl_sample *samples, int nsamples,
    const struct sys_snapshot *snap)
{
	const struct core_snap *first, *core;
	char timestr[16], col[16];
	int i, j, ncstates;

	time_hms(&snap->ts, timestr, sizeof(timestr));
	printf("-- %s ", timestr);
	for (i = 0; i < 50; i++)
		printf("-");
	printf("\n");

	first = snap_first_cstate(snap);
	ncstates = first != NULL ? first->cstate.nlevels : 0;

	printf("%-4s  %-5s  %-5s  %-6s", "CPU", "TEMP", "FREQ", "BUSY%");
	for (j = 0; j < ncstates; j++) {
		snprintf(col, sizeof(col), "%sentry%%",
		    first->cstate.levels[j].name);
		printf("  %-7s", col);
	}
	printf("\n");

	for (i = 0; i < snap->ncores; i++) {
		core = &snap->cores[i];
		printf("%3d ", core->cpu);
		if (core->have_temp)
			printf("  %4.0f ", core->temp);
		else
			printf("  %4s ", "--");
		if (core->have_freq)
			printf("  %5d", core->freq);
		else
			printf("  %5s", "--");
		if (core->have_usage)
			printf("  %6.1f", 100.0 - core->usage[4]);
		else
			printf("  %6s", "--");
		for (j = 0; j < ncstates; j++) {
			if (core->have_cstate && j < core->cstate.npct)
				printf("  %5.1f  ", core->cstate.pct[j]);
			else
				printf("  %5s  ", "--");
		}
		printf("\n");
	}

	fmt_thermal_text(snap);
	if (nsamples > 0) {
		printf("\n");
		for (i = 0; i < nsamples; i++)
			printf("  %s: %.1fW",
			    rapl_domain_name(samples[i].domain),
			    samples[i].watts);
		printf("\n");
	}
}

void
fmt_json_line(const struct rapl *r __unused,
    const struct rapl_sample *samples, int nsamples,
    const struct sys_snapshot *snap)
{
	char timestr[64];
	double tmin, tavg, tmax;
	int fmin, favg, fmax, i;

	oe_iso8601(&snap->ts, timestr, sizeof(timestr));
	printf("{\"time\":\"%s\"", timestr);
	for (i = 0; i < nsamples; i++) {
		printf(",\"%s_watts\":%.6f,\"%s_joules\":%.6f",
		    rapl_domain_name(samples[i].domain), samples[i].watts,
		    rapl_domain_name(samples[i].domain), samples[i].joules);
	}
	if (snap_temp_stats(snap, &tmin, &tavg, &tmax) > 0)
		printf(",\"temp_max\":%.1f,\"temp_avg\":%.1f", tmax, tavg);
	if (snap_freq_stats(snap, &fmin, &favg, &fmax) > 0)
		printf(",\"freq_max_mhz\":%d,\"freq_avg_mhz\":%d", fmax,
		    favg);
	if (snap->have_gpu_freq)
		printf(",\"gpu_freq_mhz\":%ld", snap->gpu_freq);
	fmt_thermal_json(snap);
	printf("}\n");
}

void
fmt_percore_json_line(const struct rapl *r __unused,
    const struct rapl_sample *samples, int nsamples,
    const struct sys_snapshot *snap)
{
	const struct core_snap *core;
	char timestr[64];
	int i, j, firstfield;

	oe_iso8601(&snap->ts, timestr, sizeof(timestr));
	printf("{\"time\":\"%s\",\"cores\":[", timestr);
	for (i = 0; i < snap->ncores; i++) {
		core = &snap->cores[i];
		printf("%s{\"cpu\":%d", i > 0 ? "," : "", core->cpu);
		if (core->have_usage)
			printf(",\"cpu_usage_pct\":{\"user\":%.2f,\"nice\":%.2f,"
			    "\"system\":%.2f,\"interrupt\":%.2f,\"idle\":%.2f}",
			    core->usage[0], core->usage[1], core->usage[2],
			    core->usage[3], core->usage[4]);
		if (core->have_temp)
			printf(",\"temp\":%.1f", core->temp);
		if (core->have_freq)
			printf(",\"freq_mhz\":%d", core->freq);
		if (core->have_cstate && core->cstate.npct > 0) {
			printf(",\"cstate\":{");
			firstfield = 1;
			for (j = 0; j < core->cstate.nlevels &&
			    j < core->cstate.npct; j++) {
				struct oe_buf eb;

				oe_buf_init(&eb);
				oe_buf_appendjson(&eb,
				    core->cstate.levels[j].name);
				printf("%s\"%s\":%.2f",
				    firstfield ? "" : ",",
				    eb.data != NULL ? eb.data : "",
				    core->cstate.pct[j]);
				oe_buf_free(&eb);
				firstfield = 0;
			}
			printf("}");
		}
		printf("}");
	}
	printf("]");
	for (i = 0; i < nsamples; i++)
		printf(",\"%s_watts\":%.6f,\"%s_joules\":%.6f",
		    rapl_domain_name(samples[i].domain), samples[i].watts,
		    rapl_domain_name(samples[i].domain), samples[i].joules);
	fmt_thermal_json(snap);
	printf("}\n");
}
