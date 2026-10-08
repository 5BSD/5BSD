/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Portable sysctl-based sensors: CPU temperature (coretemp, amdtemp or
 * a SoC driver), frequency (cpufreq), C-state entry usage (ACPI),
 * ACPI thermal zones, and Intel GPU state.  Works on any
 * architecture with the appropriate kernel drivers loaded.
 */

#include <sys/types.h>
#include <sys/cpuset.h>
#include <sys/sysctl.h>
#include <sys/resource.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hwstat.h"

static int
sysctl_int(const char *name, int *value)
{
	int v;
	size_t len = sizeof(v);

	if (sysctlbyname(name, &v, &len, NULL, 0) != 0 || len != sizeof(v))
		return (-1);
	*value = v;
	return (0);
}

static int
sysctl_str(const char *name, char *buf, size_t buflen)
{
	size_t len = buflen - 1;

	if (sysctlbyname(name, buf, &len, NULL, 0) != 0)
		return (-1);
	buf[len] = '\0';
	return (0);
}

/*
 * Read a string-typed numeric sysctl (the linuxkpi DRM sysctls are
 * all registered as CTLTYPE_STRING).  Do NOT type-sniff by length:
 * a 3-digit value like "300" is 4 bytes with its NUL and would
 * masquerade as an int32 of ASCII bytes.
 */
static int
sysctl_number(const char *name, long *value)
{
	char buf[64], *end;
	size_t len;
	long v;

	len = sizeof(buf) - 1;
	if (sysctlbyname(name, buf, &len, NULL, 0) != 0)
		return (-1);
	buf[len] = '\0';
	errno = 0;
	v = strtol(buf, &end, 10);
	if (end == buf || errno == ERANGE)
		return (-1);
	*value = v;
	return (0);
}

/* deciKelvin -> degrees Celsius (e.g. 3301 -> 57.0). */
static double
decikelvin_to_celsius(int dk)
{

	return ((double)dk / 10.0 - 273.15);
}

int
sys_cpu_count(void)
{
	int n;

	if (sysctl_int("hw.ncpu", &n) == 0 && n > 0)
		return (n);
	return (1);
}

/*
 * Parse dev.cpu.N.cx_supported:
 *	"C1/1/1 C2/2/127 C3/3/1048"
 */
int
cstate_parse_supported(const char *s, struct cstate_info *ci)
{
	char copy[256], *tok, *last, *slash1, *slash2;

	ci->nlevels = 0;
	strlcpy(copy, s, sizeof(copy));
	for (tok = strtok_r(copy, " \t\n", &last); tok != NULL &&
	    ci->nlevels < MAX_CSTATES; tok = strtok_r(NULL, " \t\n", &last)) {
		slash1 = strchr(tok, '/');
		if (slash1 == NULL)
			continue;
		slash2 = strchr(slash1 + 1, '/');
		if (slash2 == NULL)
			continue;
		*slash1 = '\0';
		*slash2 = '\0';
		strlcpy(ci->levels[ci->nlevels].name, tok,
		    sizeof(ci->levels[ci->nlevels].name));
		ci->levels[ci->nlevels].type = atoi(slash1 + 1);
		ci->levels[ci->nlevels].latency_us = atoi(slash2 + 1);
		ci->nlevels++;
	}
	return (ci->nlevels);
}

/*
 * Parse dev.cpu.N.cx_usage:
 *	"100.00% 0.00% 0.00% last 775us"
 */
void
cstate_parse_usage(const char *s, struct cstate_info *ci)
{
	char copy[256], *tok, *last;
	size_t len;

	ci->npct = 0;
	strlcpy(copy, s, sizeof(copy));
	for (tok = strtok_r(copy, " \t\n", &last); tok != NULL;
	    tok = strtok_r(NULL, " \t\n", &last)) {
		len = strlen(tok);
		if (len > 1 && tok[len - 1] == '%' &&
		    ci->npct < MAX_CSTATES) {
			tok[len - 1] = '\0';
			ci->pct[ci->npct++] = strtod(tok, NULL);
		}
		/* the trailing "last Xus" pair is ignored */
	}
}

static void
core_read(struct core_snap *core, int cpu)
{
	char name[64], buf[256];
	int v;

	memset(core, 0, sizeof(*core));
	core->cpu = cpu;

	/* New coretemp API: snapshot status without clearing hardware logs. */
	snprintf(name, sizeof(name), "dev.cpu.%d.coretemp.thermal_status", cpu);
	if (sysctl_int(name, &v) == 0) {
		core->have_thermal_status = 1;
		core->thermal_status = (uint32_t)v;
		core->throttled = (core->thermal_status & 2) != 0;
		snprintf(name, sizeof(name), "dev.cpu.%d.coretemp.tjmax", cpu);
		if ((core->thermal_status & (1U << 31)) != 0 &&
		    sysctl_int(name, &v) == 0 && v >= 0) {
			core->have_temp = 1;
			core->temp = decikelvin_to_celsius(v) -
			    ((core->thermal_status >> 16) & 0x7f);
		}
	} else {
		/* Older kernels and non-Intel temperature providers. */
		snprintf(name, sizeof(name), "dev.cpu.%d.temperature", cpu);
		if (sysctl_int(name, &v) == 0 && v >= 0) {
			core->have_temp = 1;
			core->temp = decikelvin_to_celsius(v);
		}
		snprintf(name, sizeof(name), "dev.cpu.%d.coretemp.throttle_log", cpu);
		if (sysctl_int(name, &v) == 0)
			core->throttled = v != 0;
	}
	snprintf(name, sizeof(name), "dev.cpu.%d.freq", cpu);
	if (sysctl_int(name, &v) == 0 && v > 0) {
		core->have_freq = 1;
		core->freq = v;
	}
	snprintf(name, sizeof(name), "dev.cpu.%d.cx_supported", cpu);
	if (sysctl_str(name, buf, sizeof(buf)) == 0 &&
	    cstate_parse_supported(buf, &core->cstate) > 0) {
		core->have_cstate = 1;
		snprintf(name, sizeof(name), "dev.cpu.%d.cx_usage", cpu);
		if (sysctl_str(name, buf, sizeof(buf)) == 0)
			cstate_parse_usage(buf, &core->cstate);
		snprintf(name, sizeof(name), "dev.cpu.%d.cx_lowest", cpu);
		if (sysctl_str(name, buf, sizeof(buf)) == 0) {
			char *nl = strchr(buf, '\n');

			if (nl != NULL)
				*nl = '\0';
			strlcpy(core->cstate.lowest, buf,
			    sizeof(core->cstate.lowest));
			core->cstate.have_lowest = 1;
		}
	}
}

/* Enumerate only published temperature readings, never control registers. */
static int
thermal_read(struct sys_snapshot *snap, const char *tree)
{
	int root[CTL_MAXNAME], next[CTL_MAXNAME], query[CTL_MAXNAME + 2];
	struct thermal_sensor sensor, *thermal;
	struct { u_int kind; char format[32]; } fmt;
	size_t rootlen, nextlen, len;
	int n, v;

	rootlen = CTL_MAXNAME;
	if (sysctlnametomib(tree, root, &rootlen) != 0)
		return (0);
	memcpy(next, root, rootlen * sizeof(int));
	n = (int)rootlen;
	for (;;) {
		query[0] = CTL_SYSCTL;
		query[1] = CTL_SYSCTL_NEXT;
		memcpy(query + 2, next, (size_t)n * sizeof(int));
		nextlen = sizeof(next);
		if (sysctl(query, (u_int)n + 2, next, &nextlen, NULL, 0) != 0)
			break;
		n = (int)(nextlen / sizeof(int));
		if (nextlen <= rootlen * sizeof(int) ||
		    memcmp(next, root, rootlen * sizeof(int)) != 0)
			break;
		query[1] = CTL_SYSCTL_OIDFMT;
		memcpy(query + 2, next, nextlen);
		memset(&fmt, 0, sizeof(fmt));
		len = sizeof(fmt);
		if (sysctl(query, (u_int)n + 2, &fmt, &len, NULL, 0) != 0 ||
		    (fmt.kind & CTLTYPE) != CTLTYPE_INT ||
		    strcmp(fmt.format, "IK") != 0)
			continue;
		query[1] = CTL_SYSCTL_NAME;
		memset(&sensor, 0, sizeof(sensor));
		len = sizeof(sensor.name);
		if (sysctl(query, (u_int)n + 2, sensor.name, &len, NULL, 0) != 0)
			continue;
		/* ACPI also exposes thresholds in Kelvin; omit those. */
		if (strcmp(tree, "hw.acpi.thermal") == 0 &&
		    (strrchr(sensor.name, '.') == NULL ||
		    strcmp(strrchr(sensor.name, '.'), ".temperature") != 0))
			continue;
		len = sizeof(v);
		if (sysctl(next, (u_int)n, &v, &len, NULL, 0) != 0 ||
		    len != sizeof(v) || v < 0)
			continue;
		sensor.celsius = decikelvin_to_celsius(v);
		thermal = reallocarray(snap->thermal,
		    (size_t)snap->nthermal + 1, sizeof(*thermal));
		if (thermal == NULL)
			return (-1);
		snap->thermal = thermal;
		snap->thermal[snap->nthermal++] = sensor;
	}
	return (0);
}

int
sys_snapshot(struct sys_snapshot *snap, int cpucount __unused)
{
	cpuset_t mask;
	long lv;
	int i, cpu, v, cpus;

	memset(snap, 0, sizeof(*snap));
	clock_gettime(CLOCK_REALTIME, &snap->ts);
	(void)sysctl_str("hw.model", snap->model, sizeof(snap->model));
	/* ROOT ignores a task's affinity restriction, but honors jail roots. */
	if (cpuset_getaffinity(CPU_LEVEL_ROOT, CPU_WHICH_PID, -1,
	    sizeof(mask), &mask) != 0)
		return (-1);
	cpus = CPU_COUNT(&mask);
	if (cpus == 0) {
		errno = ENXIO;
		return (-1);
	}
	snap->cores = calloc((size_t)cpus, sizeof(*snap->cores));
	if (snap->cores == NULL)
		return (-1);
	snap->ncores = cpus;
	for (cpu = i = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, &mask))
			continue;
		core_read(&snap->cores[i], cpu);
		if (snap->cores[i].throttled)
			snap->any_throttled = 1;
		i++;
	}
	{
		long *ticks;
		size_t len, expected;

		_Static_assert(CPUSTATES == 5, "CPU accounting layout");
		/* cp_times is indexed by CPU id, including offline slots. */
		len = 0;
		if (sysctlbyname("kern.cp_times", NULL, &len, NULL, 0) == 0 &&
		    len > 0 && len % (CPUSTATES * sizeof(long)) == 0) {
			expected = len;
			ticks = malloc(len);
			if (ticks == NULL) {
				sys_snapshot_free(snap);
				return (-1);
			}
			if (sysctlbyname("kern.cp_times", ticks, &len, NULL, 0) == 0 &&
			    len == expected) {
				for (i = 0; i < snap->ncores; i++) {
					cpu = snap->cores[i].cpu;
					if ((size_t)cpu >= len / (CPUSTATES * sizeof(long)))
						continue;
					memcpy(snap->cores[i].ticks, ticks + cpu * CPUSTATES,
					    sizeof(snap->cores[i].ticks));
					snap->cores[i].have_ticks = 1;
				}
			}
			free(ticks);
		}
	}
	if (hw_metrics_read(snap) != 0 ||
	    thermal_read(snap, "dev.amdtemp") != 0 ||
	    thermal_read(snap, "hw.acpi.thermal") != 0) {
		sys_snapshot_free(snap);
		return (-1);
	}
	if (sysctl_int("dev.cpu.0.coretemp.tjmax", &v) == 0 && v >= 0) {
		snap->have_tjmax = 1;
		snap->tjmax = decikelvin_to_celsius(v);
	}
	if (sysctl_int("hw.acpi.thermal.tz0.temperature", &v) == 0 && v >= 0) {
		snap->have_acpi = 1;
		snap->acpi_temp = decikelvin_to_celsius(v);
	}
	if (sysctl_number("sys.class.drm.card0.gt.gt0.rps_act_freq_mhz",
	    &lv) == 0) {
		snap->have_gpu_freq = 1;
		snap->gpu_freq = lv;
	}
	if (sysctl_number("sys.class.drm.card0.gt.gt0.rc6_residency_ms",
	    &lv) == 0) {
		snap->have_gpu_rc6 = 1;
		snap->gpu_rc6_ms = lv;
	}
	if (sysctl_number("sys.class.drm.card0.gt.gt0.throttle_reason_status",
	    &lv) == 0)
		snap->gpu_throttled = lv != 0;
	return (0);
}

void
sys_snapshot_free(struct sys_snapshot *snap)
{

	free(snap->metrics);
	snap->metrics = NULL;
	snap->nmetrics = 0;
	free(snap->sources);
	snap->sources = NULL;
	snap->nsources = 0;
	free(snap->thermal);
	snap->thermal = NULL;
	snap->nthermal = 0;
	free(snap->cores);
	snap->cores = NULL;
	snap->ncores = 0;
}

void
sys_snapshot_delta(struct sys_snapshot *snap, const struct sys_snapshot *prev)
{
	struct core_snap *cur;
	const struct core_snap *old;
	double total, delta[CPUSTATES];
	int i, j, k;

	for (i = 0; i < snap->ncores; i++) {
		cur = &snap->cores[i];
		cur->have_usage = 0;
		if (!cur->have_ticks)
			continue;
		for (k = 0; k < prev->ncores; k++)
			if (prev->cores[k].cpu == cur->cpu)
				break;
		if (k == prev->ncores)
			continue;
		old = &prev->cores[k];
		if (!old->have_ticks)
			continue;
		total = 0;
		for (j = 0; j < CPUSTATES; j++) {
			/* Rebaseline after a reset, wrap, or invalid counter. */
			if (old->ticks[j] < 0 || cur->ticks[j] < old->ticks[j])
				break;
			delta[j] = (double)(cur->ticks[j] - old->ticks[j]);
			total += delta[j];
		}
		if (j != CPUSTATES || total == 0)
			continue;
		for (j = 0; j < CPUSTATES; j++)
			cur->usage[j] = 100.0 * delta[j] / total;
		cur->have_usage = 1;
	}
}

int
snap_temp_stats(const struct sys_snapshot *snap, double *minv, double *avgv,
    double *maxv)
{
	double sum;
	int i, n;

	sum = 0;
	n = 0;
	for (i = 0; i < snap->ncores; i++) {
		const struct core_snap *c = &snap->cores[i];

		if (!c->have_temp)
			continue;
		if (n == 0 || c->temp < *minv)
			*minv = c->temp;
		if (n == 0 || c->temp > *maxv)
			*maxv = c->temp;
		sum += c->temp;
		n++;
	}
	if (n == 0)
		return (0);
	*avgv = sum / n;
	return (n);
}

int
snap_freq_stats(const struct sys_snapshot *snap, int *minv, int *avgv,
    int *maxv)
{
	long sum;
	int i, n;

	sum = 0;
	n = 0;
	for (i = 0; i < snap->ncores; i++) {
		const struct core_snap *c = &snap->cores[i];

		if (!c->have_freq)
			continue;
		if (n == 0 || c->freq < *minv)
			*minv = c->freq;
		if (n == 0 || c->freq > *maxv)
			*maxv = c->freq;
		sum += c->freq;
		n++;
	}
	if (n == 0)
		return (0);
	*avgv = (int)(sum / n);
	return (n);
}

const struct core_snap *
snap_first_cstate(const struct sys_snapshot *snap)
{
	int i;

	for (i = 0; i < snap->ncores; i++)
		if (snap->cores[i].have_cstate)
			return (&snap->cores[i]);
	return (NULL);
}
