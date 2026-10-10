/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hwstat.h"

static int
metric_add(struct sys_snapshot *snap, const char *source, const char *name,
    int64_t value)
{
	struct hw_metric *m;

	m = reallocarray(snap->metrics, snap->nmetrics + 1, sizeof(*m));
	if (m == NULL)
		return (ENOMEM);
	snap->metrics = m;
	m += snap->nmetrics++;
	strlcpy(m->source, source, sizeof(m->source));
	strlcpy(m->name, name, sizeof(m->name));
	m->value = value;
	return (0);
}

static int
source_add(struct sys_snapshot *snap, const char *name, const char *status)
{
	struct hw_source *s;

	s = reallocarray(snap->sources, snap->nsources + 1, sizeof(*s));
	if (s == NULL)
		return (ENOMEM);
	snap->sources = s;
	s += snap->nsources++;
	strlcpy(s->name, name, sizeof(s->name));
	strlcpy(s->status, status, sizeof(s->status));
	return (0);
}

/*
 * AMD kgd_pp_interface.h gpu_metrics_v2_1/v2_2 ABI. Explicit offsets avoid
 * host alignment differences (notably uint64_t on i386). Revision 2.2 adds
 * an independent throttle bitmap; the prefix has the same 120-byte layout.
 * 0xffff denotes an unpopulated 16-bit field, not a physical measurement.
 */
int
amd_metrics_decode(struct sys_snapshot *snap, const char *source,
    const void *data, size_t len)
{
	static const struct {
		unsigned offset;
		const char *name;
		int scale;
	} fields[] = {
		{ 4, "gfx_temperature_millicelsius", 10 },
		{ 6, "soc_temperature_millicelsius", 10 },
		{ 28, "gfx_activity_basis_points", 1 },
		{ 30, "media_activity_basis_points", 1 },
		{ 40, "socket_power_milliwatts", 1 },
		{ 42, "cpu_power_milliwatts", 1 },
		{ 44, "soc_power_milliwatts", 1 },
		{ 46, "gfx_power_milliwatts", 1 },
		{ 64, "average_gfx_frequency_mhz", 1 },
		{ 66, "average_soc_frequency_mhz", 1 },
		{ 68, "average_memory_frequency_mhz", 1 },
		{ 70, "average_fabric_frequency_mhz", 1 },
		{ 72, "average_video_frequency_mhz", 1 },
		{ 74, "average_display_frequency_mhz", 1 },
		{ 76, "current_gfx_frequency_mhz", 1 },
		{ 78, "current_soc_frequency_mhz", 1 },
		{ 80, "current_memory_frequency_mhz", 1 },
		{ 82, "current_fabric_frequency_mhz", 1 },
		{ 84, "current_video_frequency_mhz", 1 },
		{ 86, "current_display_frequency_mhz", 1 },
	};
	const uint8_t *p = data;
	char name[64];
	uint32_t flags;
	uint16_t v;
	size_t i, required, start;
	int error;

	if (len < 4)
		return (EMSGSIZE);
	if (p[2] != 2 || (p[3] != 1 && p[3] != 2))
		return (ENOTSUP);
	required = p[3] == 1 ? 120 : 128;
	if (len != required || le16dec(p) != required)
		return (EMSGSIZE);
	start = snap->nmetrics;
	for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
		v = le16dec(p + fields[i].offset);
		if (v == UINT16_MAX)
			continue;
		/* Activity is in hundredths of a percent. */
		if ((fields[i].offset == 28 || fields[i].offset == 30) &&
		    v > 10000)
			continue;
		error = metric_add(snap, source, fields[i].name,
		    (int64_t)v * fields[i].scale);
		if (error != 0)
			goto fail;
	}
	for (i = 0; i < 8; i++) {
		v = le16dec(p + 8 + 2 * i);
		if (v != UINT16_MAX) {
			snprintf(name, sizeof(name),
			    "core%zu_temperature_millicelsius", i);
			error = metric_add(snap, source, name, (int64_t)v * 10);
			if (error != 0)
				goto fail;
		}
		v = le16dec(p + 48 + 2 * i);
		if (v != UINT16_MAX) {
			snprintf(name, sizeof(name), "core%zu_power_milliwatts", i);
			error = metric_add(snap, source, name, v);
			if (error != 0)
				goto fail;
		}
		v = le16dec(p + 88 + 2 * i);
		if (v != UINT16_MAX) {
			snprintf(name, sizeof(name), "core%zu_frequency_mhz", i);
			error = metric_add(snap, source, name, v);
			if (error != 0)
				goto fail;
		}
	}
	for (i = 0; i < 2; i++) {
		v = le16dec(p + 24 + 2 * i);
		if (v != UINT16_MAX) {
			snprintf(name, sizeof(name),
			    "l3_%zu_temperature_millicelsius", i);
			error = metric_add(snap, source, name, (int64_t)v * 10);
			if (error != 0)
				goto fail;
		}
		v = le16dec(p + 104 + 2 * i);
		if (v != UINT16_MAX) {
			snprintf(name, sizeof(name), "l3_%zu_frequency_mhz", i);
			error = metric_add(snap, source, name, v);
			if (error != 0)
				goto fail;
		}
	}
	flags = le32dec(p + 108);
	if (flags != UINT32_MAX) {
		/* ASIC-dependent: retain the raw bitmap without guessing reasons. */
		error = metric_add(snap, source, "throttle_status_raw", flags);
		if (error != 0)
			goto fail;
	}
	return (0);
fail:
	snap->nmetrics = start;
	return (error);
}

static int
read_u32(const char *source, uint32_t *v)
{
	size_t len = sizeof(*v);

	return (sysctlbyname(source, v, &len, NULL, 0) == 0 &&
	    len == sizeof(*v));
}

int
hw_metrics_read(struct sys_snapshot *snap)
{
	static const struct {
		const char *sysctl;
		const char *name;
	} pi[] = {
		{ "arm_freq", "arm_frequency_hz" },
		{ "core_freq", "core_frequency_hz" },
		{ "sdram_freq", "sdram_frequency_hz" },
		{ "temperature", "soc_temperature_millicelsius" },
	};
	static const char *pi_flags[] = {
		"undervoltage", "frequency_capped", "throttled", "soft_temp_limit"
	};
	uint8_t data[4096];
	char source[128], name[64];
	const char *status;
	uint32_t v;
	size_t len, j;
	int unit, error;

	/* Probe independently: a missing drm unit does not end enumeration. */
	for (unit = 0; unit < 64; unit++) {
		snprintf(source, sizeof(source), "sys.device.drmn%d.gpu_metrics", unit);
		len = sizeof(data);
		if (sysctlbyname(source, data, &len, NULL, 0) == -1) {
			if (errno == ENOENT)
				continue;
			status = errno == EACCES || errno == EPERM ?
			    "permission_denied" : "read_error";
		} else {
			error = amd_metrics_decode(snap, source, data, len);
			if (error == ENOMEM)
				return (error);
			status = error == 0 ? "available" : error == ENOTSUP ?
			    "unsupported_revision" : "invalid_length";
		}
		if (source_add(snap, source, status) != 0)
			return (ENOMEM);
	}
	for (j = 0; j < sizeof(pi) / sizeof(pi[0]); j++) {
		snprintf(source, sizeof(source), "hw.cpufreq.%s", pi[j].sysctl);
		if (read_u32(source, &v) &&
		    metric_add(snap, source, pi[j].name, v) != 0)
			return (ENOMEM);
	}
	strlcpy(source, "hw.cpufreq.throttled", sizeof(source));
	if (read_u32(source, &v)) {
		if (metric_add(snap, source, "throttle_status_raw", v) != 0)
			return (ENOMEM);
		for (j = 0; j < 4; j++) {
			snprintf(name, sizeof(name), "%s_current", pi_flags[j]);
			if (metric_add(snap, source, name, (v >> j) & 1) != 0)
				return (ENOMEM);
			snprintf(name, sizeof(name), "%s_occurred", pi_flags[j]);
			if (metric_add(snap, source, name, (v >> (j + 16)) & 1) != 0)
				return (ENOMEM);
		}
	}
	for (unit = 0; unit < snap->ncores; unit++) {
		snprintf(source, sizeof(source), "dev.cpu.%d.coretemp.thermal_status",
		    snap->cores[unit].cpu);
		if (!snap->cores[unit].have_thermal_status)
			continue;
		v = snap->cores[unit].thermal_status;
		if (metric_add(snap, source, "thermal_status_raw", v) != 0 ||
		    metric_add(snap, source, "thermal_throttled_current", v & 1) != 0 ||
		    metric_add(snap, source, "critical_temperature_current",
		    (v >> 4) & 1) != 0)
			return (ENOMEM);
	}
	return (0);
}

/* Legacy cpufreq entries are MHz/milliwatts; -1 power means unknown. */
static int
freq_levels_bounds(const char *text, int *minp, int *maxp, int *countp)
{
	const char *p;
	char *end;
	long frequency;
	int low, high, count;

	low = INT_MAX;
	high = count = 0;
	p = text;
	while (*p != '\0') {
		while (isspace((unsigned char)*p))
			p++;
		if (*p == '\0')
			break;
		errno = 0;
		frequency = strtol(p, &end, 10);
		if (end == p || errno == ERANGE || *end != '/' ||
		    frequency <= 0 || frequency > INT_MAX)
			return (EINVAL);
		p = end + 1;
		(void)strtol(p, &end, 10);
		if (end == p || errno == ERANGE ||
		    (*end != '\0' && !isspace((unsigned char)*end)))
			return (EINVAL);
		if (frequency < low)
			low = (int)frequency;
		if (frequency > high)
			high = (int)frequency;
		count++;
		p = end;
	}
	if (count == 0)
		return (ENOENT);
	*minp = low;
	*maxp = high;
	*countp = count;
	return (0);
}

/* Inventory and policy limits are collected by list, not every watch tick. */
int
hw_capabilities_read(struct sys_snapshot *snap)
{
	static const char *intel_clocks[] = {
		"cpuid_base_frequency_mhz", "cpuid_max_frequency_mhz",
		"cpuid_bus_frequency_mhz"
	};
	static const char *hwp[] = {
		"caps_highest_performance", "caps_guaranteed_performance",
		"caps_efficient_performance", "caps_lowest_performance", "epp"
	};
	static const char *pi_limits[] = {
		"arm_min_freq", "arm_max_freq", "core_min_freq", "core_max_freq",
		"sdram_min_freq", "sdram_max_freq"
	};
	static const char *cppc[] = {
		"caps_highest_performance", "caps_nominal_performance",
		"caps_efficient_performance", "caps_lowest_performance",
		"minimum_performance", "maximum_performance",
		"desired_performance", "epp"
	};
	char source[128], name[64], levels[4096];
	uint32_t v;
	size_t len, j;
	int unit, low, high, count;

	for (j = 0; j < sizeof(pi_limits) / sizeof(pi_limits[0]); j++) {
		snprintf(source, sizeof(source), "hw.cpufreq.%s", pi_limits[j]);
		snprintf(name, sizeof(name), "%s_hz", pi_limits[j]);
		if (read_u32(source, &v) && v > 0 &&
		    metric_add(snap, source, name, v) != 0)
			return (ENOMEM);
	}
	if (read_u32("hw.clockrate", &v) && v > 0 && v <= INT_MAX &&
	    metric_add(snap, "hw.clockrate", "boot_clockrate_mhz", v) != 0)
		return (ENOMEM);
	for (unit = 0; unit < snap->ncores; unit++) {
		snprintf(source, sizeof(source), "dev.cpu.%d.freq_levels",
		    snap->cores[unit].cpu);
		len = sizeof(levels) - 1;
		if (sysctlbyname(source, levels, &len, NULL, 0) == 0) {
			levels[len] = '\0';
			if (freq_levels_bounds(levels, &low, &high, &count) == 0) {
				if (metric_add(snap, source, "cpufreq_level_min_mhz", low) != 0 ||
				    metric_add(snap, source, "cpufreq_level_max_mhz", high) != 0 ||
				    metric_add(snap, source, "cpufreq_level_count", count) != 0)
					return (ENOMEM);
			}
		}
		for (j = 0; j < sizeof(intel_clocks) / sizeof(intel_clocks[0]); j++) {
			snprintf(source, sizeof(source), "dev.hwpstate_intel.%d.%s",
			    snap->cores[unit].cpu, intel_clocks[j]);
			if (read_u32(source, &v) && v > 0 && v <= UINT16_MAX &&
			    metric_add(snap, source, intel_clocks[j], v) != 0)
				return (ENOMEM);
		}
		for (j = 0; j < sizeof(hwp) / sizeof(hwp[0]); j++) {
			snprintf(source, sizeof(source), "dev.hwpstate_intel.%d.%s",
			    snap->cores[unit].cpu, hwp[j]);
			snprintf(name, sizeof(name), "hwp_%s%s", hwp[j],
			    strcmp(hwp[j], "epp") == 0 ? "_pct" : "");
			if (read_u32(source, &v) && v <= 255 &&
			    metric_add(snap, source, name, v) != 0)
				return (ENOMEM);
		}
		for (j = 0; j < sizeof(cppc) / sizeof(cppc[0]); j++) {
			snprintf(source, sizeof(source), "dev.hwpstate_amd.%d.%s",
			    snap->cores[unit].cpu, cppc[j]);
			snprintf(name, sizeof(name), "cppc_%s", cppc[j]);
			if (read_u32(source, &v) && v <= 255 &&
			    metric_add(snap, source, name, v) != 0)
				return (ENOMEM);
		}
	}
	return (0);
}
