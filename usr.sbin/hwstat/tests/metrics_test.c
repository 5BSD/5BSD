/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <atf-c.h>
#include <errno.h>
#include <string.h>

static int mock_sysctlbyname(const char *, void *, size_t *, const void *, size_t);
#define sysctlbyname mock_sysctlbyname
#include "../metrics.c"
#undef sysctlbyname

static int
mock_sysctlbyname(const char *name, void *buf, size_t *len,
    const void *newp, size_t newlen)
{
	uint8_t data[120];
	uint32_t v;

	ATF_REQUIRE(newp == NULL && newlen == 0);
	if (strcmp(name, "sys.device.drmn0.gpu_metrics") == 0) {
		data[0] = 120;
		data[1] = 0;
		memcpy(buf, data, 2);
		*len = 2;
		return (0);
	}
	if (strcmp(name, "sys.device.drmn3.gpu_metrics") == 0) {
		memset(data, 0xff, sizeof(data));
		le16enc(data, sizeof(data));
		data[2] = 2;
		data[3] = 1;
		le16enc(data + 4, 4500);
		ATF_REQUIRE(*len >= sizeof(data));
		memcpy(buf, data, sizeof(data));
		*len = sizeof(data);
		return (0);
	}
	if (strcmp(name, "dev.hwpstate_intel.0.caps_guaranteed_performance") == 0)
		v = 142;
	else if (strcmp(name, "dev.hwpstate_intel.0.cpuid_base_frequency_mhz") == 0)
		v = 2400;
	else if (strcmp(name, "dev.hwpstate_intel.0.epp") == 0)
		v = 75;
	else if (strcmp(name, "dev.hwpstate_amd.0.epp") == 0)
		v = 192;
	else if (strcmp(name, "hw.cpufreq.arm_max_freq") == 0)
		v = 1800000000;
	else if (strcmp(name, "hw.cpufreq.throttled") == 0)
		v = 0x50005;
	else if (strcmp(name, "dev.cpu.0.coretemp.thermal_status") == 0)
		v = 0x80000011;
	else {
		errno = ENOENT;
		return (-1);
	}
	ATF_REQUIRE(*len >= sizeof(v));
	memcpy(buf, &v, sizeof(v));
	*len = sizeof(v);
	return (0);
}

ATF_TC_WITHOUT_HEAD(amd_binary);
ATF_TC_BODY(amd_binary, tc)
{
	struct sys_snapshot snap = {0};
	uint8_t data[128];

	memset(data, 0xff, sizeof(data));
	le16enc(data, 120);
	data[2] = 2;
	data[3] = 1;
	le16enc(data + 4, 4512);
	le16enc(data + 28, 0);
	le16enc(data + 40, 26000);
	le16enc(data + 88, 4800);
	ATF_REQUIRE_EQ(amd_metrics_decode(&snap, "drmn3", data, 120), 0);
	ATF_REQUIRE_EQ(snap.nmetrics, 4);
	ATF_CHECK_STREQ(snap.metrics[0].name, "gfx_temperature_millicelsius");
	ATF_CHECK_EQ(snap.metrics[0].value, 45120);
	ATF_CHECK_EQ(snap.metrics[1].value, 0);
	ATF_CHECK_STREQ(snap.metrics[2].name, "socket_power_milliwatts");
	ATF_CHECK_EQ(snap.metrics[2].value, 26000);
	ATF_CHECK_STREQ(snap.metrics[3].name, "core0_frequency_mhz");
	ATF_CHECK_EQ(snap.metrics[3].value, 4800);
	ATF_CHECK_STREQ(snap.metrics[3].source, "drmn3");
	free(snap.metrics);
}

ATF_TC_WITHOUT_HEAD(amd_invalid);
ATF_TC_BODY(amd_invalid, tc)
{
	struct sys_snapshot snap = {0};
	uint8_t data[128];

	memset(data, 0xff, sizeof(data));
	le16enc(data, 120);
	data[2] = 2;
	data[3] = 1;
	ATF_CHECK_EQ(amd_metrics_decode(&snap, "gpu", data, 2), EMSGSIZE);
	ATF_CHECK_EQ(amd_metrics_decode(&snap, "gpu", data, 119), EMSGSIZE);
	ATF_CHECK_EQ(amd_metrics_decode(&snap, "gpu", data, 128), EMSGSIZE);
	ATF_CHECK_EQ(snap.nmetrics, 0);
	ATF_REQUIRE_EQ(amd_metrics_decode(&snap, "gpu", data, 120), 0);
	ATF_CHECK_EQ(snap.nmetrics, 0); /* sentinel values remain unavailable */
	data[3] = 2;
	ATF_CHECK_EQ(amd_metrics_decode(&snap, "gpu", data, 128), EMSGSIZE);
	le16enc(data, 128);
	ATF_REQUIRE_EQ(amd_metrics_decode(&snap, "gpu", data, 128), 0);
	data[3] = 3;
	ATF_CHECK_EQ(amd_metrics_decode(&snap, "gpu", data, 128), ENOTSUP);
	data[2] = 1;
	ATF_CHECK_EQ(amd_metrics_decode(&snap, "gpu", data, 128), ENOTSUP);
	ATF_CHECK_EQ(snap.nmetrics, 0);
	free(snap.metrics);
}

ATF_TC_WITHOUT_HEAD(platform_collectors);
ATF_TC_BODY(platform_collectors, tc)
{
	struct core_snap core = { .cpu = 0, .have_thermal_status = 1,
	    .thermal_status = 0x11 };
	struct sys_snapshot snap = { .cores = &core, .ncores = 1 };
	size_t i;
	int current, historical, intel;

	ATF_REQUIRE_EQ(hw_metrics_read(&snap), 0);
	ATF_REQUIRE_EQ(snap.nsources, 2);
	ATF_CHECK_STREQ(snap.sources[0].status, "invalid_length");
	ATF_CHECK_STREQ(snap.sources[1].name, "sys.device.drmn3.gpu_metrics");
	ATF_CHECK_STREQ(snap.sources[1].status, "available");
	current = historical = intel = 0;
	for (i = 0; i < snap.nmetrics; i++) {
		if (strcmp(snap.metrics[i].name, "undervoltage_current") == 0) {
			ATF_CHECK_EQ(snap.metrics[i].value, 1);
			current++;
		}
		if (strcmp(snap.metrics[i].name, "throttled_occurred") == 0) {
			ATF_CHECK_EQ(snap.metrics[i].value, 1);
			historical++;
		}
		if (strcmp(snap.metrics[i].name, "critical_temperature_current") == 0) {
			ATF_CHECK_EQ(snap.metrics[i].value, 1);
			intel++;
		}
		if (strcmp(snap.metrics[i].name, "frequency_capped_current") == 0)
			ATF_CHECK_EQ(snap.metrics[i].value, 0);
	}
	ATF_CHECK_EQ(current, 1);
	ATF_CHECK_EQ(historical, 1);
	ATF_CHECK_EQ(intel, 1);
	free(snap.metrics);
	free(snap.sources);
}

ATF_TC_WITHOUT_HEAD(frequency_capabilities);
ATF_TC_BODY(frequency_capabilities, tc)
{
	int low, high, count;

	ATF_REQUIRE_EQ(freq_levels_bounds("3793/-1", &low, &high, &count), 0);
	ATF_CHECK_EQ(low, 3793);
	ATF_CHECK_EQ(high, 3793);
	ATF_CHECK_EQ(count, 1);
	ATF_REQUIRE_EQ(freq_levels_bounds("2400/18000 1200/-1 800/4000 ",
	    &low, &high, &count), 0);
	ATF_CHECK_EQ(low, 800);
	ATF_CHECK_EQ(high, 2400);
	ATF_CHECK_EQ(count, 3);
	ATF_CHECK_EQ(freq_levels_bounds("", &low, &high, &count), ENOENT);
	ATF_CHECK_EQ(freq_levels_bounds("2400/bad", &low, &high, &count), EINVAL);
	ATF_CHECK_EQ(freq_levels_bounds("2400/-1x", &low, &high, &count), EINVAL);
	ATF_CHECK_EQ(freq_levels_bounds("-1/-1", &low, &high, &count), EINVAL);
}

ATF_TC_WITHOUT_HEAD(capability_collectors);
ATF_TC_BODY(capability_collectors, tc)
{
	struct core_snap core = { .cpu = 0, .have_thermal_status = 1,
	    .thermal_status = 0x11 };
	struct sys_snapshot snap = { .cores = &core, .ncores = 1 };
	size_t i;
	int found = 0;

	ATF_REQUIRE_EQ(hw_capabilities_read(&snap), 0);
	ATF_REQUIRE_EQ(snap.nmetrics, 5);
	for (i = 0; i < snap.nmetrics; i++) {
		if (strcmp(snap.metrics[i].name, "hwp_caps_guaranteed_performance") == 0) {
			ATF_CHECK_EQ(snap.metrics[i].value, 142);
			found++;
		} else if (strcmp(snap.metrics[i].name, "cpuid_base_frequency_mhz") == 0) {
			ATF_CHECK_EQ(snap.metrics[i].value, 2400);
			found++;
		} else if (strcmp(snap.metrics[i].name, "arm_max_freq_hz") == 0) {
			ATF_CHECK_EQ(snap.metrics[i].value, 1800000000);
			found++;
		} else if (strcmp(snap.metrics[i].name, "hwp_epp_pct") == 0) {
			ATF_CHECK_EQ(snap.metrics[i].value, 75);
			found++;
		} else if (strcmp(snap.metrics[i].name, "cppc_epp") == 0) {
			ATF_CHECK_EQ(snap.metrics[i].value, 192);
			found++;
		}
	}
	ATF_CHECK_EQ(found, 5);
	free(snap.metrics);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, amd_binary);
	ATF_TP_ADD_TC(tp, amd_invalid);
	ATF_TP_ADD_TC(tp, platform_collectors);
	ATF_TP_ADD_TC(tp, frequency_capabilities);
	ATF_TP_ADD_TC(tp, capability_collectors);
	return (atf_no_error());
}
