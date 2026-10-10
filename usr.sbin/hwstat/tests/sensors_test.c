/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/cpuset.h>
#include <sys/sysctl.h>
#include <atf-c.h>
#include <errno.h>
#include <string.h>

static int mock_sysctl(const int *, u_int, void *, size_t *, const void *, size_t);
static int mock_nametomib(const char *, int *, size_t *);
static int mock_byname(const char *, void *, size_t *, const void *, size_t);
static int core_temperature = -1;
static int use_mask, thermal_status;
static cpuset_t cpu_mask;
static long cpu_ticks[8][5];
static int mock_affinity(cpulevel_t, cpuwhich_t, id_t, size_t, cpuset_t *);

#define cpuset_getaffinity mock_affinity
#define sysctlbyname mock_byname
#define sysctl mock_sysctl
#define sysctlnametomib mock_nametomib
#include "../sensors.c"
#undef cpuset_getaffinity
#undef sysctl
#undef sysctlbyname
#undef sysctlnametomib

static int
mock_affinity(cpulevel_t level, cpuwhich_t which, id_t id, size_t size,
    cpuset_t *mask)
{

	ATF_REQUIRE_EQ(level, CPU_LEVEL_ROOT);
	ATF_REQUIRE_EQ(which, CPU_WHICH_PID);
	ATF_REQUIRE_EQ(id, -1);
	ATF_REQUIRE_EQ(size, sizeof(*mask));
	CPU_ZERO(mask);
	if (use_mask)
		*mask = cpu_mask;
	else
		CPU_SET(0, mask);
	return (0);
}

static int
mock_byname(const char *name, void *out, size_t *len,
    const void *newp, size_t newlen)
{
	ATF_REQUIRE(newp == NULL && newlen == 0);
	if (thermal_status && strcmp(name, "dev.cpu.0.coretemp.thermal_status") == 0) {
		uint32_t status = (1U << 31) | (25U << 16) | 3;
		memcpy(out, &status, sizeof(status));
		*len = sizeof(status);
		return (0);
	}
	if (thermal_status && strcmp(name, "dev.cpu.0.coretemp.tjmax") == 0) {
		int tjmax = 3731;
		memcpy(out, &tjmax, sizeof(tjmax));
		*len = sizeof(tjmax);
		return (0);
	}
	if (thermal_status)
		ATF_REQUIRE(strcmp(name, "dev.cpu.0.temperature") != 0 &&
		    strcmp(name, "dev.cpu.0.coretemp.throttle_log") != 0);
	if (use_mask && strcmp(name, "kern.cp_times") == 0) {
		if (out != NULL) {
			ATF_REQUIRE(*len >= sizeof(cpu_ticks));
			memcpy(out, cpu_ticks, sizeof(cpu_ticks));
		}
		*len = sizeof(cpu_ticks);
		return (0);
	}
	if (strcmp(name, "dev.cpu.0.temperature") != 0) {
		errno = ENOENT;
		return (-1);
	}
	ATF_REQUIRE(*len >= sizeof(core_temperature));
	memcpy(out, &core_temperature, sizeof(core_temperature));
	*len = sizeof(core_temperature);
	return (0);
}

static const struct {
	const char *name;
	const char *format;
	int value;
	int error;
} readings[] = {
	{ "dev.amdtemp.0.core0.sensor0", "IK", 3231, 0 },
	{ "dev.amdtemp.0.ccd2", "IK", 3331, 0 },
	{ "dev.amdtemp.0.sensor_offset", "I", 10, 0 },
	{ "hw.acpi.thermal.tz0.temperature", "IK", 3131, 0 },
	{ "hw.acpi.thermal.tz1.temperature", "IK", 3031, 0 },
	{ "hw.acpi.thermal.tz1._CRT", "IK", 3731, 0 },
	{ "hw.acpi.thermal.tz2.temperature", "IK", -1, 0 },
	{ "hw.acpi.thermal.tz3.temperature", "IK", 0, EIO },
};

static int
mock_nametomib(const char *name, int *mib, size_t *len)
{

	ATF_REQUIRE(*len >= 1);
	if (strcmp(name, "dev.amdtemp") == 0)
		mib[0] = 10;
	else if (strcmp(name, "hw.acpi.thermal") == 0)
		mib[0] = 20;
	else {
		errno = ENOENT;
		return (-1);
	}
	*len = 1;
	return (0);
}

static int
mock_sysctl(const int *mib, u_int n, void *out, size_t *len,
    const void *newp, size_t newlen)
{
	struct { u_int kind; char format[32]; } fmt;
	int next[2], i, first, last;
	size_t size;

	ATF_REQUIRE(newp == NULL);
	ATF_REQUIRE_EQ(newlen, 0);
	if (mib[0] != CTL_SYSCTL) {
		ATF_REQUIRE_EQ(n, 2);
		i = mib[1];
		if (readings[i].error) {
			errno = readings[i].error;
			return (-1);
		}
		ATF_REQUIRE_EQ(*len, sizeof(int));
		memcpy(out, &readings[i].value, sizeof(int));
		return (0);
	}
	first = mib[2] == 10 ? 0 : 3;
	last = mib[2] == 10 ? 3 : 8;
	if (mib[1] == CTL_SYSCTL_NEXT) {
		i = n == 3 ? first : mib[3] + 1;
		next[0] = i < last ? mib[2] : mib[2] + 1;
		next[1] = i;
		ATF_REQUIRE(*len >= sizeof(next));
		memcpy(out, next, sizeof(next));
		*len = sizeof(next);
		return (0);
	}
	ATF_REQUIRE_EQ(n, 4);
	i = mib[3];
	if (mib[1] == CTL_SYSCTL_NAME) {
		size = strlen(readings[i].name) + 1;
		ATF_REQUIRE(*len >= size);
		memcpy(out, readings[i].name, size);
		*len = size;
	} else {
		ATF_REQUIRE_EQ(mib[1], CTL_SYSCTL_OIDFMT);
		memset(&fmt, 0, sizeof(fmt));
		fmt.kind = CTLTYPE_INT | CTLFLAG_RD;
		strlcpy(fmt.format, readings[i].format, sizeof(fmt.format));
		ATF_REQUIRE_EQ(*len, sizeof(fmt));
		memcpy(out, &fmt, sizeof(fmt));
	}
	return (0);
}

ATF_TC_WITHOUT_HEAD(named_temperatures);
ATF_TC_BODY(named_temperatures, tc)
{
	struct sys_snapshot snap;

	memset(&snap, 0, sizeof(snap));
	ATF_REQUIRE_EQ(thermal_read(&snap, "missing"), 0);
	ATF_REQUIRE_EQ(snap.nthermal, 0);
	ATF_REQUIRE_EQ(thermal_read(&snap, "dev.amdtemp"), 0);
	ATF_REQUIRE_EQ(snap.nthermal, 2);
	ATF_CHECK_STREQ(snap.thermal[1].name, "dev.amdtemp.0.ccd2");
	ATF_CHECK(snap.thermal[0].celsius > 49.9 &&
	    snap.thermal[0].celsius < 50.1);
	ATF_REQUIRE_EQ(thermal_read(&snap, "hw.acpi.thermal"), 0);
	ATF_REQUIRE_EQ(snap.nthermal, 4);
	ATF_CHECK_STREQ(snap.thermal[3].name,
	    "hw.acpi.thermal.tz1.temperature");
	ATF_CHECK(snap.thermal[3].celsius > 29.9 &&
	    snap.thermal[3].celsius < 30.1);
	sys_snapshot_free(&snap);
	ATF_CHECK(snap.thermal == NULL);
	ATF_CHECK_EQ(snap.nthermal, 0);
}

ATF_TC_WITHOUT_HEAD(cpu_intervals);
ATF_TC_BODY(cpu_intervals, tc)
{
	struct core_snap a = { .cpu = 0, .have_ticks = 1,
	    .ticks = {100, 10, 40, 5, 500} };
	struct core_snap b = { .cpu = 0, .have_ticks = 1,
	    .ticks = {120, 15, 50, 10, 560} };
	struct sys_snapshot old = { .cores = &a, .ncores = 1 };
	struct sys_snapshot cur = { .cores = &b, .ncores = 1 };

	sys_snapshot_delta(&cur, &old);
	ATF_REQUIRE(b.have_usage);
	ATF_CHECK_EQ(b.usage[0], 20);
	ATF_CHECK_EQ(b.usage[4], 60);
	b.ticks[0] = 99; /* reset: no invented busy percentage */
	sys_snapshot_delta(&cur, &old);
	ATF_CHECK(!b.have_usage);
	b = a;
	sys_snapshot_delta(&cur, &old);
	ATF_CHECK(!b.have_usage); /* no ticks in this interval */
	b.ticks[0]++;
	a.have_ticks = 0;
	sys_snapshot_delta(&cur, &old);
	ATF_CHECK(!b.have_usage);
}

ATF_TC_WITHOUT_HEAD(invalid_temperature);
ATF_TC_BODY(invalid_temperature, tc)
{
	struct core_snap core;

	core_temperature = -1; /* coretemp's invalid-reading sentinel */
	core_read(&core, 0);
	ATF_CHECK(!core.have_temp);
	core_temperature = 3231;
	core_read(&core, 0);
	ATF_REQUIRE(core.have_temp);
	ATF_CHECK(core.temp > 49.9 && core.temp < 50.1);
}

ATF_TC_WITHOUT_HEAD(sparse_cpu_ids);
ATF_TC_BODY(sparse_cpu_ids, tc)
{
	struct sys_snapshot before, after;

	use_mask = 1;
	CPU_ZERO(&cpu_mask);
	CPU_SET(0, &cpu_mask);
	CPU_SET(7, &cpu_mask);
	cpu_ticks[7][4] = 100;
	ATF_REQUIRE_EQ(sys_snapshot(&before, 2), 0);
	ATF_REQUIRE_EQ(before.ncores, 2);
	ATF_CHECK_EQ(before.cores[1].cpu, 7);
	ATF_CHECK_EQ(before.cores[1].ticks[4], 100);
	CPU_CLR(0, &cpu_mask); /* membership/index changes */
	cpu_ticks[7][0] = 20;
	cpu_ticks[7][4] = 180;
	ATF_REQUIRE_EQ(sys_snapshot(&after, 2), 0);
	ATF_REQUIRE_EQ(after.ncores, 1);
	ATF_REQUIRE_EQ(after.cores[0].cpu, 7);
	sys_snapshot_delta(&after, &before);
	ATF_REQUIRE(after.cores[0].have_usage);
	ATF_CHECK_EQ(after.cores[0].usage[0], 20);
	ATF_CHECK_EQ(after.cores[0].usage[4], 80);
	sys_snapshot_free(&before);
	sys_snapshot_free(&after);
}

ATF_TC_WITHOUT_HEAD(nonclearing_intel_temperature);
ATF_TC_BODY(nonclearing_intel_temperature, tc)
{
	struct core_snap core;

	thermal_status = 1;
	core_read(&core, 0);
	ATF_REQUIRE(core.have_temp);
	ATF_REQUIRE(core.have_thermal_status);
	ATF_CHECK(core.throttled);
	ATF_CHECK(core.temp > 74.9 && core.temp < 75.1);
	ATF_CHECK((core.thermal_status & 3) == 3);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, sparse_cpu_ids);
	ATF_TP_ADD_TC(tp, nonclearing_intel_temperature);
	ATF_TP_ADD_TC(tp, named_temperatures);
	ATF_TP_ADD_TC(tp, cpu_intervals);
	ATF_TP_ADD_TC(tp, invalid_temperature);
	return (atf_no_error());
}
