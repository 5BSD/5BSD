/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/cpuctl.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static int mock_clock_gettime(clockid_t, struct timespec *);

static int mock_open(const char *, int, ...);
static int mock_close(int);
static int mock_ioctl(int, unsigned long, ...);

#define clock_gettime mock_clock_gettime
#define open mock_open
#define close mock_close
#define ioctl mock_ioctl
#include "../rapl.c"
#undef clock_gettime
#undef open
#undef close
#undef ioctl

static int vendor_amd, family, unavailable, fail_energy, intel_reads;
static uint64_t energy;
static int model = 0x5e, exponent = 16, all_domains;
static double now;
static int power_exponent;

static int
mock_clock_gettime(clockid_t clock, struct timespec *ts)
{

	ATF_REQUIRE_EQ(clock, CLOCK_MONOTONIC);
	ts->tv_sec = (time_t)now;
	ts->tv_nsec = (long)((now - (double)ts->tv_sec) * 1e9);
	return (0);
}

static int
mock_open(const char *path, int flags, ...)
{

	ATF_REQUIRE_STREQ(path, "/dev/cpuctl0");
	ATF_REQUIRE_EQ(flags, O_RDONLY);
	if (unavailable) {
		errno = EACCES;
		return (-1);
	}
	return (42);
}

static int
mock_close(int fd)
{

	ATF_REQUIRE_EQ(fd, 42);
	return (0);
}

static int
mock_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	cpuctl_cpuid_args_t *cpu;
	cpuctl_msr_args_t *msr;

	ATF_REQUIRE_EQ(fd, 42);
	va_start(ap, request);
	if (request == CPUCTL_CPUID) {
		cpu = va_arg(ap, cpuctl_cpuid_args_t *);
		if (cpu->level == 0) {
			cpu->data[1] = vendor_amd ? 0x68747541 : 0x756e6547;
			cpu->data[3] = vendor_amd ? 0x69746e65 : 0x49656e69;
			cpu->data[2] = vendor_amd ? 0x444d4163 : 0x6c65746e;
		} else {
			ATF_REQUIRE_EQ(cpu->level, 1);
			cpu->data[0] = vendor_amd ?
			    ((family - 0xf) << 20) | (0xf << 8) :
			    (6 << 8) | ((model & 0xf) << 4) | ((model >> 4) << 16);
		}
		va_end(ap);
		return (0);
	}
	ATF_REQUIRE_EQ(request, CPUCTL_RDMSR);
	msr = va_arg(ap, cpuctl_msr_args_t *);
	va_end(ap);
	if (vendor_amd) {
		ATF_REQUIRE((uint32_t)msr->msr == MSR_AMD_RAPL_POWER_UNIT ||
		    (uint32_t)msr->msr == MSR_AMD_PKG_ENERGY_STATUS);
	} else
		intel_reads++;
	if ((uint32_t)msr->msr == MSR_AMD_RAPL_POWER_UNIT ||
	    (uint32_t)msr->msr == MSR_RAPL_POWER_UNIT) {
		msr->data = (exponent << 8) | power_exponent;
		return (0);
	}
	if (!fail_energy && ((uint32_t)msr->msr == MSR_AMD_PKG_ENERGY_STATUS ||
	    (uint32_t)msr->msr == MSR_PKG_ENERGY_STATUS || all_domains)) {
		msr->data = energy;
		return (0);
	}
	errno = EIO;
	return (-1);
}

ATF_TC_WITHOUT_HEAD(amd_energy);
ATF_TC_BODY(amd_energy, tc)
{
	struct rapl *r;
	struct rapl_sample samples[RAPL_NDOMAINS];
	enum rapl_domain domains[RAPL_NDOMAINS];
	double a, b, c, elapsed;
	const int families[] = { 0x17, 0x19, 0x1a };
	size_t i;

	vendor_amd = 1;
	for (i = 0; i < nitems(families); i++) {
		family = families[i];
		energy = 0xffff0000;
		r = rapl_open();
		ATF_REQUIRE(r != NULL);
		ATF_CHECK_EQ(rapl_domains(r, domains), 1);
		ATF_CHECK_EQ(domains[0], RAPL_PACKAGE);
		ATF_CHECK(rapl_energy_unit(r) == 1.0 / 65536);
		ATF_CHECK_EQ(rapl_power_info(r, &a, &b, &c), -1);
		ATF_CHECK_EQ(rapl_sample(r, samples, &elapsed), 0);
		now += 1;
		energy = 0x100000000ULL;
		ATF_CHECK_EQ(rapl_sample(r, samples, &elapsed), 1);
		ATF_CHECK(samples[0].joules == 1.0);
		ATF_CHECK(samples[0].watts > 0);
		ATF_CHECK(elapsed > 0);
		fail_energy = 1;
		ATF_CHECK_EQ(rapl_sample(r, samples, &elapsed), -1);
		fail_energy = 0;
		rapl_close(r);
	}
}

ATF_TC_WITHOUT_HEAD(unavailable_energy);
ATF_TC_BODY(unavailable_energy, tc)
{

	vendor_amd = 1;
	family = 0x16;
	ATF_CHECK(rapl_open() == NULL);
	family = 0x19;
	unavailable = 1;
	ATF_CHECK(rapl_open() == NULL);
	unavailable = 0;
	fail_energy = 1;
	ATF_CHECK(rapl_open() == NULL);
}

ATF_TC_WITHOUT_HEAD(intel_partial_domains);
ATF_TC_BODY(intel_partial_domains, tc)
{
	struct rapl *r;
	enum rapl_domain domains[RAPL_NDOMAINS];

	vendor_amd = 0;
	r = rapl_open();
	ATF_REQUIRE(r != NULL);
	ATF_CHECK_STREQ(rapl_microarch(r), "Skylake");
	ATF_CHECK_EQ(intel_reads, 6);
	ATF_CHECK_EQ(rapl_domains(r, domains), 1);
	ATF_CHECK_EQ(domains[0], RAPL_PACKAGE);
	ATF_CHECK(rapl_joules(r, RAPL_PACKAGE, 65536) == 1.0);
	rapl_close(r);
	ATF_CHECK_EQ(rapl_counter_delta(10, 5), 5);
	ATF_CHECK_EQ(rapl_counter_delta(0, 0xffffffffULL), 1);
}

ATF_TC_WITHOUT_HEAD(intel_energy_units);
ATF_TC_BODY(intel_energy_units, tc)
{
	static const struct { int model; double dram, platform; } cases[] = {
		{ 0x2d, 4, 4 }, { 0x3e, 4, 4 }, /* SNB/IVB use MSR units */
		{ 0x3f, 1, 4 }, { 0x4f, 1, 4 }, /* HSW/BDW fixed DRAM */
		{ 0x55, 1, 4 }, { 0x6a, 1, 4 }, /* SKX/ICX fixed DRAM */
		{ 0x8f, 4, 65536 }, { 0xcf, 4, 65536 }, /* SPR/EMR PSys */
		{ 0x5e, 4, 4 }
	};
	struct rapl *r;
	size_t i;

	vendor_amd = 0;
	exponent = 14; /* Must differ from fixed DRAM exponent 16. */
	all_domains = 1;
	for (i = 0; i < nitems(cases); i++) {
		model = cases[i].model;
		r = rapl_open();
		ATF_REQUIRE(r != NULL);
		ATF_CHECK_EQ(rapl_joules(r, RAPL_PACKAGE, 65536), 4);
		ATF_CHECK_EQ(rapl_joules(r, RAPL_DRAM, 65536), cases[i].dram);
		ATF_CHECK_EQ(rapl_joules(r, RAPL_PLATFORM, 65536), cases[i].platform);
		rapl_close(r);
	}
}

ATF_TC_WITHOUT_HEAD(long_energy_interval);
ATF_TC_BODY(long_energy_interval, tc)
{
	struct rapl *r;
	struct rapl_sample samples[RAPL_NDOMAINS];
	double elapsed;
	int i;

	vendor_amd = 1;
	family = 0x19;
	r = rapl_open();
	ATF_REQUIRE(r != NULL);
	ATF_REQUIRE_EQ(rapl_poll(r), 0);
	/* 1500 s at 100 W crosses the 32-bit counter boundary twice. */
	for (i = 0; i < 1500; i++) {
		now += 1;
		energy += 6553600;
		ATF_REQUIRE_EQ(rapl_poll(r), 0);
	}
	ATF_REQUIRE_EQ(rapl_sample(r, samples, &elapsed), 1);
	ATF_CHECK_EQ(elapsed, 1500);
	ATF_CHECK_EQ(samples[0].joules, 150000);
	ATF_CHECK_EQ(samples[0].watts, 100);
	now += 1;
	energy += 6553600;
	ATF_REQUIRE_EQ(rapl_sample(r, samples, &elapsed), 1);
	ATF_CHECK_EQ(elapsed, 1);
	ATF_CHECK_EQ(samples[0].joules, 100); /* output resets totals only */
	rapl_close(r);
}

ATF_TC_WITHOUT_HEAD(energy_failure_is_sticky);
ATF_TC_BODY(energy_failure_is_sticky, tc)
{
	struct rapl *r;
	struct rapl_sample samples[RAPL_NDOMAINS];
	double elapsed;

	vendor_amd = 1;
	family = 0x19;
	r = rapl_open();
	ATF_REQUIRE(r != NULL);
	ATF_REQUIRE_EQ(rapl_poll(r), 0);
	now += 1;
	energy += 6553600;
	ATF_REQUIRE_EQ(rapl_poll(r), 0);
	fail_energy = 1;
	ATF_CHECK_EQ(rapl_poll(r), -1);
	fail_energy = 0;
	ATF_CHECK_EQ(rapl_sample(r, samples, &elapsed), -1);
	rapl_close(r);
}

ATF_TC_WITHOUT_HEAD(delayed_energy_poll);
ATF_TC_BODY(delayed_energy_poll, tc)
{
	struct rapl *r;
	struct rapl_sample samples[RAPL_NDOMAINS];
	double elapsed;

	vendor_amd = 1;
	family = 0x19;
	exponent = 20;
	r = rapl_open();
	ATF_REQUIRE(r != NULL);
	ATF_CHECK(rapl_poll_interval(r) < 1);
	ATF_REQUIRE_EQ(rapl_poll(r), 0);
	now += 3 * rapl_poll_interval(r);
	ATF_CHECK_EQ(rapl_sample(r, samples, &elapsed), -1);
	ATF_CHECK_EQ(errno, EOVERFLOW);
	rapl_close(r);
}

ATF_TC_WITHOUT_HEAD(wrap_deadline_not_poll_period);
ATF_TC_BODY(wrap_deadline_not_poll_period, tc)
{
	const double delays[] = { 3, 6.55, 6.56 };
	struct rapl_sample samples[RAPL_NDOMAINS];
	struct rapl *r;
	double elapsed;
	size_t i;

	vendor_amd = 1;
	family = 0x19;
	exponent = 16; /* 65536 J range; 6.5536 seconds at the 10 kW bound. */
	for (i = 0; i < nitems(delays); i++) {
		now = 0;
		energy = 0;
		r = rapl_open();
		ATF_REQUIRE(r != NULL);
		ATF_REQUIRE_EQ(rapl_poll(r), 0);
		now = delays[i];
		energy = (uint64_t)(100 * now * 65536);
		if (i < 2) {
			ATF_REQUIRE_EQ(rapl_sample(r, samples, &elapsed), 1);
			ATF_CHECK(samples[0].watts > 99.99 && samples[0].watts < 100.01);
		} else {
			ATF_CHECK_EQ(rapl_sample(r, samples, &elapsed), -1);
			ATF_CHECK_EQ(errno, EOVERFLOW);
		}
		rapl_close(r);
	}
}

ATF_TC_WITHOUT_HEAD(shortest_domain_wrap_deadline);
ATF_TC_BODY(shortest_domain_wrap_deadline, tc)
{
	struct rapl *r;

	vendor_amd = 0;
	model = 0x3f;
	exponent = 14;
	all_domains = 1;
	r = rapl_open();
	ATF_REQUIRE(r != NULL);
	ATF_REQUIRE_EQ(rapl_poll(r), 0);
	/* Package bound is 26.2144 s, but fixed-unit DRAM is only 6.5536 s. */
	now += 10;
	ATF_CHECK_EQ(rapl_poll(r), -1);
	ATF_CHECK_EQ(errno, EOVERFLOW);
	rapl_close(r);
}


/* Intel SDM Vol. 4, Tables 2-8/2-10: ESU is 2^n microjoules. */
ATF_TC_WITHOUT_HEAD(atom_units);
ATF_TC_BODY(atom_units, tc)
{
	const int models[] = { 0x37, 0x4a, 0x4d, 0x5a, 0x5d };
	const int exponents[] = { 0, 5, 16, 31 };
	struct rapl *r;
	double tdp, low, high, expected;
	size_t i, j;
	int reads;

	vendor_amd = 0;
	for (i = 0; i < nitems(models); i++) {
		model = models[i];
		for (j = 0; j < nitems(exponents); j++) {
			exponent = exponents[j];
			power_exponent = j == 0 ? 0 : j == 1 ? 5 : 15;
			r = rapl_open();
			ATF_REQUIRE(r != NULL);
			expected = (double)(1ULL << exponent);
			ATF_CHECK_MSG(fabs(rapl_joules(r, RAPL_PACKAGE, 1000000) -
			    expected) < expected * 1e-12, "model %#x ESU %d", model, exponent);
			ATF_CHECK(fabs(r->power_unit -
			    (double)(1U << power_exponent) / 1000) < 1e-12);
			/* Atom's package-info register/layout is not the Core ABI. */
			reads = intel_reads;
			ATF_CHECK_EQ(rapl_power_info(r, &tdp, &low, &high), -1);
			ATF_CHECK_EQ(intel_reads, reads);
			rapl_close(r);
		}
	}
}

ATF_TC_WITHOUT_HEAD(atom_sample_rollover);
ATF_TC_BODY(atom_sample_rollover, tc)
{
	struct rapl_sample sample[RAPL_NDOMAINS];
	struct rapl *r;
	double elapsed;

	model = 0x37;
	exponent = power_exponent = 5;
	energy = 0xfffffff0;
	r = rapl_open();
	ATF_REQUIRE(r != NULL);
	ATF_REQUIRE_EQ(rapl_poll(r), 0);
	now = 1;
	energy += 1000000; /* Cross the 32-bit boundary at 32 microjoules/tick. */
	ATF_REQUIRE_EQ(rapl_sample(r, sample, &elapsed), 1);
	ATF_CHECK_EQ(elapsed, 1);
	ATF_CHECK(fabs(sample[0].joules - 32) < 1e-9);
	ATF_CHECK(fabs(sample[0].watts - 32) < 1e-9);
	rapl_close(r);
}

ATF_TC_WITHOUT_HEAD(atom_wrap_deadline);
ATF_TC_BODY(atom_wrap_deadline, tc)
{
	const double delays[] = { 13.74, 13.75 };
	struct rapl *r;
	size_t i;

	model = 0x37;
	exponent = 5; /* 137438.953472 J range, 13.7438953472 s at 10 kW. */
	for (i = 0; i < nitems(delays); i++) {
		now = 0;
		r = rapl_open();
		ATF_REQUIRE(r != NULL);
		ATF_CHECK_EQ(rapl_poll_interval(r), 1);
		ATF_REQUIRE_EQ(rapl_poll(r), 0);
		now = delays[i];
		ATF_CHECK_EQ(rapl_poll(r), i == 0 ? 0 : -1);
		if (i != 0)
			ATF_CHECK_EQ(errno, EOVERFLOW);
		rapl_close(r);
	}
	now = 0;
	exponent = 0; /* Finer Atom units also require sub-second polling. */
	r = rapl_open();
	ATF_REQUIRE(r != NULL);
	ATF_CHECK(fabs(rapl_poll_interval(r) - 0.2147483648) < 1e-12);
	ATF_REQUIRE_EQ(rapl_poll(r), 0);
	now = 0.43;
	ATF_CHECK_EQ(rapl_poll(r), -1);
	ATF_CHECK_EQ(errno, EOVERFLOW);
	rapl_close(r);
}

ATF_TC_WITHOUT_HEAD(non_atom_units_unchanged);
ATF_TC_BODY(non_atom_units_unchanged, tc)
{
	const int models[] = { 0x5e, 0x7a }; /* Core and Goldmont Plus. */
	struct rapl *r;
	size_t i;

	exponent = power_exponent = 5;
	for (i = 0; i < nitems(models); i++) {
		model = models[i];
		r = rapl_open();
		ATF_REQUIRE(r != NULL);
		ATF_CHECK_EQ(rapl_joules(r, RAPL_PACKAGE, 32), 1);
		ATF_CHECK_EQ(r->power_unit, 1.0 / 32);
		rapl_close(r);
	}
	vendor_amd = 1;
	family = 0x19;
	r = rapl_open();
	ATF_REQUIRE(r != NULL);
	ATF_CHECK_EQ(rapl_joules(r, RAPL_PACKAGE, 32), 1);
	rapl_close(r);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, atom_units);
	ATF_TP_ADD_TC(tp, atom_sample_rollover);
	ATF_TP_ADD_TC(tp, atom_wrap_deadline);
	ATF_TP_ADD_TC(tp, non_atom_units_unchanged);
	ATF_TP_ADD_TC(tp, wrap_deadline_not_poll_period);
	ATF_TP_ADD_TC(tp, shortest_domain_wrap_deadline);
	ATF_TP_ADD_TC(tp, intel_energy_units);
	ATF_TP_ADD_TC(tp, long_energy_interval);
	ATF_TP_ADD_TC(tp, energy_failure_is_sticky);
	ATF_TP_ADD_TC(tp, delayed_energy_poll);
	ATF_TP_ADD_TC(tp, amd_energy);
	ATF_TP_ADD_TC(tp, unavailable_energy);
	ATF_TP_ADD_TC(tp, intel_partial_domains);
	return (atf_no_error());
}
