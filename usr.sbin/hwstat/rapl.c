/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Intel RAPL and AMD Zen package energy counters via cpuctl(4)
 * MSR and CPUID access.
 * See Intel SDM Vol. 3B ch. 15.10.  This whole backend is x86-only;
 * on other architectures rapl_open() returns NULL and the tool
 * degrades to the sysctl-based sensors.
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hwstat.h"

const char *
rapl_domain_name(enum rapl_domain d)
{

	switch (d) {
	case RAPL_PACKAGE:	return ("package");
	case RAPL_PP0:		return ("pp0");
	case RAPL_PP1:		return ("pp1");
	case RAPL_DRAM:		return ("dram");
	case RAPL_PLATFORM:	return ("platform");
	default:		return ("unknown");
	}
}

const char *
rapl_domain_label(enum rapl_domain d)
{

	switch (d) {
	case RAPL_PACKAGE:	return ("Package (CPU socket)");
	case RAPL_PP0:		return ("PP0 (cores)");
	case RAPL_PP1:		return ("PP1 (GPU / uncore)");
	case RAPL_DRAM:		return ("DRAM");
	case RAPL_PLATFORM:	return ("Platform / PSys");
	default:		return ("unknown");
	}
}

uint64_t
rapl_counter_delta(uint64_t cur, uint64_t prev)
{

	/* 32-bit counter with rollover. */
	return (cur >= prev ? cur - prev : (0x100000000ULL - prev) + cur);
}

#if defined(__amd64__) || defined(__i386__)

#include <sys/ioctl.h>
#include <sys/cpuctl.h>

#include <fcntl.h>
#include <unistd.h>

/* RAPL MSR addresses. */
#define	MSR_AMD_RAPL_POWER_UNIT	0xc0010299U
#define	MSR_AMD_PKG_ENERGY_STATUS 0xc001029bU
#define	MSR_RAPL_POWER_UNIT	0x606
#define	MSR_PKG_POWER_INFO	0x614
#define	MSR_PKG_ENERGY_STATUS	0x611
#define	MSR_PP0_ENERGY_STATUS	0x639
#define	MSR_PP1_ENERGY_STATUS	0x641
#define	MSR_DRAM_ENERGY_STATUS	0x619
#define	MSR_PLATFORM_ENERGY_STATUS 0x64d

struct rapl {
	char		 microarch[32];
	enum rapl_domain domains[RAPL_NDOMAINS];
	int		 ndomains;
	int		 amd;
	int		 atom_units;
	double		 energy_unit;
	double		 dram_energy_unit;
	double		 platform_energy_unit;
	double		 poll_interval, max_poll_gap;
	double		 power_unit;
	double		 time_unit;
	uint64_t	 prev[RAPL_NDOMAINS];
	struct timespec	 prev_ts, sample_ts;
	uint64_t	 accum[RAPL_NDOMAINS];
	int		 failed;
	int		 primed;
};

static uint32_t
domain_msr(const struct rapl *r, enum rapl_domain d)
{

	if (r->amd)
		return (MSR_AMD_PKG_ENERGY_STATUS);
	switch (d) {
	case RAPL_PACKAGE:	return (MSR_PKG_ENERGY_STATUS);
	case RAPL_PP0:		return (MSR_PP0_ENERGY_STATUS);
	case RAPL_PP1:		return (MSR_PP1_ENERGY_STATUS);
	case RAPL_DRAM:		return (MSR_DRAM_ENERGY_STATUS);
	case RAPL_PLATFORM:	return (MSR_PLATFORM_ENERGY_STATUS);
	default:		return (-1);
	}
}

static int
cpuctl_open(int cpu)
{
	char path[32];

	snprintf(path, sizeof(path), "/dev/cpuctl%d", cpu);
	return (open(path, O_RDONLY));
}

static int
cpuctl_rdmsr(int fd, uint32_t msr, uint64_t *value)
{
	cpuctl_msr_args_t args;

	memset(&args, 0, sizeof(args));
	args.msr = msr;
	if (ioctl(fd, CPUCTL_RDMSR, &args) != 0)
		return (-1);
	*value = args.data;
	return (0);
}

static int
cpuctl_cpuid(int fd, int leaf, uint32_t regs[4])
{
	cpuctl_cpuid_args_t args;

	memset(&args, 0, sizeof(args));
	args.level = leaf;
	if (ioctl(fd, CPUCTL_CPUID, &args) != 0)
		return (-1);
	regs[0] = args.data[0];
	regs[1] = args.data[1];
	regs[2] = args.data[2];
	regs[3] = args.data[3];
	return (0);
}

enum rapl_unit_quirk {
	RAPL_UNIT_DEFAULT,
	RAPL_UNIT_FIXED_DRAM,
	RAPL_UNIT_SPR,
	RAPL_UNIT_ATOM
};

struct microarch_map {
	uint32_t	 model;		/* CPUID display model */
	const char	*name;
	const enum rapl_domain *domains;
	int		 ndomains;
	enum rapl_unit_quirk unit_quirk;
};

static const enum rapl_domain dom_client_old[] =	/* SNB/IVB */
    { RAPL_PACKAGE, RAPL_PP0, RAPL_PP1 };
static const enum rapl_domain dom_server[] =		/* EP parts */
    { RAPL_PACKAGE, RAPL_PP0, RAPL_DRAM };
static const enum rapl_domain dom_client_hsw[] =	/* HSW/BDW */
    { RAPL_PACKAGE, RAPL_PP0, RAPL_PP1, RAPL_DRAM };
static const enum rapl_domain dom_client_skl[] =	/* SKL+ client */
    { RAPL_PACKAGE, RAPL_PP0, RAPL_PP1, RAPL_DRAM, RAPL_PLATFORM };
static const enum rapl_domain dom_server_skx[] =	/* SKX+ server */
    { RAPL_PACKAGE, RAPL_PP0, RAPL_DRAM, RAPL_PLATFORM };
static const enum rapl_domain dom_atom[] =
    { RAPL_PACKAGE };

#define	MA(model, name, doms, units)					\
	{ (model), (name), (doms), (int)nitems(doms), (units) }

static const struct microarch_map microarchs[] = {
	MA(0x2a, "Sandy Bridge", dom_client_old, RAPL_UNIT_DEFAULT),
	MA(0x2d, "Sandy Bridge-EP", dom_server, RAPL_UNIT_DEFAULT),
	MA(0x3a, "Ivy Bridge", dom_client_old, RAPL_UNIT_DEFAULT),
	MA(0x3e, "Ivy Bridge-EP", dom_server, RAPL_UNIT_DEFAULT),
	MA(0x3c, "Haswell", dom_client_hsw, RAPL_UNIT_DEFAULT),
	MA(0x45, "Haswell", dom_client_hsw, RAPL_UNIT_DEFAULT),
	MA(0x46, "Haswell", dom_client_hsw, RAPL_UNIT_DEFAULT),
	MA(0x3f, "Haswell-EP", dom_server, RAPL_UNIT_FIXED_DRAM),
	MA(0x3d, "Broadwell", dom_client_hsw, RAPL_UNIT_DEFAULT),
	MA(0x47, "Broadwell", dom_client_hsw, RAPL_UNIT_DEFAULT),
	MA(0x4f, "Broadwell-EP", dom_server, RAPL_UNIT_FIXED_DRAM),
	MA(0x56, "Broadwell-EP", dom_server, RAPL_UNIT_FIXED_DRAM),
	MA(0x4e, "Skylake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x5e, "Skylake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x66, "Skylake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x55, "Skylake-X", dom_server_skx, RAPL_UNIT_FIXED_DRAM),
	MA(0x8e, "Kaby Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x9e, "Kaby Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0xa5, "Comet Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0xa6, "Comet Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x7e, "Ice Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x7d, "Ice Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x6a, "Ice Lake-X", dom_server_skx, RAPL_UNIT_FIXED_DRAM),
	MA(0x6c, "Ice Lake-X", dom_server_skx, RAPL_UNIT_FIXED_DRAM),
	MA(0x8c, "Tiger Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x8d, "Tiger Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x97, "Alder Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x9a, "Alder Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0xb7, "Raptor Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0xba, "Raptor Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0xbf, "Raptor Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0xaa, "Meteor Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0xac, "Meteor Lake", dom_client_skl, RAPL_UNIT_DEFAULT),
	MA(0x8f, "Sapphire Rapids", dom_server_skx, RAPL_UNIT_SPR),
	MA(0xcf, "Emerald Rapids", dom_server_skx, RAPL_UNIT_SPR),
	MA(0x1c, "Atom", dom_atom, RAPL_UNIT_DEFAULT),
	MA(0x26, "Atom", dom_atom, RAPL_UNIT_DEFAULT),
	MA(0x27, "Atom", dom_atom, RAPL_UNIT_DEFAULT),
	MA(0x35, "Atom", dom_atom, RAPL_UNIT_DEFAULT),
	MA(0x36, "Atom", dom_atom, RAPL_UNIT_DEFAULT),
	MA(0x37, "Atom", dom_atom, RAPL_UNIT_ATOM),
	MA(0x4a, "Atom", dom_atom, RAPL_UNIT_ATOM),
	MA(0x4d, "Atom", dom_atom, RAPL_UNIT_ATOM),
	MA(0x5a, "Atom", dom_atom, RAPL_UNIT_ATOM),
	MA(0x5d, "Atom", dom_atom, RAPL_UNIT_ATOM),
	MA(0x7a, "Atom", dom_atom, RAPL_UNIT_DEFAULT),
};

static const struct microarch_map amd_zen =
    MA(0, "AMD Zen (family 17h)", dom_atom, RAPL_UNIT_DEFAULT);
static const struct microarch_map amd_zen3 =
    MA(0, "AMD Zen (family 19h)", dom_atom, RAPL_UNIT_DEFAULT);
static const struct microarch_map amd_zen5 =
    MA(0, "AMD Zen (family 1ah)", dom_atom, RAPL_UNIT_DEFAULT);

static const struct microarch_map *
detect_microarch(int fd, int *amd)
{
	uint32_t regs[4], family, model, extmodel, display;
	size_t i;

	if (cpuctl_cpuid(fd, 0, regs) != 0)
		return (NULL);
	/* "AuthenticAMD" in ebx/edx/ecx.  Probe energy MSRs below. */
	*amd = regs[1] == 0x68747541 && regs[3] == 0x69746e65 &&
	    regs[2] == 0x444d4163;
	if (*amd) {
		if (cpuctl_cpuid(fd, 1, regs) != 0)
			return (NULL);
		family = (regs[0] >> 8) & 0xf;
		if (family == 0xf)
			family += (regs[0] >> 20) & 0xff;
		switch (family) {
		case 0x17: return (&amd_zen);
		case 0x19: return (&amd_zen3);
		case 0x1a: return (&amd_zen5);
		default: return (NULL);
		}
	}
	/* "GenuineIntel" in ebx/edx/ecx. */
	if (regs[1] != 0x756e6547 || regs[3] != 0x49656e69 ||
	    regs[2] != 0x6c65746e)
		return (NULL);
	if (cpuctl_cpuid(fd, 1, regs) != 0)
		return (NULL);
	family = (regs[0] >> 8) & 0xf;
	model = (regs[0] >> 4) & 0xf;
	extmodel = (regs[0] >> 16) & 0xf;
	if (family != 6)
		return (NULL);
	display = (extmodel << 4) | model;
	for (i = 0; i < nitems(microarchs); i++)
		if (microarchs[i].model == display)
			return (&microarchs[i]);
	return (NULL);
}

struct rapl *
rapl_open(void)
{
	const struct microarch_map *ma;
	struct rapl *r;
	uint64_t unitreg, value;
	double powerexp, energyexp, timeexp;
	int amd, fd, i;

	fd = cpuctl_open(0);
	if (fd < 0)
		return (NULL);
	ma = detect_microarch(fd, &amd);
	if (ma == NULL || cpuctl_rdmsr(fd, amd ?
	    MSR_AMD_RAPL_POWER_UNIT : MSR_RAPL_POWER_UNIT,
	    &unitreg) != 0) {
		close(fd);
		return (NULL);
	}
	r = calloc(1, sizeof(*r));
	if (r == NULL) {
		close(fd);
		return (NULL);
	}
	r->amd = amd;
	r->atom_units = ma->unit_quirk == RAPL_UNIT_ATOM;
	strlcpy(r->microarch, ma->name, sizeof(r->microarch));
	/* Model tables describe candidates; advertise only readable counters. */
	for (i = 0; i < ma->ndomains; i++) {
		if (cpuctl_rdmsr(fd, domain_msr(r, ma->domains[i]),
		    &value) == 0)
			r->domains[r->ndomains++] = ma->domains[i];
	}
	close(fd);
	if (r->ndomains == 0) {
		free(r);
		return (NULL);
	}

	/*
	 * Core/Zen units use inverse powers of two. Silvermont MSRs use
	 * 2^n microjoules and milliwatts (Intel SDM Vol. 4, Tables 2-8/2-10).
	 * power bits 3:0, energy bits 12:8, time bits 19:16.
	 */
	powerexp = (double)(unitreg & 0xf);
	energyexp = (double)((unitreg >> 8) & 0x1f);
	timeexp = (double)((unitreg >> 16) & 0xf);
	if (r->atom_units) {
		r->power_unit = (double)(1ULL << (int)powerexp) / 1000.0;
		r->energy_unit = (double)(1ULL << (int)energyexp) / 1000000.0;
	} else {
		r->power_unit = 1.0 / (double)(1ULL << (int)powerexp);
		r->energy_unit = 1.0 / (double)(1ULL << (int)energyexp);
	}
	r->time_unit = 1.0 / (double)(1ULL << (int)timeexp);
	/*
	 * HSW/BDW/SKX/ICX servers use fixed 2^-16 J DRAM units.
	 * SPR/EMR instead use the register unit for DRAM and 1 J for PSys.
	 */
	r->dram_energy_unit = ma->unit_quirk == RAPL_UNIT_FIXED_DRAM ?
	    1.0 / (double)(1ULL << 16) : r->energy_unit;
	r->platform_energy_unit = ma->unit_quirk == RAPL_UNIT_SPR ?
	    1.0 : r->energy_unit;
	/*
	 * Poll independently of output. Allow up to 10 kW per domain;
	 * schedule at half its wrap time, capped at one second. A delayed
	 * poll beyond that wrap time is rejected rather than undercounted.
	 */
	r->max_poll_gap = DBL_MAX;
	for (i = 0; i < r->ndomains; i++) {
		double wrap_time = rapl_joules(r, r->domains[i],
		    0x100000000ULL) / 10000.0;
		if (wrap_time < r->max_poll_gap)
			r->max_poll_gap = wrap_time;
	}
	/* A scheduling cap must not shorten the counter's validity window. */
	r->poll_interval = r->max_poll_gap / 2;
	if (r->poll_interval > 1.0)
		r->poll_interval = 1.0;
	return (r);
}

int
rapl_read_counters(struct rapl *r, uint64_t counters[RAPL_NDOMAINS])
{
	uint64_t value;
	int fd, i;

	fd = cpuctl_open(0);
	if (fd < 0)
		return (-1);
	for (i = 0; i < r->ndomains; i++) {
		if (cpuctl_rdmsr(fd, domain_msr(r, r->domains[i]),
		    &value) != 0) {
			close(fd);
			return (-1);
		}
		counters[r->domains[i]] = value & 0xffffffffULL;
	}
	close(fd);
	return (0);
}

int
rapl_power_info(struct rapl *r, double *tdp, double *minpower,
    double *maxpower)
{
	uint64_t value;
	int fd, error;

	/* AMD and Silvermont do not use the Core package-info register/layout. */
	if (r->amd || r->atom_units)
		return (-1);
	fd = cpuctl_open(0);
	if (fd < 0)
		return (-1);
	error = cpuctl_rdmsr(fd, MSR_PKG_POWER_INFO, &value);
	close(fd);
	if (error != 0)
		return (-1);
	*tdp = (double)(value & 0x7fff) * r->power_unit;
	*minpower = (double)((value >> 16) & 0x7fff) * r->power_unit;
	*maxpower = (double)((value >> 32) & 0x7fff) * r->power_unit;
	return (0);
}

double
rapl_poll_interval(const struct rapl *r)
{

	return (r->poll_interval);
}

int
rapl_poll(struct rapl *r)
{
	struct timespec now;
	uint64_t counters[RAPL_NDOMAINS];
	double elapsed;
	int i;

	if (r->failed) {
		errno = EIO;
		return (-1);
	}
	memset(counters, 0, sizeof(counters));
	if (rapl_read_counters(r, counters) != 0 ||
	    clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		goto fail;
	if (r->primed) {
		elapsed = (double)(now.tv_sec - r->prev_ts.tv_sec) +
		    (double)(now.tv_nsec - r->prev_ts.tv_nsec) / 1e9;
		if (elapsed < 0 || elapsed >= r->max_poll_gap) {
			errno = EOVERFLOW;
			goto fail;
		}
		for (i = 0; i < r->ndomains; i++) {
			enum rapl_domain d = r->domains[i];

			r->accum[d] += rapl_counter_delta(counters[d], r->prev[d]);
		}
	} else {
		r->sample_ts = now;
		r->primed = 1;
	}
	memcpy(r->prev, counters, sizeof(r->prev));
	r->prev_ts = now;
	return (0);
fail:
	/* Never turn a partial measurement into a valid-looking report. */
	r->failed = 1;
	return (-1);
}

int
rapl_sample(struct rapl *r, struct rapl_sample samples[RAPL_NDOMAINS],
    double *elapsed)
{
	int i, primed;

	primed = r->primed;
	if (rapl_poll(r) != 0)
		return (-1);
	if (!primed)
		return (0);
	*elapsed = (double)(r->prev_ts.tv_sec - r->sample_ts.tv_sec) +
	    (double)(r->prev_ts.tv_nsec - r->sample_ts.tv_nsec) / 1e9;
	for (i = 0; i < r->ndomains; i++) {
		enum rapl_domain d = r->domains[i];

		samples[i].domain = d;
		samples[i].joules = rapl_joules(r, d, r->accum[d]);
		samples[i].watts = *elapsed > 0 ?
		    samples[i].joules / *elapsed : 0;
	}
	memset(r->accum, 0, sizeof(r->accum));
	r->sample_ts = r->prev_ts;
	return (r->ndomains);
}

double
rapl_joules(const struct rapl *r, enum rapl_domain d, uint64_t delta)
{

	return ((double)delta * (d == RAPL_DRAM ? r->dram_energy_unit :
	    d == RAPL_PLATFORM ? r->platform_energy_unit : r->energy_unit));
}

const char *
rapl_microarch(const struct rapl *r)
{

	return (r->microarch);
}

double
rapl_energy_unit(const struct rapl *r)
{

	return (r->energy_unit);
}

int
rapl_domains(const struct rapl *r, enum rapl_domain domains[RAPL_NDOMAINS])
{
	int i;

	for (i = 0; i < r->ndomains; i++)
		domains[i] = r->domains[i];
	return (r->ndomains);
}

void
rapl_close(struct rapl *r)
{

	free(r);
}

#else /* !__amd64__ && !__i386__ */

double
rapl_poll_interval(const struct rapl *r __unused)
{

	return (1.0);
}

int
rapl_poll(struct rapl *r __unused)
{

	return (-1);
}


/*
 * Non-x86: no RAPL.  The rest of hwstat (sysctl sensors) works
 * unchanged; see ARM notes in the manual page.
 */

struct rapl;

struct rapl *
rapl_open(void)
{

	return (NULL);
}

void
rapl_close(struct rapl *r __unused)
{
}

const char *
rapl_microarch(const struct rapl *r __unused)
{

	return ("");
}

double
rapl_energy_unit(const struct rapl *r __unused)
{

	return (0.0);
}

int
rapl_domains(const struct rapl *r __unused,
    enum rapl_domain domains[RAPL_NDOMAINS] __unused)
{

	return (0);
}

int
rapl_read_counters(struct rapl *r __unused,
    uint64_t counters[RAPL_NDOMAINS] __unused)
{

	return (-1);
}

double
rapl_joules(const struct rapl *r __unused, enum rapl_domain d __unused,
    uint64_t delta __unused)
{

	return (0.0);
}

int
rapl_sample(struct rapl *r __unused,
    struct rapl_sample samples[RAPL_NDOMAINS] __unused,
    double *elapsed __unused)
{

	return (-1);
}

int
rapl_power_info(struct rapl *r __unused, double *tdp __unused,
    double *minpower __unused, double *maxpower __unused)
{

	return (-1);
}

#endif /* __amd64__ || __i386__ */
