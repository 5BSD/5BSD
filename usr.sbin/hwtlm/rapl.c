/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Intel RAPL energy counters via cpuctl(4) MSR and CPUID access.
 * See Intel SDM Vol. 3B ch. 15.10.  This whole backend is x86-only;
 * on other architectures rapl_open() returns NULL and the tool
 * degrades to the sysctl-based sensors.
 */

#include <sys/param.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hwtlm.h"

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
	int		 fixed_dram_unit;
	double		 energy_unit;
	double		 dram_energy_unit;
	double		 power_unit;
	double		 time_unit;
	uint64_t	 prev[RAPL_NDOMAINS];
	struct timespec	 prev_ts;
	int		 primed;
};

static int
domain_msr(enum rapl_domain d)
{

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
cpuctl_rdmsr(int fd, int msr, uint64_t *value)
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

struct microarch_map {
	uint32_t	 model;		/* CPUID display model */
	const char	*name;
	const enum rapl_domain *domains;
	int		 ndomains;
	int		 fixed_dram_unit;
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

#define	MA(model, name, doms, fixed)					\
	{ (model), (name), (doms), (int)nitems(doms), (fixed) }

static const struct microarch_map microarchs[] = {
	MA(0x2a, "Sandy Bridge", dom_client_old, 0),
	MA(0x2d, "Sandy Bridge-EP", dom_server, 1),
	MA(0x3a, "Ivy Bridge", dom_client_old, 0),
	MA(0x3e, "Ivy Bridge-EP", dom_server, 1),
	MA(0x3c, "Haswell", dom_client_hsw, 0),
	MA(0x45, "Haswell", dom_client_hsw, 0),
	MA(0x46, "Haswell", dom_client_hsw, 0),
	MA(0x3f, "Haswell-EP", dom_server, 1),
	MA(0x3d, "Broadwell", dom_client_hsw, 0),
	MA(0x47, "Broadwell", dom_client_hsw, 0),
	MA(0x4f, "Broadwell-EP", dom_server, 1),
	MA(0x56, "Broadwell-EP", dom_server, 1),
	MA(0x4e, "Skylake", dom_client_skl, 0),
	MA(0x5e, "Skylake", dom_client_skl, 0),
	MA(0x66, "Skylake", dom_client_skl, 0),
	MA(0x55, "Skylake-X", dom_server_skx, 1),
	MA(0x8e, "Kaby Lake", dom_client_skl, 0),
	MA(0x9e, "Kaby Lake", dom_client_skl, 0),
	MA(0xa5, "Comet Lake", dom_client_skl, 0),
	MA(0xa6, "Comet Lake", dom_client_skl, 0),
	MA(0x7e, "Ice Lake", dom_client_skl, 0),
	MA(0x7d, "Ice Lake", dom_client_skl, 0),
	MA(0x6a, "Ice Lake-X", dom_server_skx, 1),
	MA(0x6c, "Ice Lake-X", dom_server_skx, 1),
	MA(0x8c, "Tiger Lake", dom_client_skl, 0),
	MA(0x8d, "Tiger Lake", dom_client_skl, 0),
	MA(0x97, "Alder Lake", dom_client_skl, 0),
	MA(0x9a, "Alder Lake", dom_client_skl, 0),
	MA(0xb7, "Raptor Lake", dom_client_skl, 0),
	MA(0xba, "Raptor Lake", dom_client_skl, 0),
	MA(0xbf, "Raptor Lake", dom_client_skl, 0),
	MA(0xaa, "Meteor Lake", dom_client_skl, 0),
	MA(0xac, "Meteor Lake", dom_client_skl, 0),
	MA(0x8f, "Sapphire Rapids", dom_server_skx, 1),
	MA(0xcf, "Emerald Rapids", dom_server_skx, 1),
	MA(0x1c, "Atom", dom_atom, 0),
	MA(0x26, "Atom", dom_atom, 0),
	MA(0x27, "Atom", dom_atom, 0),
	MA(0x35, "Atom", dom_atom, 0),
	MA(0x36, "Atom", dom_atom, 0),
	MA(0x37, "Atom", dom_atom, 0),
	MA(0x4a, "Atom", dom_atom, 0),
	MA(0x4d, "Atom", dom_atom, 0),
	MA(0x5a, "Atom", dom_atom, 0),
	MA(0x5d, "Atom", dom_atom, 0),
	MA(0x7a, "Atom", dom_atom, 0),
};

static const struct microarch_map *
detect_microarch(int fd)
{
	uint32_t regs[4], family, model, extmodel, display;
	size_t i;

	if (cpuctl_cpuid(fd, 0, regs) != 0)
		return (NULL);
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
	uint64_t unitreg;
	double powerexp, energyexp, timeexp;
	int fd, i;

	fd = cpuctl_open(0);
	if (fd < 0)
		return (NULL);
	ma = detect_microarch(fd);
	if (ma == NULL || cpuctl_rdmsr(fd, MSR_RAPL_POWER_UNIT,
	    &unitreg) != 0) {
		close(fd);
		return (NULL);
	}
	close(fd);

	r = calloc(1, sizeof(*r));
	if (r == NULL)
		return (NULL);
	strlcpy(r->microarch, ma->name, sizeof(r->microarch));
	for (i = 0; i < ma->ndomains; i++)
		r->domains[i] = ma->domains[i];
	r->ndomains = ma->ndomains;
	r->fixed_dram_unit = ma->fixed_dram_unit;

	/*
	 * MSR 0x606 encodes 0.5^n fixed-point exponents:
	 * power bits 3:0, energy bits 12:8, time bits 19:16.
	 */
	powerexp = (double)(unitreg & 0xf);
	energyexp = (double)((unitreg >> 8) & 0x1f);
	timeexp = (double)((unitreg >> 16) & 0xf);
	r->power_unit = 1.0 / (double)(1ULL << (int)powerexp);
	r->energy_unit = 1.0 / (double)(1ULL << (int)energyexp);
	r->time_unit = 1.0 / (double)(1ULL << (int)timeexp);
	/*
	 * Server parts use a fixed 2^-16 J (~15.3 uJ) DRAM energy
	 * unit regardless of the power-unit register.
	 */
	r->dram_energy_unit = ma->fixed_dram_unit ?
	    1.0 / (double)(1ULL << 16) : r->energy_unit;
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
		if (cpuctl_rdmsr(fd, domain_msr(r->domains[i]),
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

int
rapl_sample(struct rapl *r, struct rapl_sample samples[RAPL_NDOMAINS],
    double *elapsed)
{
	struct timespec now;
	uint64_t counters[RAPL_NDOMAINS], delta;
	int i, n;

	memset(counters, 0, sizeof(counters));
	if (rapl_read_counters(r, counters) != 0)
		return (-1);
	clock_gettime(CLOCK_MONOTONIC, &now);
	if (!r->primed) {
		memcpy(r->prev, counters, sizeof(r->prev));
		r->prev_ts = now;
		r->primed = 1;
		return (0);
	}
	*elapsed = (double)(now.tv_sec - r->prev_ts.tv_sec) +
	    (double)(now.tv_nsec - r->prev_ts.tv_nsec) / 1e9;
	n = 0;
	for (i = 0; i < r->ndomains; i++) {
		enum rapl_domain d = r->domains[i];

		delta = rapl_counter_delta(counters[d], r->prev[d]);
		samples[n].domain = d;
		samples[n].joules = rapl_joules(r, d, delta);
		samples[n].watts = *elapsed > 0 ?
		    samples[n].joules / *elapsed : 0;
		n++;
	}
	memcpy(r->prev, counters, sizeof(r->prev));
	r->prev_ts = now;
	return (n);
}

double
rapl_joules(const struct rapl *r, enum rapl_domain d, uint64_t delta)
{

	return ((double)delta * (d == RAPL_DRAM ? r->dram_energy_unit :
	    r->energy_unit));
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

/*
 * Non-x86: no RAPL.  The rest of hwtlm (sysctl sensors) works
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
