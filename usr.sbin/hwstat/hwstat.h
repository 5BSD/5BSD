/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * hwstat — hardware telemetry for the base system, with OpenTelemetry
 * output.  C port of the ObservableBSD Swift tool.
 *
 * The sysctl-based sensors (temperatures, frequencies, C-states,
 * ACPI thermal, GPU) are portable to every architecture.  RAPL
 * energy counters use Intel or AMD MSRs and are compiled only on x86;
 * rapl_open() returns NULL everywhere else and RAPL columns
 * are omitted.
 */

#ifndef _HWSTAT_H_
#define	_HWSTAT_H_

#include <sys/types.h>

#include <stdint.h>
#include <time.h>

#define	HWSTAT_VERSION	"0.1.0"

/* ---------------------------------------------------------------- */
/* Energy domains (Intel and AMD x86 at runtime)		 	*/

enum rapl_domain {
	RAPL_PACKAGE = 0,
	RAPL_PP0,
	RAPL_PP1,
	RAPL_DRAM,
	RAPL_PLATFORM,
	RAPL_NDOMAINS
};

struct rapl_sample {
	enum rapl_domain domain;
	double		 joules;
	double		 watts;
};

struct rapl;

/* NULL when energy MSRs are unavailable or cpuctl cannot be read. */
struct rapl	*rapl_open(void);
void		 rapl_close(struct rapl *);
/* Internal polls accumulate across output intervals. Errors invalidate a run. */
int		 rapl_poll(struct rapl *);
double		 rapl_poll_interval(const struct rapl *);
const char	*rapl_microarch(const struct rapl *);
double		 rapl_energy_unit(const struct rapl *);
/* The ordered list of domains this CPU exposes. */
int		 rapl_domains(const struct rapl *,
		    enum rapl_domain domains[RAPL_NDOMAINS]);
/* Raw 32-bit energy counters, indexed by enum rapl_domain. */
int		 rapl_read_counters(struct rapl *,
		    uint64_t counters[RAPL_NDOMAINS]);
/* Joules for a raw counter delta in the given domain. */
double		 rapl_joules(const struct rapl *, enum rapl_domain,
		    uint64_t delta);
/*
 * Interval sampling: first call primes and returns 0; later calls
 * fill samples[] and return the count.  -1 on read failure.
 */
int		 rapl_sample(struct rapl *,
		    struct rapl_sample samples[RAPL_NDOMAINS],
		    double *elapsed);
/* Package power info; -1 if unavailable. */
int		 rapl_power_info(struct rapl *, double *tdp,
		    double *minpower, double *maxpower);
const char	*rapl_domain_name(enum rapl_domain);
const char	*rapl_domain_label(enum rapl_domain);
/* 32-bit counter delta with rollover. */
uint64_t	 rapl_counter_delta(uint64_t cur, uint64_t prev);

/* ---------------------------------------------------------------- */
/* Portable sysctl sensors					 	*/

#define	MAX_CSTATES	8

struct cstate_level {
	char		 name[16];
	int		 type;
	int		 latency_us;
};

struct cstate_info {
	struct cstate_level levels[MAX_CSTATES];
	int		 nlevels;
	double		 pct[MAX_CSTATES];	/* accumulated entry percentages */
	int		 npct;
	char		 lowest[16];
	int		 have_lowest;
};

struct core_snap {
	int		 cpu;
	int		 have_temp;
	double		 temp;			/* degC */
	int		 have_freq;
	int		 freq;			/* MHz */
	int		 have_cstate;
	struct cstate_info cstate;
	int		 throttled;
	int		 have_thermal_status;
	uint32_t	 thermal_status;
	int		 have_ticks, have_usage;
	long		 ticks[5];
	double		 usage[5]; /* user, nice, system, interrupt, idle percent */
};

struct thermal_sensor {
	char		 name[128];	/* sysctl source, including package/zone */
	double		 celsius;
};

struct hw_metric {
	char source[128];
	char name[64]; /* includes unit, e.g. gfx_temperature_millicelsius */
	int64_t value;
};

struct hw_source {
	char name[128];
	char status[32];
};

struct sys_snapshot {
	struct timespec	 ts;
	struct hw_metric *metrics;
	size_t nmetrics;
	struct hw_source *sources;
	size_t nsources;
	char		 model[128];
	struct thermal_sensor *thermal;
	int		 nthermal;
	struct core_snap *cores;
	int		 ncores;		/* entries in cores[] */
	int		 any_throttled;
	int		 have_tjmax;
	double		 tjmax;
	int		 have_acpi;
	double		 acpi_temp;
	int		 have_gpu_freq;
	long		 gpu_freq;		/* MHz */
	int		 have_gpu_rc6;
	long		 gpu_rc6_ms;
	int		 gpu_throttled;
};

int	 sys_cpu_count(void);
/* Take a full snapshot; caller frees with sys_snapshot_free(). */
int	 sys_snapshot(struct sys_snapshot *, int cpucount);
void	 sys_snapshot_free(struct sys_snapshot *);

int	 hw_metrics_read(struct sys_snapshot *);
int	 hw_capabilities_read(struct sys_snapshot *);
/* Parse a complete AMD v2.1/v2.2 table; errno value on failure. */
int	 amd_metrics_decode(struct sys_snapshot *, const char *,
	    const void *, size_t);
void	 sys_snapshot_delta(struct sys_snapshot *, const struct sys_snapshot *);
void	 fmt_metrics_json(const struct sys_snapshot *);
void	 fmt_metrics_text(const struct sys_snapshot *);

/* Aggregates; return 0 if no core had the sensor. */
int	 snap_temp_stats(const struct sys_snapshot *, double *minv,
	    double *avgv, double *maxv);
int	 snap_freq_stats(const struct sys_snapshot *, int *minv, int *avgv,
	    int *maxv);
/* First core with C-state data, or NULL. */
const struct core_snap *snap_first_cstate(const struct sys_snapshot *);

/* C-state string parsers (exposed for reuse/tests). */
int	 cstate_parse_supported(const char *, struct cstate_info *);
void	 cstate_parse_usage(const char *, struct cstate_info *);

/* format.c */
enum hw_format {
	HW_FORMAT_TEXT,
	HW_FORMAT_JSON,
	HW_FORMAT_OTEL
};

void	 fmt_thermal_json(const struct sys_snapshot *);
void	 fmt_thermal_text(const struct sys_snapshot *);
void	 fmt_text_header(const struct rapl *);
void	 fmt_text_row(const struct rapl *, const struct rapl_sample *,
	    int nsamples, const struct sys_snapshot *);
void	 fmt_percore_text(const struct rapl *, const struct rapl_sample *,
	    int nsamples, const struct sys_snapshot *);
void	 fmt_json_line(const struct rapl *, const struct rapl_sample *,
	    int nsamples, const struct sys_snapshot *);
void	 fmt_percore_json_line(const struct rapl *,
	    const struct rapl_sample *, int nsamples,
	    const struct sys_snapshot *);

/* subcommands */
int	 cmd_hw_list(int argc, char **argv);
int	 cmd_hw_watch(int argc, char **argv);
int	 cmd_hw_exec(int argc, char **argv);

#endif /* !_HWSTAT_H_ */
