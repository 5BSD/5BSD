/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long pthread_t;
typedef struct {
	uint16_t dp_vmid;
	uint64_t dp_vmepoch;
	uint32_t dp_neprobes;
	unsigned char dp_ident[16];
	char dp_vmname[32];
} dtrace_prog_t;
typedef struct { unsigned dpi_matches; } dtrace_proginfo_t;

static void *g_dtp;
static _Atomic int g_intr, g_impatient;
static _Atomic int g_output_worker_done = 1;
static int g_quiet = 1, g_verbose;
static pthread_t g_worktd;
static struct { int print_upon_exit; } g_host_workarg;
static struct dtotel_session { int unused; } otel_session, *g_otel;
static int create_fail, exec_fail, augment_fail, worker_fail;
static int guest_fail, clock_fail;
static unsigned creates, execs, augments, starts, workers, options;
static unsigned guests, clocks, errors;

static struct dtotel *
dtotel_session_bridge(struct dtotel_session *session)
{
	assert(session == &otel_session);
	return ((struct dtotel *)session);
}

static int
dtotel_guest(struct dtotel *bridge, uint16_t vmid, uint64_t epoch,
    const char *name)
{
	assert(bridge == (struct dtotel *)&otel_session);
	assert(vmid == 3 && epoch == 7 && strcmp(name, "guest") == 0);
	guests++;
	return (guest_fail ? -1 : 0);
}

static int
otel_clock(void)
{
	/* The clock is enabled before any traced program. */
	assert(g_otel != NULL && execs == 0);
	clocks++;
	return (clock_fail ? -1 : 0);
}

static int
dtrace_vprobes_create(void *dtp, dtrace_prog_t *pgp)
{
	(void)dtp;
	(void)pgp;
	creates++;
	if (create_fail) {
		errno = EIO;
		return (-1);
	}
	return (1);
}

static int
dtrace_program_exec(void *dtp, dtrace_prog_t *pgp, dtrace_proginfo_t *dpi)
{
	(void)dtp;
	(void)pgp;
	execs++;
	if (exec_fail) {
		errno = EIO;
		return (-1);
	}
	dpi->dpi_matches = 1;
	return (0);
}

static int
dtrace_augment_tracing(void *dtp, dtrace_prog_t *pgp)
{
	(void)dtp;
	(void)pgp;
	augments++;
	if (augment_fail) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

static int
dtrace_hypertrace_options_update(void *dtp)
{
	(void)dtp;
	options++;
	return (0);
}

static void
setup_tracing(void)
{
	starts++;
}

static void *
dtc_work(void *arg)
{
	return (arg);
}

static int
fake_pthread_create(pthread_t *thread, const void *attr,
    void *(*start)(void *), void *arg)
{
	(void)attr;
	assert(start == dtc_work && arg == &g_host_workarg);
	workers++;
	if (worker_fail != 0) {
		*thread = 999; /* A failing backend may clobber its output. */
		return (worker_fail);
	}
	*thread = 123;
	return (0);
}
#define pthread_create fake_pthread_create

static void
notice(const char *fmt, ...)
{
	(void)fmt;
}

static void
error(const char *fmt, ...)
{
	(void)fmt;
	errors++;
}

static void
fatal(const char *fmt, ...)
{
	(void)fmt;
	abort();
}

static void
dtrace_dump_actions(dtrace_prog_t *pgp)
{
	(void)pgp;
}

static void
dtrace_dump_ecbs(dtrace_prog_t *pgp)
{
	(void)pgp;
}

/* FUNCTION */

static void
reset(void)
{
	atomic_store(&g_intr, 0);
	atomic_store(&g_impatient, 0);
	create_fail = exec_fail = augment_fail = worker_fail = 0;
	guest_fail = clock_fail = 0;
	creates = execs = augments = starts = workers = options = 0;
	guests = clocks = errors = 0;
	g_otel = NULL;
}

int
main(void)
{
	dtrace_prog_t pgp = {.dp_vmid = 3, .dp_vmepoch = 7,
	    .dp_vmname = "guest"};
	dtrace_prog_t resp = {.dp_vmid = 3, .dp_vmepoch = 7,
	    .dp_neprobes = 1};

	assert(process_new_pgp(&pgp, NULL) == -1);
	assert(atomic_load(&g_intr) == 1 && creates == 0 && execs == 0);
	reset();
	resp.dp_vmepoch++;
	g_otel = &otel_session;
	assert(process_new_pgp(&pgp, &resp) == -1);
	assert(atomic_load(&g_intr) == 1 && creates == 0 && execs == 0);
	/* A refused program does not touch the OpenTelemetry resource. */
	assert(guests == 0 && clocks == 0);
	reset();
	resp.dp_vmepoch--;
	resp.dp_neprobes = 0;
	assert(process_new_pgp(&pgp, &resp) == 0);
	assert(atomic_load(&g_intr) == 0 && creates == 0 && execs == 0);
	assert(guests == 0 && clocks == 0 && errors == 0);
	/* A resource that cannot be updated is reported, not fatal. */
	reset();
	g_otel = &otel_session;
	guest_fail = 1;
	assert(process_new_pgp(&pgp, &resp) == 0);
	assert(atomic_load(&g_intr) == 0 && guests == 1 && errors == 1 &&
	    creates == 0 && clocks == 0);
	reset();
	resp.dp_neprobes = 1;
	create_fail = 1;
	assert(process_new_pgp(&pgp, &resp) == -1);
	assert(atomic_load(&g_intr) == 1 && creates == 1 && execs == 0);
	/* Without its probe clock the first program is not enabled. */
	reset();
	g_otel = &otel_session;
	clock_fail = 1;
	assert(process_new_pgp(&pgp, &resp) == -1);
	assert(atomic_load(&g_intr) == 1 && guests == 1 && errors == 0 &&
	    creates == 1 && clocks == 1 && execs == 0 && starts == 0);
	reset();
	exec_fail = 1;
	assert(process_new_pgp(&pgp, &resp) == -1);
	assert(atomic_load(&g_intr) == 1 && creates == 1 && execs == 1 &&
	    starts == 0 && workers == 0 && g_worktd == 0);
	reset();
	worker_fail = EAGAIN;
	assert(process_new_pgp(&pgp, &resp) == -1);
	assert(atomic_load(&g_intr) == 1 && execs == 1 && starts == 1 &&
	    workers == 1 && g_worktd == 0);
	assert(atomic_load(&g_output_worker_done) == 1);
	reset();
	g_otel = &otel_session;
	assert(process_new_pgp(&pgp, &resp) == 0);
	assert(atomic_load(&g_intr) == 0 && execs == 1 && starts == 1 &&
	    workers == 1 && g_worktd == 123);
	assert(guests == 1 && clocks == 1 && errors == 0);
	assert(atomic_load(&g_output_worker_done) == 0);
	reset();
	augment_fail = 1;
	assert(process_new_pgp(&pgp, &resp) == -1);
	assert(atomic_load(&g_intr) == 1 && augments == 1 && options == 0);
	/* Later programs join the running clock. */
	reset();
	g_otel = &otel_session;
	assert(process_new_pgp(&pgp, &resp) == 0);
	assert(atomic_load(&g_intr) == 0 && augments == 1 && options == 1);
	assert(guests == 1 && clocks == 0 && execs == 0 && workers == 0);
	puts("PASS: production consumer execution fails closed");
	return (0);
}
