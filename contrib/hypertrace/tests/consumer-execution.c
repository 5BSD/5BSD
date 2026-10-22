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
	unsigned dp_vmid;
	unsigned dp_vmepoch;
	unsigned dp_neprobes;
	unsigned char dp_ident[16];
	char dp_vmname[32];
} dtrace_prog_t;
typedef struct { unsigned dpi_matches; } dtrace_proginfo_t;

static void *g_dtp;
static _Atomic int g_intr, g_impatient;
static _Atomic int g_output_worker_done = 1;
static int g_quiet = 1, g_verbose;
static pthread_t g_worktd;
static int create_fail, exec_fail, augment_fail, worker_fail;
static unsigned creates, execs, augments, starts, workers, options;

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
	(void)start;
	(void)arg;
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
	creates = execs = augments = starts = workers = options = 0;
}

int
main(void)
{
	dtrace_prog_t pgp = {.dp_vmid = 3, .dp_vmepoch = 7};
	dtrace_prog_t resp = {.dp_vmid = 3, .dp_vmepoch = 7,
	    .dp_neprobes = 1};

	process_new_pgp(&pgp, NULL);
	assert(atomic_load(&g_intr) == 1 && creates == 0 && execs == 0);
	reset();
	resp.dp_vmepoch++;
	process_new_pgp(&pgp, &resp);
	assert(atomic_load(&g_intr) == 1 && creates == 0 && execs == 0);
	reset();
	resp.dp_vmepoch--;
	resp.dp_neprobes = 0;
	process_new_pgp(&pgp, &resp);
	assert(atomic_load(&g_intr) == 0 && creates == 0 && execs == 0);
	reset();
	resp.dp_neprobes = 1;
	create_fail = 1;
	process_new_pgp(&pgp, &resp);
	assert(atomic_load(&g_intr) == 1 && creates == 1 && execs == 0);
	reset();
	exec_fail = 1;
	process_new_pgp(&pgp, &resp);
	assert(atomic_load(&g_intr) == 1 && creates == 1 && execs == 1 &&
	    starts == 0 && workers == 0 && g_worktd == 0);
	reset();
	worker_fail = EAGAIN;
	process_new_pgp(&pgp, &resp);
	assert(atomic_load(&g_intr) == 1 && execs == 1 && starts == 1 &&
	    workers == 1 && g_worktd == 0);
	reset();
	process_new_pgp(&pgp, &resp);
	assert(atomic_load(&g_intr) == 0 && execs == 1 && starts == 1 &&
	    workers == 1 && g_worktd == 123);
	reset();
	augment_fail = 1;
	process_new_pgp(&pgp, &resp);
	assert(atomic_load(&g_intr) == 1 && augments == 1 && options == 0);
	reset();
	process_new_pgp(&pgp, &resp);
	assert(atomic_load(&g_intr) == 0 && augments == 1 && options == 1);
	puts("PASS: production consumer execution fails closed");
	return (0);
}
