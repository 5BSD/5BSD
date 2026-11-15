/*
 * Compiled with the current dt_enable_ioctl() and dtrace_program_exec() by
 * enable-boundary.py.
 */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DTRACE_D_STRIP 1
#define DTRACEIOC_ENABLE 6
#define EDT_NOMEM 1001
#define EDT_DIFINVAL 1002
#define EDT_DIFFAULT 1003
#define EDT_DIFSIZE 1004
#define EDT_ENABLING_ERR 1005

typedef struct { int id; } dtrace_probedesc_t;
typedef struct { int dt_errno; } dtrace_hdl_t;
typedef struct { int dpi_matches; } dtrace_proginfo_t;
typedef struct {
	int dp_vmid;
	uint64_t dp_vmepoch;
	int dp_neprobes;
	dtrace_probedesc_t *dp_eprobes;
} dtrace_prog_t;
typedef struct {
	void *dof;
	dtrace_probedesc_t *ps;
	int n_matched;
	int n_desc;
	int ps_bufsize;
	int vmid;
	uint64_t epoch;
} dtrace_enable_io_t;

static int report_desc;
static int ioctl_error;
static int needed_desc;		/* E2BIG until the buffer holds this many */
static int dof_destroyed;
static int malloc_calls, fail_malloc_at;
static int calloc_calls, fail_calloc_at;
static int ioctl_calls;
static int bufsizes[16];

static void *
test_malloc(size_t size)
{
	malloc_calls++;
	if (malloc_calls == fail_malloc_at)
		return (NULL);
	return (malloc(size));
}

static void *
test_calloc(size_t n, size_t size)
{
	calloc_calls++;
	if (calloc_calls == fail_calloc_at)
		return (NULL);
	return (calloc(n, size));
}

static void
dtrace_program_info(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_proginfo_t *pip)
{
	(void)dtp;
	(void)pgp;
	(void)pip;
}

static void *
dtrace_dof_create(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, int flags)
{
	(void)dtp;
	(void)pgp;
	(void)flags;
	return (&dof_destroyed);
}

static void
dtrace_dof_destroy(dtrace_hdl_t *dtp, void *dof)
{
	(void)dtp;
	assert(dof == &dof_destroyed);
	dof_destroyed++;
	errno = 0;	/* the caller must not depend on errno surviving this */
}

static int
dt_set_errno(dtrace_hdl_t *dtp, int err)
{
	dtp->dt_errno = err;
	return (-1);
}

static int
dt_ioctl(dtrace_hdl_t *dtp, int cmd, dtrace_enable_io_t *args)
{
	int ndesc = args->ps_bufsize / (int)sizeof(dtrace_probedesc_t);

	(void)dtp;
	assert(cmd == DTRACEIOC_ENABLE);
	assert(args->ps != NULL && args->ps_bufsize > 0);
	assert(args->n_matched == 0 && args->n_desc == 0);
	assert(ioctl_calls < (int)(sizeof(bufsizes) / sizeof(bufsizes[0])));
	bufsizes[ioctl_calls++] = ndesc;
	if (ioctl_error != 0) {
		errno = ioctl_error;
		return (-1);
	}
	if (ndesc < needed_desc) {
		errno = E2BIG;
		return (-1);
	}
	args->n_matched = 1;
	args->n_desc = report_desc;
	args->ps[0].id = 42;
	return (0);
}

#define malloc test_malloc
#define calloc test_calloc
#include "enable-boundary-impl.inc"
#undef calloc
#undef malloc

static void
reset_counts(void)
{
	malloc_calls = calloc_calls = ioctl_calls = 0;
	memset(bufsizes, 0, sizeof(bufsizes));
}

int
main(void)
{
	dtrace_hdl_t dtp = { 0 };
	dtrace_prog_t pgp = { 0 };
	dtrace_proginfo_t pip = { 0 };

	/* A driver that reports more descriptions than fit. */
	reset_counts();
	report_desc = DT_ENABLE_NPROBES_MIN + 1;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_DIFSIZE && pgp.dp_eprobes == NULL);
	assert(pip.dpi_matches == 0 && dof_destroyed == 1);
	assert(ioctl_calls == 1 && bufsizes[0] == DT_ENABLE_NPROBES_MIN);

	reset_counts();
	report_desc = -1;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_DIFSIZE && dof_destroyed == 2);

	reset_counts();
	report_desc = 1;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == 0);
	assert(pgp.dp_neprobes == 1 && pgp.dp_eprobes[0].id == 42);
	assert(pip.dpi_matches == 1 && dof_destroyed == 3);
	assert(ioctl_calls == 1);

	/* E2BIG grows the buffer by four until the descriptions fit. */
	reset_counts();
	needed_desc = 5 * DT_ENABLE_NPROBES_MIN;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == 0);
	assert(ioctl_calls == 3 && calloc_calls == 3);
	assert(bufsizes[0] == DT_ENABLE_NPROBES_MIN &&
	    bufsizes[1] == 4 * DT_ENABLE_NPROBES_MIN &&
	    bufsizes[2] == 16 * DT_ENABLE_NPROBES_MIN);
	assert(pip.dpi_matches == 2 && dof_destroyed == 4);

	/* More descriptions than the first buffer holds, once it has grown. */
	reset_counts();
	needed_desc = report_desc = DT_ENABLE_NPROBES_MIN + 1;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == 0);
	assert(ioctl_calls == 2 && pgp.dp_neprobes == DT_ENABLE_NPROBES_MIN + 1);
	assert(pip.dpi_matches == 3 && dof_destroyed == 5);
	needed_desc = 0;
	report_desc = 1;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == 0);
	assert(pgp.dp_neprobes == 1 && dof_destroyed == 6);

	/* E2BIG at every size stops at the cap and keeps the old probes. */
	reset_counts();
	ioctl_error = E2BIG;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_DIFSIZE && pgp.dp_neprobes == 1);
	assert(pgp.dp_eprobes[0].id == 42 && dof_destroyed == 7);
	assert(bufsizes[ioctl_calls - 1] == DT_ENABLE_NPROBES_MAX);
	assert(ioctl_calls == 6);
	ioctl_error = 0;

	/* Another error is reported as itself, with no retry. */
	reset_counts();
	ioctl_error = EFAULT;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_DIFFAULT && ioctl_calls == 1);
	assert(dof_destroyed == 8);
	ioctl_error = 0;

	/* The first buffer cannot be allocated. */
	reset_counts();
	fail_calloc_at = 1;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_NOMEM && dof_destroyed == 9);
	assert(ioctl_calls == 0);
	assert(pgp.dp_neprobes == 1 && pgp.dp_eprobes[0].id == 42);

	/* A larger buffer cannot be allocated while growing. */
	reset_counts();
	needed_desc = 5 * DT_ENABLE_NPROBES_MIN;
	fail_calloc_at = 2;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_NOMEM && dof_destroyed == 10);
	assert(ioctl_calls == 1);
	assert(pgp.dp_neprobes == 1 && pgp.dp_eprobes[0].id == 42);
	needed_desc = 0;
	fail_calloc_at = 0;

	/* The enabled-probe copy cannot be allocated. */
	reset_counts();
	fail_malloc_at = 1;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_NOMEM && dof_destroyed == 11);
	assert(pgp.dp_neprobes == 1 && pgp.dp_eprobes[0].id == 42);
	fail_malloc_at = 0;

	reset_counts();
	report_desc = 0;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == 0);
	assert(pgp.dp_neprobes == 0 && pgp.dp_eprobes == NULL);
	assert(pip.dpi_matches == 5 && dof_destroyed == 12);
	return (0);
}
