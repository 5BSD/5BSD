/* Compiled with the current dtrace_program_exec() body by enable-boundary.py. */
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DTRACE_MIN_NPROBES 2
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
static int dof_destroyed;
static int alloc_calls;
static int fail_alloc_at;

static void *
test_malloc(size_t size)
{
	alloc_calls++;
	if (alloc_calls == fail_alloc_at)
		return (NULL);
	return (malloc(size));
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
	(void)dtp;
	assert(cmd == DTRACEIOC_ENABLE);
	assert(args->ps_bufsize == 2 * (int)sizeof(dtrace_probedesc_t));
	if (ioctl_error != 0) {
		errno = ioctl_error;
		return (-1);
	}
	args->n_matched = 1;
	args->n_desc = report_desc;
	args->ps[0].id = 42;
	return (0);
}

#define malloc test_malloc
#include "enable-boundary-impl.inc"
#undef malloc

int
main(void)
{
	dtrace_hdl_t dtp = { 0 };
	dtrace_prog_t pgp = { 0 };
	dtrace_proginfo_t pip = { 0 };

	report_desc = 3;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_DIFSIZE && pgp.dp_eprobes == NULL);
	assert(pip.dpi_matches == 0 && dof_destroyed == 1);

	report_desc = -1;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_DIFSIZE && dof_destroyed == 2);

	report_desc = 1;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == 0);
	assert(pgp.dp_neprobes == 1 && pgp.dp_eprobes[0].id == 42);
	assert(pip.dpi_matches == 1 && dof_destroyed == 3);

	ioctl_error = E2BIG;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_DIFSIZE && pgp.dp_neprobes == 1);
	assert(pgp.dp_eprobes[0].id == 42 && dof_destroyed == 4);
	ioctl_error = 0;

	alloc_calls = 0;
	fail_alloc_at = 1;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_NOMEM && dof_destroyed == 5);
	assert(pgp.dp_neprobes == 1 && pgp.dp_eprobes[0].id == 42);

	alloc_calls = 0;
	fail_alloc_at = 2;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == -1);
	assert(dtp.dt_errno == EDT_NOMEM && dof_destroyed == 6);
	assert(pgp.dp_neprobes == 1 && pgp.dp_eprobes[0].id == 42);
	fail_alloc_at = 0;

	report_desc = 0;
	assert(dtrace_program_exec(&dtp, &pgp, &pip) == 0);
	assert(pgp.dp_neprobes == 0 && pgp.dp_eprobes == NULL);
	assert(pip.dpi_matches == 2 && dof_destroyed == 7);
	return (0);
}
