/* SPDX-License-Identifier: BSD-2-Clause */
#include <string.h>
#include <dt_program.h>
#include <dt_printf.h>

int
hypertrace_test_format(dtrace_prog_t *program)
{
	dt_stmt_t *stmt = dt_list_next(&program->dp_stmts);
	dt_pfargv_t *format = stmt != NULL ?
	    stmt->ds_desc->dtsd_fmtdata : NULL;
	dt_pfargd_t *arg = format != NULL ? format->pfv_argv : NULL;

	return (arg != NULL && arg->pfd_conv != NULL &&
	    strcmp(arg->pfd_conv->pfc_name, "d") == 0 &&
	    arg->pfd_next != NULL && arg->pfd_next->pfd_conv == NULL);
}

void *
hypertrace_test_fmtdata(dtrace_prog_t *program)
{
	dt_stmt_t *stmt = dt_list_next(&program->dp_stmts);

	return (stmt != NULL ? stmt->ds_desc->dtsd_fmtdata : NULL);
}

uint32_t
hypertrace_test_rflags(dtrace_prog_t *program)
{
	return (program->dp_rflags);
}
