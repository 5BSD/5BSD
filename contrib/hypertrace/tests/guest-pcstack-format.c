/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* STACK_MACROS */
#define DTRACEOPT_STACKINDENT 0
#define DTRACEOPT_UNSET -2
#define EDT_BADSTACKPC 7
typedef unsigned long long u_longlong_t;
typedef char *caddr_t;
typedef struct { uint64_t st_value; } GElf_Sym;
typedef struct { const char *dts_object, *dts_name; } dtrace_syminfo_t;
typedef struct { int64_t dt_options[1]; } dtrace_hdl_t;
static int _dtrace_stkindent = 2;
static int lookups;
static int
dt_printf(dtrace_hdl_t *dtp, FILE *fp, const char *format, ...)
{
	va_list args;
	int result;
	(void)dtp;
	va_start(args, format);
	result = vfprintf(fp, format, args);
	va_end(args);
	return result;
}
static int
dt_set_errno(dtrace_hdl_t *dtp, int error)
{
	(void)dtp;
	assert(error == EDT_BADSTACKPC);
	return -1;
}
static int
dtrace_lookup_by_addr(dtrace_hdl_t *dtp, uint64_t pc,
    GElf_Sym *sym, dtrace_syminfo_t *info)
{
	(void)dtp;
	lookups++;
	info->dts_object = "host";
	info->dts_name = "function";
	if (sym != NULL)
		sym->st_value = pc;
	return 0;
}
/* PRODUCTION_FORMATTER */
int
main(void)
{
	dtrace_hdl_t dtp = {{DTRACEOPT_UNSET}};
	uint64_t pcs[2] = {0x1234, 0};
	char output[512];
	FILE *fp = tmpfile();
	assert(fp != NULL);
	assert(dt_print_stack(&dtp, fp, NULL, (caddr_t)pcs,
	    HYPERTRACE_STACK_ENCODE(7, 2), sizeof(uint64_t)) == 0);
	assert(lookups == 0);
	assert(fseek(fp, 0, SEEK_SET) == 0);
	size_t n = fread(output, 1, sizeof(output) - 1, fp);
	output[n] = 0;
	assert(strstr(output, "guest[7]`0x1234") != NULL);
	assert(strstr(output, "host") == NULL);
	fclose(fp);
	fp = tmpfile();
	assert(fp != NULL);
	assert(dt_print_stack(&dtp, fp, NULL, (caddr_t)pcs, 2,
	    sizeof(uint64_t)) == 0);
	assert(lookups == 1);
	assert(fseek(fp, 0, SEEK_SET) == 0);
	n = fread(output, 1, sizeof(output) - 1, fp);
	output[n] = 0;
	assert(strstr(output, "host`function") != NULL);
	fclose(fp);
	puts("PASS: guest kernel PCs retain VMID and bypass host symbols");
	return 0;
}
