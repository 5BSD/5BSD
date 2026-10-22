#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production USTACK formatters without a live DTrace device."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/lib/libdtrace/common/dt_consume.c').read_text()
start = source.index('int\ndt_format_ustack(')
end = source.index('\nint\ndt_print_stack(', start)
format_fn = source[start:end]
start = source.index('int\ndt_print_ustack(')
end = source.index('\nstatic int\ndt_format_usym(', start)
print_fn = source[start:end]
fixture = r'''
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/hypertrace.h>
typedef char *caddr_t;
typedef unsigned long long u_longlong_t;
typedef struct { uint64_t st_value; } GElf_Sym;
typedef struct { int pr_mflags; } prmap_t;
struct ps_prochandle { int unused; };
typedef struct { void *dt_vector; uint64_t dt_options[1]; } dtrace_hdl_t;
enum { DTRACEOPT_STACKINDENT = 0, MA_WRITE = 1 };
#define DTRACEOPT_UNSET UINT64_MAX
#define DTRACE_USTACK_NFRAMES(arg) ((uint32_t)(arg))
#define DTRACE_USTACK_STRSIZE(arg) (0U)
#define PGRAB_RDONLY 0
#define PGRAB_FORCE 0
static int _dtrace_stkindent = 2;
static int grabs, guest_labels;
static char printed[2048];
static size_t printed_len;
static struct ps_prochandle *dt_proc_grab(dtrace_hdl_t *dtp, pid_t pid,
    int flags, int monitor)
{
    (void)dtp; (void)flags; (void)monitor;
    assert(pid == 77);
    grabs++;
    return NULL;
}
static void dt_proc_lock(dtrace_hdl_t *dtp, struct ps_prochandle *p)
{ (void)dtp; (void)p; }
static void dt_proc_unlock(dtrace_hdl_t *dtp, struct ps_prochandle *p)
{ (void)dtp; (void)p; }
static void dt_proc_release(dtrace_hdl_t *dtp, struct ps_prochandle *p)
{ (void)dtp; (void)p; }
static int Plookup_by_addr(struct ps_prochandle *p, uint64_t pc,
    char *name, size_t len, GElf_Sym *sym)
{ (void)p; (void)pc; (void)name; (void)len; (void)sym; return -1; }
static int Pobjname(struct ps_prochandle *p, uint64_t pc,
    char *name, size_t len)
{ (void)p; (void)pc; (void)name; (void)len; return -1; }
static const prmap_t *Paddr_to_map(struct ps_prochandle *p, uint64_t pc)
{ (void)p; (void)pc; return NULL; }
static const char *dt_basename(const char *name) { return name; }
static int dt_printf(dtrace_hdl_t *dtp, FILE *fp, const char *fmt, ...)
{
    va_list args;
    int n;
    (void)dtp; (void)fp;
    va_start(args, fmt);
    n = vsnprintf(printed + printed_len, sizeof(printed) - printed_len,
        fmt, args);
    va_end(args);
    assert(n >= 0 && (size_t)n < sizeof(printed) - printed_len);
    printed_len += (size_t)n;
    return n;
}
static void xo_emit(const char *fmt, ...)
{
    if (strstr(fmt, "guest-vmid") != NULL)
        guest_labels++;
}
static void xo_open_list(const char *name) { (void)name; }
static void xo_close_list(const char *name) { (void)name; }
static void xo_open_instance(const char *name) { (void)name; }
static void xo_close_instance(const char *name) { (void)name; }
FORMAT_FN
PRINT_FN
int main(void)
{
    dtrace_hdl_t dtp = { .dt_options = { DTRACEOPT_UNSET } };
    uint64_t guest[3] = { HYPERTRACE_USTACK_ENCODE(7, 77), 0x1234, 0 };
    uint64_t host[3] = { 77, 0x1234, 0 };
    assert(dt_format_ustack(&dtp, (caddr_t)guest, 2) == 0);
    assert(guest_labels == 1 && grabs == 0);
    assert(dt_print_ustack(&dtp, stdout, NULL, (caddr_t)guest, 2) >= 0);
    assert(grabs == 0 && strstr(printed, "guest vmid=7 pid=77") != NULL &&
        strstr(printed, "0x1234") != NULL);
    printed_len = 0; printed[0] = '\0';
    assert(dt_format_ustack(&dtp, (caddr_t)host, 2) == 0);
    assert(dt_print_ustack(&dtp, stdout, NULL, (caddr_t)host, 2) >= 0);
    assert(grabs == 2 && guest_labels == 1 &&
        strstr(printed, "guest vmid") == NULL);
    puts("PASS: guest stack formatting never looks up a host PID");
    return 0;
}
'''.replace('FORMAT_FN', format_fn).replace('PRINT_FN', print_fn)
file = out / 'guest-ustack-format.c'
file.write_text(fixture)
binary = out / 'guest-ustack-format'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-Wno-sign-compare', '-Wno-unused-variable',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
    str(file), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
