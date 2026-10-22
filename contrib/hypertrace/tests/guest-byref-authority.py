#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production by-reference load authorization across address spaces."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
def function(name):
    start = source.index('static int\n' + name + '(')
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define DTRACE_ACCESS_KERNEL 1
#define CPU_DTRACE_ILLOP 2
#define CPU_DTRACE_KPRIV 4
#define CPU_DTRACE_BADADDR 8
#define DIF_TF_BYREF 1
#define DIF_TYPE_STRING 2
#define DIF_TYPE_OTHER 3
#define DTRACEOPT_STRSIZE 0
#define ASSERT(x) assert(x)
#define DTRACE_CPUFLAG_SET(f) (cpu_core[0].cpuc_dtrace_flags |= (f))
#define DTRACE_RANGE_REMAIN(remain,addr,base,length) do { \
    if ((remain) != NULL) *(remain) = (length); \
} while (0)
#define MIN(a,b) ((a) < (b) ? (a) : (b))
typedef struct { int dtpr_vmid; } dtrace_probe_t;
typedef struct { size_t dts_options[1]; } dtrace_state_t;
typedef struct { dtrace_state_t *dtvs_state; } dtrace_vstate_t;
typedef struct {
    dtrace_probe_t *dtms_probe;
    const void *dtms_vmhdl;
    unsigned dtms_access;
} dtrace_mstate_t;
typedef struct { unsigned dtdt_flags, dtdt_kind; size_t dtdt_size; }
    dtrace_diftype_t;
static struct { unsigned cpuc_dtrace_flags; uintptr_t cpuc_dtrace_illval; }
    cpu_core[1];
static const int curcpu = 0, guest_tag = 1, stale_tag = 2;
static const size_t dtrace_strsize_default = 32;
static unsigned host_checks;
static int dtrace_canload(uint64_t addr, size_t size,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
    (void)addr; (void)size; (void)mstate; (void)vstate;
    ++host_checks;
    return 1;
}
static int dtrace_canload_remains(uint64_t addr, size_t size, size_t *remain,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
    if (remain != NULL) *remain = size;
    return dtrace_canload(addr, size, mstate, vstate);
}
static size_t dtrace_strlen(const void *tag, const char *addr, size_t limit)
{
    (void)tag; (void)addr; (void)limit;
    return 0;
}
PRODUCTION_HELPER
PRODUCTION_STRCANLOAD
PRODUCTION_VCANLOAD
int main(void)
{
    dtrace_probe_t probe = {1};
    dtrace_state_t state = {{24}};
    dtrace_vstate_t vstate = {&state};
    dtrace_mstate_t machine = {&probe, &guest_tag, 0};
    dtrace_diftype_t type = {DIF_TF_BYREF, DIF_TYPE_OTHER, 16};
    size_t remain = 0;
    uintptr_t host_scratch = (uintptr_t)0x8000;
    assert(dtrace_vcanload(NULL, (void *)host_scratch, &type,
        &remain, &machine, &vstate) == 1);
    assert(host_checks == 1 && remain == 16);
    host_checks = 0;
    remain = 0;
    assert(dtrace_vcanload(&guest_tag, (void *)host_scratch, &type,
        &remain, &machine, &vstate) == 0);
    assert(host_checks == 0 && remain == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_KPRIV);
    cpu_core[0].cpuc_dtrace_flags = 0;
    assert(dtrace_strcanload(host_scratch, 24, &guest_tag, &remain,
        &machine, &vstate) == 0);
    assert(host_checks == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_KPRIV);
    cpu_core[0].cpuc_dtrace_flags = 0;
    machine.dtms_access = DTRACE_ACCESS_KERNEL;
    assert(dtrace_strcanload(host_scratch, 24, &guest_tag, &remain,
        &machine, &vstate) == 1);
    assert(host_checks == 0 && remain == 24);
    assert(dtrace_vcanload(&guest_tag, (void *)host_scratch, &type,
        &remain, &machine, &vstate) == 1);
    assert(host_checks == 0 && remain == 16);
    type.dtdt_kind = DIF_TYPE_STRING;
    assert(dtrace_vcanload(&guest_tag, (void *)host_scratch, &type,
        &remain, &machine, &vstate) == 1);
    assert(host_checks == 0 && remain == 24);
    assert(dtrace_vcanload(&stale_tag, (void *)host_scratch, &type,
        &remain, &machine, &vstate) == 0);
    assert(host_checks == 0 &&
        (cpu_core[0].cpuc_dtrace_flags & CPU_DTRACE_ILLOP) != 0);
    cpu_core[0].cpuc_dtrace_flags = 0;
    assert(dtrace_vcanload(&guest_tag, (void *)UINTPTR_MAX, &type,
        &remain, &machine, &vstate) == 0);
    assert(host_checks == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR);
    puts("PASS: guest by-reference reads never borrow host ranges");
}
'''.replace('PRODUCTION_HELPER', function('dtrace_canload_tagged')).replace(
    'PRODUCTION_STRCANLOAD', function('dtrace_strcanload')).replace(
    'PRODUCTION_VCANLOAD', function('dtrace_vcanload'))
cfile = out / 'guest-byref-authority.c'
cfile.write_text(fixture)
binary = out / 'guest-byref-authority'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(cfile), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
