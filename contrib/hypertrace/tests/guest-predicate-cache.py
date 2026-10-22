#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production predicate-cache paths with reused host threads."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('\tif (probe->dtpr_vmid == 0 && !onintr &&')
end = source.index('\n#ifdef illumos', start)
lookup = source[start:end]
start = source.index('\t\t\tif (!(*flags & CPU_DTRACE_ERROR) && !rval) {')
end = source.index('{', start) + 1
depth = 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
reject = source[start:end]
fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

typedef unsigned dtrace_cacheid_t;
typedef struct { unsigned dtpr_vmid, dtpr_predcache; } dtrace_probe_t;
typedef struct { unsigned dtp_cacheid; } dtrace_predicate_t;
typedef struct { unsigned t_predcache; } dtrace_thread_t;
static dtrace_thread_t thread;
static dtrace_thread_t *curthread = &thread;
static int evaluations, matches, exits;
#define DTRACE_CACHEIDNONE UINT32_MAX
#define CPU_DTRACE_ERROR 1
#define ASSERT(expr) assert(expr)
static void dtrace_probe_exit(int cookie) { assert(cookie == 1); ++exits; }
static void run(dtrace_probe_t *probe, dtrace_predicate_t *pred,
    uint64_t rval, int onintr)
{
    int cookie = 1;
    unsigned flag_bits = 0, *flags = &flag_bits;
PRODUCTION_LOOKUP
    ++evaluations;
    for (int once = 0; once < 1; once++) {
        if (pred != NULL) {
PRODUCTION_REJECT
        }
        ++matches;
    }
}
int main(void)
{
    dtrace_probe_t guest = {1, 42}, host = {0, 42};
    dtrace_predicate_t pred = {42};

    run(&guest, &pred, 0, 0);
    assert(evaluations == 1 && matches == 0 && thread.t_predcache == 0);
    run(&guest, &pred, 1, 0);
    assert(evaluations == 2 && matches == 1);

    run(&host, &pred, 0, 0);
    assert(evaluations == 3 && matches == 1 && thread.t_predcache == 42);
    run(&guest, &pred, 1, 0);
    assert(evaluations == 4 && matches == 2 && exits == 0);
    run(&host, &pred, 1, 0);
    assert(evaluations == 4 && matches == 2 && exits == 1);

    thread.t_predcache = 0;
    run(&host, &pred, 0, 1);
    assert(evaluations == 5 && thread.t_predcache == 0);
    return 0;
}
'''
path = out / 'guest-predicate-cache.c'
path.write_text(fixture.replace('PRODUCTION_LOOKUP', lookup).replace(
    'PRODUCTION_REJECT', reject))
binary = out / 'guest-predicate-cache'
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
                '-fsanitize=address,undefined', str(path), '-o', str(binary)],
               check=True)
subprocess.run([str(binary)], check=True)
print('PASS: guest predicates ignore host-thread cache; host cache retained')
