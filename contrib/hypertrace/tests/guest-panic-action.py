#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production panic helper at the guest/host boundary."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static void\ndtrace_action_panic(dtrace_ecb_t *ecb)')
end = source.index('{', start) + 1
depth = 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
helper = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>

typedef struct { const char *dtpv_name; } dtrace_provider_t;
typedef struct {
    unsigned dtpr_vmid;
    void *dtpr_provider;
    const char *dtpr_mod, *dtpr_func, *dtpr_name;
} dtrace_probe_t;
typedef struct { dtrace_probe_t *dte_probe; } dtrace_ecb_t;
enum { CPU_DTRACE_ILLOP = 1 };
static unsigned flags;
static int dtrace_destructive_disallow, panic_calls, claim_calls;
static void *dtrace_panicked;
static char thread;
#define curthread (&thread)
#define ASSERT(expr) assert(expr)
#define DTRACE_CPUFLAG_SET(flag) (flags |= (flag))
static void *dtrace_casptr(void **where, void *old, void *new_value)
{
    void *prior = *where;
    ++claim_calls;
    if (prior == old)
        *where = new_value;
    return prior;
}
static void dtrace_panic(const char *fmt, ...)
{
    assert(strstr(fmt, "host probe") != NULL);
    ++panic_calls;
}
PRODUCTION_HELPER
int main(void)
{
    dtrace_provider_t provider = {"test"};
    dtrace_probe_t guest = {7, &provider, "mod", "func", "name"};
    dtrace_probe_t host = {0, &provider, "mod", "func", "name"};
    dtrace_ecb_t ecb = {&guest};

    dtrace_action_panic(&ecb);
    assert(flags == CPU_DTRACE_ILLOP);
    assert(panic_calls == 0 && claim_calls == 0 && dtrace_panicked == NULL);

    flags = 0;
    ecb.dte_probe = &host;
    dtrace_destructive_disallow = 1;
    dtrace_action_panic(&ecb);
    assert(flags == 0 && panic_calls == 0 && claim_calls == 0);

    dtrace_destructive_disallow = 0;
    dtrace_action_panic(&ecb);
    assert(flags == 0 && panic_calls == 1 && claim_calls == 1);
    assert(dtrace_panicked == curthread);
    dtrace_action_panic(&ecb);
    assert(panic_calls == 1 && claim_calls == 1);
    return 0;
}
'''
path = out / 'guest-panic-action.c'
path.write_text(fixture.replace('PRODUCTION_HELPER', helper))
binary = out / 'guest-panic-action'
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
                '-fsanitize=address,undefined', str(path), '-o', str(binary)],
               check=True)
subprocess.run([str(binary)], check=True)
print('PASS: guest panic is illegal without claiming or panicking the host')
