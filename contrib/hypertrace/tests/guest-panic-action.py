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
early_start = source.index('\t\t\t/* These actions operate on or resolve')
early_end = source.index('\n\t\t\tswitch (act->dta_kind) {', early_start)
early = source[early_start:early_end]
arm_start = source.index('\n\t\t\tcase DTRACEACT_PANIC:\n', early_end) + 1
arm = source[arm_start:source.index('\t\t\t\tcontinue;\n', arm_start) +
    len('\t\t\t\tcontinue;\n')]
assert 'dtrace_action_panic(ecb);' in arm
fixture = r'''
#include <assert.h>
#include <setjmp.h>
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
enum {
    DTRACEACT_STOP = 1, DTRACEACT_BREAKPOINT, DTRACEACT_PANIC,
    DTRACEACT_CHILL, DTRACEACT_RAISE, DTRACEACT_IMMSTACK, DTRACEACT_JSTACK,
    DTRACEACT_SYM, DTRACEACT_MOD, DTRACEACT_USYM, DTRACEACT_UMOD
};
static unsigned cpu_flags;
static int dtrace_destructive_disallow, panic_calls, claim_calls;
static void *dtrace_panicked;
static char thread;
#define curthread (&thread)
/* A failed ASSERT is a debug-kernel panic: trap it where a case expects one. */
static jmp_buf assert_trap;
static int assert_armed;
#define ASSERT(expr) do { if (!(expr)) { assert(assert_armed); \
    longjmp(assert_trap, 1); } } while (0)
#define ASSERT_TRIPS(stmt) do { assert_armed = 1; \
    if (setjmp(assert_trap) == 0) { stmt; assert(!"ASSERT held"); } \
    assert_armed = 0; } while (0)
#define DTRACE_CPUFLAG_SET(flag) (cpu_flags |= (flag))
static int dtrace_priv_kernel_destructive(void *state)
{
    (void)state;
    return 1;
}
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
static void
run_action(dtrace_ecb_t *ecb)
{
    dtrace_probe_t *probe = ecb->dte_probe;
    struct action { int dta_kind; } action_record = {DTRACEACT_PANIC};
    struct action *act = &action_record;
    unsigned *flags = &cpu_flags;
    void *state = NULL;

    for (int action = 0; action < 1; action++) {
PRODUCTION_EARLY
        switch (act->dta_kind) {
PRODUCTION_ARM
        default: assert(0);
        }
    }
}
int main(void)
{
    dtrace_provider_t provider = {"test"};
    dtrace_probe_t guest = {7, &provider, "mod", "func", "name"};
    dtrace_probe_t host = {0, &provider, "mod", "func", "name"};
    dtrace_ecb_t ecb = {&guest};

    run_action(&ecb);
    assert(cpu_flags == CPU_DTRACE_ILLOP);
    assert(panic_calls == 0 && claim_calls == 0 && dtrace_panicked == NULL);
    /* dtrace_probe() refuses it first; the helper never sees a guest. */
    cpu_flags = 0;
    ASSERT_TRIPS(dtrace_action_panic(&ecb));
    assert(panic_calls == 0 && claim_calls == 0 && dtrace_panicked == NULL);

    cpu_flags = 0;
    ecb.dte_probe = &host;
    dtrace_destructive_disallow = 1;
    run_action(&ecb);
    assert(cpu_flags == 0 && panic_calls == 0 && claim_calls == 0);

    dtrace_destructive_disallow = 0;
    run_action(&ecb);
    assert(cpu_flags == 0 && panic_calls == 1 && claim_calls == 1);
    assert(dtrace_panicked == curthread);
    dtrace_action_panic(&ecb);
    assert(panic_calls == 1 && claim_calls == 1);
    return 0;
}
'''
path = out / 'guest-panic-action.c'
path.write_text(fixture.replace('PRODUCTION_HELPER', helper)
    .replace('PRODUCTION_EARLY', early).replace('PRODUCTION_ARM', arm))
binary = out / 'guest-panic-action'
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
                '-fsanitize=address,undefined', str(path), '-o', str(binary)],
               check=True)
subprocess.run([str(binary)], check=True)
print('PASS: guest panic is illegal without claiming or panicking the host')
