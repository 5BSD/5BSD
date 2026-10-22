#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check the production virtual-probe argument reader at its array limit."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static dtrace_reg_t\ndtrace_guest_argument(')
end = source.index('\n}', start) + 2
helper = source[start:end]
slot_start = source.index('static int\ndtrace_minion_stackarg_slot(')
slot_end = source.index('\n}', slot_start) + 2
slot_helper = source[slot_start:slot_end]
argument_arm = source[source.index('\tcase DIF_VAR_ARGS:'):
                      source.index('\tcase DIF_VAR_REGS:')]
if 'return (dtrace_guest_argument(mstate, ndx));' not in argument_arm:
    raise SystemExit('Virtual args[] no longer uses the bounded reader')
if ('!dtrace_minion_stackarg_slot(mstate, ndx,' not in argument_arm or
        'mstate->dtms_stackarg[minion_slot] = val;' not in argument_arm):
    raise SystemExit('Minion args[] no longer bounds its stack cache')
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/hypertrace.h>

typedef struct {
    uint64_t dttr_value;
    const void *dttr_vmhdl;
} dtrace_reg_t;
typedef struct {
    hypertrace_args_t *dtms_htrargs;
    const void *dtms_vmhdl;
    uint64_t dtms_arg[5];
    uint64_t dtms_stackarg[5];
} dtrace_mstate_t;

HELPER
SLOT_HELPER

int main(void)
{
    hypertrace_args_t envelope = {0};
    const int handle = 1;
    dtrace_mstate_t mstate = {
        .dtms_htrargs = &envelope, .dtms_vmhdl = &handle
    };
    for (uint64_t i = 0; i < HYPERTRACE_ARGS_MAX; i++)
        envelope.htr_args[i] = 0x1000 + i;
    for (uint64_t i = 0; i < HYPERTRACE_ARGS_MAX; i++) {
        dtrace_reg_t result = dtrace_guest_argument(&mstate, i);
        assert(result.dttr_value == 0x1000 + i);
        assert(result.dttr_vmhdl == &handle);
    }
    for (uint64_t i = HYPERTRACE_ARGS_MAX; i < HYPERTRACE_ARGS_MAX + 8; i++) {
        dtrace_reg_t result = dtrace_guest_argument(&mstate, i);
        assert(result.dttr_value == 0 && result.dttr_vmhdl == NULL);
    }
    dtrace_reg_t huge = dtrace_guest_argument(&mstate, UINT64_MAX);
    assert(huge.dttr_value == 0 && huge.dttr_vmhdl == NULL);
    mstate.dtms_htrargs = NULL;
    dtrace_reg_t absent = dtrace_guest_argument(&mstate, 5);
    assert(absent.dttr_value == 0 && absent.dttr_vmhdl == NULL);
    size_t slot = SIZE_MAX;
    for (uint64_t i = 5; i < 10; i++) {
        assert(dtrace_minion_stackarg_slot(&mstate, i, &slot));
        assert(slot == i - 5);
    }
    for (uint64_t i = 0; i < 5; i++)
        assert(!dtrace_minion_stackarg_slot(&mstate, i, &slot));
    for (uint64_t i = 10; i < 18; i++)
        assert(!dtrace_minion_stackarg_slot(&mstate, i, &slot));
    assert(!dtrace_minion_stackarg_slot(&mstate, UINT64_MAX, &slot));
    assert(!dtrace_minion_stackarg_slot(&mstate, 5, NULL));
    return 0;
}
'''.replace('SLOT_HELPER', slot_helper).replace('HELPER', helper)
test_source = out / 'guest-arg-bounds.c'
test_source.write_text(fixture)
binary = out / 'guest-arg-bounds'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
                '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
                str(test_source), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
