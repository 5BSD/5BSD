#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production DIF array-load verifier with real ABI bounds."""
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)

header = (root / 'sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h').read_text()
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
names = ('DIF_VAR_ARRAY_MAX', 'DIF_VAR_ARRAY_GMIN', 'DIF_VAR_ARRAY_GMAX',
         'DIF_VAR_ARRAY_HMIN', 'DIF_VAR_ARRAY_HMAX')
defines = []
for name in names:
    match = re.search(rf'^#define\s+{name}\s+(0x[0-9a-fA-F]+)\b',
                      header, re.MULTILINE)
    if match is None:
        raise SystemExit(f'Missing {name}')
    defines.append(f'#define {name} {match.group(1)}')
# ldga/ldta carry the array in r1; guest and host arrays have no encoding.
if not re.search(r'^#define\s+DIF_INSTR_R1\(i\)\s+\(\(\(i\) >> 16\) & 0xff\)',
                 header, re.MULTILINE):
    raise SystemExit('DIF_INSTR_R1 is no longer 8 bits')
start = source.index('\t\tcase DIF_OP_LDGA:',
                     source.index('\ndtrace_difo_validate('))
end = source.index('\t\tcase DIF_OP_LDGS:', start)
arms = source[start:end]

fixture = r'''
#include <assert.h>
#include <stdio.h>

enum { DIF_OP_LDGA = 1, DIF_OP_LDTA = 2 };
DEFINES
static int report(unsigned pc, const char *fmt, ...)
{
    (void)pc;
    (void)fmt;
    return 1;
}
static int verify(unsigned op, unsigned r1, unsigned r2, unsigned rd)
{
    unsigned nregs = 4, pc = 0;
    int err = 0;
    int (*efunc)(unsigned, const char *, ...) = report;
    switch (op) {
ARMS
    default: assert(0);
    }
    return err;
}
int main(void)
{
    const unsigned accepted[] = { 0, 0x80, 0xff };
    const unsigned rejected[] = { 0x100, 0x14f, DIF_VAR_ARRAY_GMIN,
        DIF_VAR_ARRAY_GMAX, 0x250, 0x2ff, DIF_VAR_ARRAY_HMIN, 0x302,
        DIF_VAR_ARRAY_HMAX, 0x400, 0xffff };
    for (unsigned op = DIF_OP_LDGA; op <= DIF_OP_LDTA; op++) {
        for (unsigned i = 0; i < sizeof(accepted) / sizeof(*accepted); i++)
            assert(verify(op, accepted[i], 1, 2) == 0);
        for (unsigned i = 0; i < sizeof(rejected) / sizeof(*rejected); i++)
            assert(verify(op, rejected[i], 1, 2) == 1);
        assert(verify(op, 0, 4, 2) == 1);
        assert(verify(op, 0, 1, 4) == 1);
        assert(verify(op, 0, 1, 0) == 1);
    }
    puts("PASS: DIF array verifier bounds and register checks");
    return 0;
}
'''.replace('DEFINES', '\n'.join(defines)).replace('ARMS', arms)
source_file = out / 'dif-array-verifier.c'
source_file.write_text(fixture)
binary = out / 'dif-array-verifier'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
                '-fsanitize=address,undefined', str(source_file), '-o',
                str(binary)], check=True)
subprocess.run([str(binary)], check=True)
