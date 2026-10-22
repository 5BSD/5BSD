#!/usr/bin/env python3.12
"""Compile the production DIF-to-VMM register map for all guest ISAs."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static int\ndtrace_guest_reg_name(')
end = source.index('\n}', start) + 2
helper = source[start:end]
cases = {
    'amd64': (None, '''
        assert(dtrace_guest_reg_name(0) == VM_REG_GUEST_GS);
        assert(dtrace_guest_reg_name(4) == VM_REG_GUEST_RDI);
        assert(dtrace_guest_reg_name(11) == VM_REG_GUEST_RAX);
        assert(dtrace_guest_reg_name(12) == -1);
        assert(dtrace_guest_reg_name(13) == -1);
        assert(dtrace_guest_reg_name(14) == VM_REG_GUEST_RIP);
        assert(dtrace_guest_reg_name(17) == VM_REG_GUEST_RSP);
        assert(dtrace_guest_reg_name(GS + 1 + REG_R15) == VM_REG_GUEST_R15);
        assert(dtrace_guest_reg_name(GS + 1 + REG_RAX) == VM_REG_GUEST_RAX);
        assert(dtrace_guest_reg_name(GS + 1 + REG_TRAPNO) == -1);
        assert(dtrace_guest_reg_name(GS + 1 + REG_SS) == VM_REG_GUEST_SS);
        assert(dtrace_guest_reg_name(GS + 2 + REG_SS) == -1);
    '''),
    'arm64': ('__aarch64__', '''
        assert(dtrace_guest_reg_name(REG_X0) == VM_REG_GUEST_X0);
        assert(dtrace_guest_reg_name(REG_X29) == VM_REG_GUEST_X29);
        assert(dtrace_guest_reg_name(REG_LR) == VM_REG_GUEST_LR);
        assert(dtrace_guest_reg_name(REG_SP) == VM_REG_GUEST_SP);
        assert(dtrace_guest_reg_name(REG_PC) == VM_REG_GUEST_PC);
        assert(dtrace_guest_reg_name(REG_PC + 1) == -1);
    '''),
    'riscv': ('__riscv', '''
        assert(dtrace_guest_reg_name(REG_ZERO) == VM_REG_GUEST_ZERO);
        assert(dtrace_guest_reg_name(REG_RA) == VM_REG_GUEST_RA);
        assert(dtrace_guest_reg_name(REG_A7) == VM_REG_GUEST_A7);
        assert(dtrace_guest_reg_name(REG_T6) == VM_REG_GUEST_T6);
        assert(dtrace_guest_reg_name(REG_PC) == VM_REG_GUEST_SEPC);
        assert(dtrace_guest_reg_name(REG_PC + 1) == -1);
    '''),
}
for arch, (macro, checks) in cases.items():
    header = (root / f'sys/{arch}/include/vmm.h').read_text()
    enum_start = header.index('enum vm_reg_name {')
    enum_end = header.index('};', enum_start) + 2
    regset = 'x86' if arch == 'amd64' else ('aarch64' if arch == 'arm64' else 'riscv')
    prefix = '#include <assert.h>\n#include <stdint.h>\n#include <stdio.h>\n'
    if macro:
        prefix += f'#undef __amd64__\n#define {macro} 1\n'
    prefix += f'#include <cddl/dev/dtrace/{regset}/regset.h>\n'
    prefix += 'typedef unsigned int uint_t;\n' + header[enum_start:enum_end] + '\n'
    fixture = prefix + helper + '\nint main(void) {\n' + checks + '\nputs("PASS: guest register map"); return (0);\n}\n'
    source_file = out / f'{arch}.c'
    source_file.write_text(fixture)
    binary = out / arch
    subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
        str(source_file), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
