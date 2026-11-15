#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production RISC-V checkpoint CPU capture with mocked queries."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/riscv/checkpoint_cpu_machdep.c').read_text()
start = source.index('static void\nrecord_scalar(')
common = (root / 'usr.sbin/bhyve/checkpoint_cpu.c').read_text()
match_start = common.index('int\ncheckpoint_cpu_contract_validate(')
match_end = common.index('\nint\ncheckpoint_cpu_contract_encode(', match_start)
describe_start = common.index('/*\n * Name one register of a contract record')
describe_end = common.index('\n}\n', common.index(
    '\ncheckpoint_cpu_contract_match(', describe_start)) + 3
vmexit = (root / 'usr.sbin/bhyve/riscv/vmexit.c').read_text()
sbi_start = vmexit.index('static int\nvmm_sbi_probe_extension(')
sbi_end = vmexit.index('\nstatic int\nvmexit_ecall_hsm(', sbi_start)
sbi_names = {'SBI_IMPL_ID_BHYVE', 'SBI_EXT_ID_HYPERTRACE',
    'SBI_HYPERTRACE_VERSION', 'SBI_EXT_ID_HSM', 'SBI_EXT_ID_TIME',
    'SBI_EXT_ID_IPI', 'SBI_EXT_ID_RFNC', 'SBI_EXT_ID_SRST',
    'SBI_CONSOLE_PUTCHAR', 'SBI_CONSOLE_GETCHAR'}
sbi_header = (root / 'sys/riscv/include/sbi.h').read_text()
sbi_defines = [line for line in sbi_header.splitlines()
    if line.startswith('#define') and line.split()[1] in sbi_names]
if len(sbi_defines) != len(sbi_names):
    raise SystemExit('Missing SBI ABI constant')
fixture = Path(__file__).with_suffix('.c').read_text()
fixture = fixture.replace('/* SBI_IDS */', '\n'.join(sbi_defines), 1)
fixture = fixture.replace('/* PRODUCTION_SBI_MASK */',
    vmexit[sbi_start:sbi_end], 1)
fixture = fixture.replace('/* PRODUCTION_CAPTURE */', source[start:], 1)
fixture = fixture.replace('/* PRODUCTION_MATCH */',
    common[match_start:match_end] + '\n' +
    common[describe_start:describe_end], 1)
path = out / 'riscv-cpu-contract.c'
path.write_text(fixture)
binary = out / 'riscv-cpu-contract'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(root / 'usr.sbin/bhyve'),
    '-I' + str(root / 'usr.sbin/bhyve/riscv'),
    str(path), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
