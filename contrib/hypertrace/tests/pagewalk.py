#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile actual kernel page-walker functions against synthetic page tables."""
from pathlib import Path
import re, subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/dev/dtrace/amd64/dtrace_vm_subr.c').read_text() + '\n' + (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
functions = []
for name in ['DTRACE_PHYS_TO_DMAP', 'dtrace_emulate_ad_bits', 'dtrace_valid_bit',
             'DTRACE_PHYS_TO_VM_PAGE', 'dtrace_get_page', 'dtrace_gla2hva_impl', 'dtrace_gla2hva', 'dtrace_guest_load']:
    match = re.search(r'(?:static [^\n]+|int)\n' + name + r'\(', source)
    if not match:
        raise SystemExit('Function not found: ' + name)
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    functions.append(source[match.start():end])
(out / 'walker.inc').write_text('\n\n'.join(functions) + '\n')
strings = []
for name in ['dtrace_strncmp', 'dtrace_bcmp', 'dtrace_bcopy', 'dtrace_strcpy']:
    match = re.search(r'static [^\n]+\n' + name + r'\(', source)
    if not match:
        raise SystemExit('Function not found: ' + name)
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    strings.append(source[match.start():end])
(out / 'strings.inc').write_text('\n\n'.join(strings) + '\n')
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                '-I' + str(out), str(Path(__file__).with_name('pagewalk.c')),
                '-o', str(out / 'pagewalk-test')], check=True)
subprocess.run([str(out / 'pagewalk-test')], check=True, timeout=30)
print('PASS: read-only legacy 32-bit, PAE and 4/5-level guest and EPT/NPT translation, missing mappings and bounds')
