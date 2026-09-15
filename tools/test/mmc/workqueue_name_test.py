#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Test queue-name formatting and audit legacy dynamic-name callers."""
from pathlib import Path
import re
from power_test import run_test
ROOT = Path(__file__).resolve().parents[3]
if __name__ == '__main__':
    run_test('workqueue_name_test.c', [('sys/compat/linuxkpi/common/src/linux_work.c',
              'struct workqueue_struct *', 'linux_alloc_ordered_workqueue')])
    # Every current call starts with either a literal or a plain identifier.
    # Audit two-argument calls whose dynamic names would be format strings.
    calls = []
    for base in ('sys/ofed','sys/dev','sys/compat/linuxkpi/common/src','sys/contrib/dev'):
        for path in (ROOT/base).rglob('*.c'):
            for call in re.findall(r'alloc_ordered_workqueue\(([^;]+?)\);', path.read_text(errors='replace')):
                # Select the legacy two-argument form: a dynamic name here
                # must not bypass format checking after a compatibility change.
                match = re.fullmatch(r'\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*|0)\s*',call)
                if match:
                    calls.append((path,match.group(1)))
    assert not calls, 'Unconverted dynamic workqueue names: '+str(calls)
print('PASS: ordered queue formatting, literal percent names and legacy dynamic-name call-site audit')
