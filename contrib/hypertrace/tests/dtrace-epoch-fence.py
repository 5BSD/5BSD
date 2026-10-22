#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual kernel DTrace VM-epoch fence without loading a module."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static uint64_t dtrace_hypertrace_epochs[')
end = source.index('\n#endif', start)
parts = [source[start:end]]
for name in ('dtrace_hypertrace_epoch_suspended',
             'dtrace_hypertrace_epoch_publish',
             'dtrace_hypertrace_epoch_revoke',
             'dtrace_hypertrace_epoch_suspend',
             'dtrace_hypertrace_epoch_resume'):
    start = source.index('int\n' + name + '(')
    end = source.index('\n}', start) + 2
    parts.append(source[start:end])
(out / 'dtrace-epoch-fence.inc').write_text('\n\n'.join(parts) + '\n')
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'dtrace-epoch-fence-test')], check=True)
subprocess.run([str(out / 'dtrace-epoch-fence-test')], check=True, timeout=30)
