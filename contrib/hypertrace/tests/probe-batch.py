#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import re, subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
subprocess.run([sys.executable, str(Path(__file__).with_name('probe-map.py')), str(out)], check=True)
src = (root / 'sys/cddl/dev/hypertrace/hypertrace.c').read_text()
def fn(name):
    m = re.search(r'(?:static )?[^\n]+\n' + name + r'\(', src)
    return src[m.start():src.index('\n}', m.start()) + 2]
(out / 'batch.inc').write_text('\n'.join(fn(x) for x in
    ('hypertrace_priv_epoch_byid', 'hypertrace_vm_alloc', 'hypertrace_vm_release', 'hypertrace_priv_check_epoch', 'hypertrace_probe', 'hypertrace_priv_disable', 'hypertrace_priv_rmprobe', 'hypertrace_priv_create_probes')))
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-pthread', '-fsanitize=address,undefined',
    '-I' + str(out), str(Path(__file__).with_name('probe-batch.c')),
    '-o', str(out / 'probe-batch-test')], check=True)
subprocess.run([str(out / 'probe-batch-test')], check=True, timeout=30)
