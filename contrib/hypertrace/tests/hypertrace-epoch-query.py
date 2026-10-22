#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the real privileged HyperTrace epoch query handler."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/dev/hypertrace/hypertrace.c').read_text()
start = source.index('static int\nhypertrace_ioctl(')
end = source.index('\n}', start) + 2
handler = source[start:end]
start = source.index('static int\nhypertrace_priv_check_epoch(')
end = source.index('\n}', start) + 2
(out / 'hypertrace-epoch-query.inc').write_text(
    handler + '\n\n' + source[start:end] + '\n')
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'hypertrace-epoch-query-test')], check=True)
subprocess.run([str(out / 'hypertrace-epoch-query-test')], check=True,
    timeout=30)
