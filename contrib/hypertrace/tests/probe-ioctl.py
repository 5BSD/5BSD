#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual VPROBE_CREATE ioctl case and its lock helpers."""
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
parts = []
for name in ('dtrace_hypertrace_config_lock', 'dtrace_hypertrace_config_unlock'):
    start = source.index('void\n' + name + '(')
    end = source.index('\n}\n', start) + 3
    parts.append(source[start:end])
source = (root / 'sys/cddl/dev/dtrace/dtrace_ioctl.c').read_text()
start = source.index('\tcase DTRACEIOC_VPROBE_CREATE:')
end = source.index('\n\tdefault:', start)
parts.append('static int dispatch(void *addr) { switch (DTRACEIOC_VPROBE_CREATE) {\n' +
             source[start:end] + '\n} return EINVAL; }\n')
(out / 'ioctl.inc').write_text('\n'.join(parts))
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
               '-I' + str(out), str(Path(__file__).with_name('probe-ioctl.c')),
               '-o', str(out / 'probe-ioctl-test')], check=True)
subprocess.run([str(out / 'probe-ioctl-test')], check=True, timeout=30)
