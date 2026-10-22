#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/dev/dtrace/dtrace_ioctl.c').read_text()
a = source.index('\tcase DTRACEIOC_AUGMENT:')
b = source.index('\tcase DTRACEIOC_VPROBE_CREATE:', a)
(out / 'augment.inc').write_text('static int dispatch(void *addr, state_t *state, thread_t *td) { switch (DTRACEIOC_AUGMENT) {\n' + source[a:b] + '\n} return EINVAL; }\n')
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(out), str(Path(__file__).with_name('augment-ioctl.c')),
    '-o', str(out / 'augment-test')], check=True)
subprocess.run([str(out / 'augment-test')], check=True, timeout=30)
