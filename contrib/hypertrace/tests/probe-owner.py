#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/sys/dtrace_impl.h').read_text()
a = source.index('typedef struct dtrace_vprobe_owner {')
b = source.index('} dtrace_vprobe_owner_t;', a) + len('} dtrace_vprobe_owner_t;')
(out / 'owner-types.inc').write_text(source[a:b])
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
parts = []
for name in ('dtrace_vprobe_register_owner', 'dtrace_vprobe_release_owner'):
    a = source.index('static void\n' + name + '(')
    b = source.index('\n}', a) + 2
    parts.append(source[a:b])
(out / 'owner.inc').write_text('\n'.join(parts))
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(out), str(Path(__file__).with_name('probe-owner.c')), '-o', str(out / 'owner-test')], check=True)
subprocess.run([str(out / 'owner-test')], check=True, timeout=30)
