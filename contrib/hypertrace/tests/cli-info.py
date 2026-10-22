#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/cmd/dtrace/dtrace.c').read_text()
a = source.index('static void\nprint_imsgs(')
b = source.index('\nint\nmain(', a)
c = source.index('\tif (g_mode == DMODE_LISTVMS) {', b)
d = source.index('\n\t/*', c)
(out / 'cli-info.inc').write_text(source[a:b] + '\nstatic void listing(void) {\n' + source[c:d] + '\n}\n')
subprocess.run(['cc', '-pthread', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'usr.sbin/dtraced'),
    str(Path(__file__).with_name('cli-info.c')), '-o', str(out / 'cli-info-test')], check=True)
subprocess.run([str(out / 'cli-info-test')], check=True, timeout=30)
