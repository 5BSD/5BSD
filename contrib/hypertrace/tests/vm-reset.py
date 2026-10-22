#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/amd64/vmm/vmm.c').read_text()
a = source.index('int\nvm_reset(')
b = source.index('\n}', a) + 2
(out / 'vm-reset.inc').write_text(source[a:b])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(out), str(Path(__file__).with_name('vm-reset.c')), '-o', str(out / 'vm-reset-test')], check=True)
subprocess.run([str(out / 'vm-reset-test')], check=True, timeout=30)
