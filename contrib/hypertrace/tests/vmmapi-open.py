#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise libvmmapi's production open validation without a VM device."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'lib/libvmmapi/vmmapi.c').read_text()
start = source.index('struct vmctx *\nvm_openf(')
end = source.index('\nvoid\nvm_close(', start)
(out / 'vmmapi-open.inc').write_text(source[start:end])
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out), '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.c')), '-o', str(out / 'vmmapi-open-test')],
    check=True)
subprocess.run([str(out / 'vmmapi-open-test')], check=True, timeout=30)
