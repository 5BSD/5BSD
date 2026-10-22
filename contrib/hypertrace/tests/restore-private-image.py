#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the snapshot coordinator's exact private-image digest helper."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/snapshot.c').read_text()
start = source.index('static void\nhypertrace_private_image_digest(')
end = source.index('\nstatic int\nhypertrace_restore_prepare_handoff(', start)
(out / 'restore-private-image.inc').write_text(source[start:end])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-lmd',
    '-o', str(out / 'restore-private-image-test')], check=True)
subprocess.run([str(out / 'restore-private-image-test')], check=True,
    timeout=30)
