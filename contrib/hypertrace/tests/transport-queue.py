#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/dev/dttransport/dttransport.c').read_text()
start = source.index('static int\ndtt_queue_enqueue_at(')
end = source.index('\nstatic moduledata_t dtt_kmod', start)
(out / 'transport-queue.inc').write_text(source[start:end])
subprocess.run(['cc', '-std=gnu17', '-pthread', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'transport-queue-test')], check=True)
subprocess.run([str(out / 'transport-queue-test')], check=True, timeout=30)
