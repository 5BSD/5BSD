#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production dttransport read path with failed user copies."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/dev/dttransport/dttransport.c').read_text()
queue_start = source.index('static bool\ndtt_owner_matches(')
queue_end = source.index('\nstatic int\ndtt_handler(', queue_start)
read_start = source.index('static int\ndtt_read(')
read_end = source.index('\nstatic int\ndtt_write(', read_start)
(out / 'transport-read.inc').write_text(source[queue_start:queue_end] +
                                         '\n' + source[read_start:read_end] + '\n')
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'transport-read-test')], check=True)
subprocess.run([str(out / 'transport-read-test')], check=True, timeout=30)
