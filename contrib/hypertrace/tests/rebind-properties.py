#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Sanitized standalone tests of production HRC2 rebind record helpers."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = Path(__file__).with_suffix('.cc')
binary = out / 'rebind-properties'
command = ['c++', '-std=c++17', '-O1', '-g', '-UNDEBUG', '-Wall', '-Wextra',
           '-Werror', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
           '-I' + str(root/'sys'), '-I' + str(root/'usr.sbin/dtraced'),
           str(source), '-lcrypto', '-o', str(binary)]
build = subprocess.run(command, capture_output=True, text=True)
(out/'build.log').write_text(build.stdout + build.stderr)
if build.returncode:
    raise SystemExit('Compilation failed; see build.log')
run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
(out/'run.log').write_text(run.stdout + run.stderr)
paths = [source, Path(__file__), binary, root/'usr.sbin/dtraced/dtraced_rebind_wire.h',
         root/'usr.sbin/dtraced/dtraced_wire.h']
(out/'results.json').write_text(json.dumps({'status': run.returncode,
    'command': command, 'live_testing': False,
    'sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}, indent=2)+'\n')
print(run.stdout, end='')
raise SystemExit(run.returncode)
