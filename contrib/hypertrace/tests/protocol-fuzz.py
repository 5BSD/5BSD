#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run bounded coverage-guided fuzzing of production protocol parsers offline."""
import hashlib
import json
import resource
import struct
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
corpus = out / 'corpus'
corpus.mkdir(exist_ok=True)
seeds = [struct.pack('<Q', 0), struct.pack('<QQ', 1, 1) + b'\0',
         struct.pack('<QQ', 1, 3) + b'vm\0',
         struct.pack('<QQQ', 2, 1, 0),
         struct.pack('<QQ', 4097, 2**64 - 1),
         struct.pack('<4sHHQQ', b'HTV2', 2, 7, 9, 2) + b'vm\x7fELF']
for i, seed in enumerate(seeds):
    (corpus / ('seed-%d' % i)).write_bytes(seed)
source = Path(__file__).with_suffix('.cc')
binary = out / 'protocol-fuzz'
command = ['c++', '-std=c++17', '-O1', '-g', '-UNDEBUG',
           '-Wall', '-Wextra', '-Werror', '-fsanitize=fuzzer,address,undefined',
           '-fno-sanitize-recover=all', '-I' + str(root / 'sys'),
           '-I' + str(root / 'usr.sbin/dtraced'), str(source), '-o', str(binary)]
build = subprocess.run(command, capture_output=True, text=True)
(out / 'build.log').write_text(build.stdout + build.stderr)
if build.returncode:
    raise SystemExit('Build failed; inspect build.log')
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
run_command = [str(binary), str(corpus), '-runs=200000', '-seed=5987622',
               '-max_len=65536', '-timeout=5', '-rss_limit_mb=1024',
               '-artifact_prefix=' + str(out) + '/']
with (out / 'fuzz.log').open('w') as log:
    run = subprocess.run(run_command, stdout=log, stderr=subprocess.STDOUT,
                         timeout=180)
paths = [source, Path(__file__), binary] + sorted(
    (root / 'usr.sbin/dtraced').glob('*.h')) + [
    root / 'sys/sys/hypertrace.h', root / 'sys/sys/hypertrace_wire.h']
(out / 'results.json').write_text(json.dumps({
    'status': run.returncode, 'build_command': command, 'run_command': run_command,
    'live_testing': False, 'production_coverage_percentage': None,
    'sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
    'corpus_files': len(list(corpus.iterdir()))}, indent=2) + '\n')
raise SystemExit(run.returncode)
