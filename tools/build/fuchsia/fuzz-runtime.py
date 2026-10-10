#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run a freshly built native codec-fuzz target and retain reproducible evidence.

Build with build-runtime.py --fuzz, or use make check-fuzz. This runner does
not rebuild its explicit target. All corpus and crash artifacts stay in /usr/obj.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--target', type=Path, default=Path('/usr/obj/5bsd-fidl-runtime/fuzzed/codec-fuzz'))
p.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-fidl-runtime'))
p.add_argument('--seconds', type=int, default=300)
p.add_argument('--seed', type=int, default=23389)
a = p.parse_args()
if not 1 <= a.seconds <= 86400 or not 1 <= a.seed <= 4294967295:
    p.error('seconds must be 1..86400 and seed must be 1..4294967295')
a.target = a.target.resolve()
a.obj = a.obj.resolve()
if not a.obj.is_relative_to('/usr/obj') or not a.target.is_file():
    p.error('use an object directory under /usr/obj and an existing codec-fuzz target')
a.obj.mkdir(parents=True, exist_ok=True)
work = Path(tempfile.mkdtemp(prefix='fuzz-', dir=a.obj))
corpus = work/'corpus'
crashes = work/'crashes'
crashes.mkdir()
env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
           UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
record = {'status':'RUNNING', 'target':str(a.target),
          'binary_sha256':hashlib.sha256(a.target.read_bytes()).hexdigest(),
          'platform':list(os.uname()), 'seconds_requested':a.seconds, 'seed':a.seed,
          'leak_sanitizer':'unavailable; descriptor lifetime checked by pipe EOF',
          'work':str(work)}
print('Native codec fuzz evidence: '+str(work), flush=True)
try:
    subprocess.run([str(a.target),'--write-corpus',str(corpus)],env=env,check=True,timeout=30)
    record['initial_corpus'] = {f.name:hashlib.sha256(f.read_bytes()).hexdigest()
                                for f in sorted(corpus.iterdir())}
    with (work/'seed-replay.log').open('w') as output:
        subprocess.run([str(a.target),'-runs=0',str(corpus)],env=env,check=True,
                       stdout=output,stderr=subprocess.STDOUT,timeout=30)
    replay = (work/'seed-replay.log').read_text()
    accepted = {int(k):int(v) for k,v in re.findall(r'fidl-fuzz shape=(\d+) decoded=\d+ accepted=(\d+)',replay)}
    if any(accepted.get(shape,0) == 0 for shape in range(9)):
        raise RuntimeError('initial corpus did not reach all nine valid decoder shapes: '+str(accepted))
    record['seed_accepted'] = accepted
    command = [str(a.target), '-max_total_time='+str(a.seconds), '-seed='+str(a.seed),
               '-max_len=14338','-timeout=5','-rss_limit_mb=1024','-print_final_stats=1',
               '-artifact_prefix='+str(crashes)+'/',str(corpus)]
    record['command'] = command
    started = time.monotonic()
    with (work/'fuzz.log').open('w') as output:
        subprocess.run(command,env=env,check=True,stdout=output,
                       stderr=subprocess.STDOUT,timeout=a.seconds+30)
    record['elapsed_seconds'] = round(time.monotonic()-started,3)
    output = (work/'fuzz.log').read_text()
    units = re.search(r'stat::number_of_executed_units:\s+(\d+)',output)
    if not units or int(units[1]) == 0 or list(crashes.iterdir()):
        raise RuntimeError('fuzzer did not complete a clean measured run')
    record['executed_inputs'] = int(units[1])
    record['final_corpus_files'] = len(list(corpus.iterdir()))
    record['status'] = 'PASS'
except Exception as error:
    record.update(status='FAIL', error=str(error))
    raise
finally:
    (work/'result.json').write_text(json.dumps(record,indent=2)+'\n')
print('Native codec fuzz: PASS; '+str(work),flush=True)
