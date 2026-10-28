#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare explicitly selected objcopy tools on one retained input.

This is a sequential warm-cache microbenchmark, not a disk-throughput or
system-build benchmark. wait4 supplies separate child CPU/RSS/I/O counters;
block counters do not measure physical-device traffic or bytes. Outputs from
a buggy baseline may differ: correctness is established by separate audits.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import time


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline-tool', 'candidate-tool', 'input', 'options', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--iterations', type=int, default=30)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error('--iterations must be positive')
    args.work.mkdir(parents=True, exist_ok=False)
    tools = {'baseline': args.baseline_tool.resolve(strict=True), 'candidate': args.candidate_tool.resolve(strict=True)}
    report = {'scope': __doc__, 'complete': False, 'iterations': args.iterations,
              'host': list(os.uname()), 'logical_cpus': os.cpu_count(), 'inputs': {}, 'samples': []}
    for name, path in {**tools, 'input': args.input, 'options': args.options}.items():
        report['inputs'][name] = {'path': str(path), 'sha256': digest(path), 'bytes': path.stat().st_size}
    source = args.work / 'input.o'
    shutil.copyfile(args.input, source)
    shutil.copyfile(args.options, args.work / 'options')
    flags = (args.work / 'options').read_text().splitlines()
    if any(not flag.startswith(('-L', '-N')) or any(c.isspace() for c in flag) for flag in flags):
        raise ValueError('expected maintained module export flags, one per line')
    env = dict(os.environ)
    for key in list(env):
        if key.startswith('LD_'):
            del env[key]
    try:
        # Alternate order to reduce systematic bias; retain warmups separately.
        for iteration in range(-2, args.iterations):
            order = ('baseline', 'candidate') if iteration % 2 == 0 else ('candidate', 'baseline')
            for name in order:
                output = args.work / (name + '.o')
                command = [str(tools[name]), *flags, str(source), str(output)]
                start = time.perf_counter()
                with (args.work / (name + '.stderr')).open('wb') as error:
                    proc = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=error)
                    _, status, usage = os.wait4(proc.pid, 0)
                    proc.returncode = os.waitstatus_to_exitcode(status)
                elapsed = time.perf_counter() - start
                if proc.returncode:
                    raise RuntimeError(f'{name} failed: {proc.returncode}')
                report['samples'].append({'tool': name, 'iteration': iteration, 'warmup': iteration < 0,
                    'wall_seconds': elapsed, 'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
                    'max_rss_kib': usage.ru_maxrss, 'block_inputs': usage.ru_inblock,
                    'block_outputs': usage.ru_oublock, 'major_faults': usage.ru_majflt})
        report['summary'] = {}
        for name in tools:
            samples = [s for s in report['samples'] if s['tool'] == name and not s['warmup']]
            output = args.work / (name + '.o')
            report['summary'][name] = {
                'median_wall_seconds': statistics.median(s['wall_seconds'] for s in samples),
                'total_user_seconds': sum(s['user_seconds'] for s in samples),
                'total_system_seconds': sum(s['system_seconds'] for s in samples),
                'max_rss_kib': max(s['max_rss_kib'] for s in samples),
                'total_block_inputs': sum(s['block_inputs'] for s in samples),
                'total_block_outputs': sum(s['block_outputs'] for s in samples),
                'output_bytes': output.stat().st_size,
                'output_allocated_bytes': output.stat().st_blocks * 512,
                'output_sha256': digest(output)}
        for name, path in {**tools, 'input': args.input, 'options': args.options}.items():
            if digest(path) != report['inputs'][name]['sha256']:
                raise ValueError('input changed during measurement: ' + name)
        report['complete'] = True
    finally:
        (args.work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
