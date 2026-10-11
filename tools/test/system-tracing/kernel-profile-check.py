#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Render and offline-compile the semantic kernel profiles (not live qualification)."""
import argparse
import concurrent.futures
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

PROFILES = (
    'audio-xruns', 'bufcache-waits', 'dma-waits', 'epoch-stalls',
    'ffs-pressure', 'firmware-load', 'geom-retries', 'gtaskqueue-latency',
    'inotify-loss', 'ktls-fallback', 'linux-epoll-waits', 'linux-futex-waits',
    'linux-socket-compat', 'netgraph-path', 'netlink-errors', 'rfcomm-stalls',
    'rpc-retries', 'taskqueue-latency', 'tty-flow', 'uma-pressure',
    'usb-latency', 'wifi-state',
)


def check_contracts(source, inventory):
    # These profiles deliberately use scalar args, never typed args[] or
    # dereferenced saved identities. Validate selectors even when -Z permits
    # compilation without any of their providers on the running host.
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.S)
    clauses = re.finditer(
        r'((?:[\w*]+:[^:\s]*:[^:\s]*:[\w*-]+\s*,?\s*)+)'
        r'(?:/[^{}]*?/\s*)?\{([^{}]*)\}', source, re.S)
    seen = 0
    for clause in clauses:
        selectors = re.findall(r'([\w*]+):([^:\s]*):([^:\s]*):([\w*-]+)',
                               clause[1])
        args = [int(n) for n in re.findall(r'\barg(\d+)\b', clause[0])]
        for provider, module, function, name in selectors:
            matches = [p for p in inventory
                       if fnmatch.fnmatchcase(p['provider'], provider)
                       and (not module or p.get('module', '') == module)
                       and (not function or p.get('function', '') == function)
                       and fnmatch.fnmatchcase(p['name'], name)]
            assert matches, 'unknown selector: ' + ':'.join(
                (provider, module, function, name))
            assert all(not args or max(args) < len(p['types'])
                       for p in matches), 'argument outside contract: ' + name
            seen += 1
    assert seen, 'no probe clauses validated'
    return seen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--bsdinstruments', default='/usr/sbin/bsdinstruments')
    parser.add_argument('--dtrace', default='/usr/sbin/dtrace')
    args = parser.parse_args()
    out = args.output or Path(tempfile.mkdtemp(prefix='kernel-profiles-'))
    out.mkdir(parents=True, exist_ok=True)
    tests = args.src / 'tools/test/system-tracing'
    inv = json.loads((tests / 'kernel-probes.json').read_text())['probes']
    inv += json.loads((tests / 'kernel-probes-next.json').read_text())
    for p in inv:
        if p['provider'] == 'linuxulator{,32}':
            p['provider'] = 'linuxulator'
    profiles = args.src / 'cddl/usr.sbin/bsdinstruments/profiles'

    def check(job):
        name, filtered = job
        source = profiles / (name + '.d')
        content = source.read_text()
        count = check_contracts(content, inv)
        cmd = [args.bsdinstruments, 'generate', '-f', str(source)]
        if filtered:
            cmd += ['--pid', '42', '--duration', '1']
        rendered = subprocess.run(cmd, capture_output=True, text=True,
                                  check=True).stdout
        assert '@bsdinstruments-' not in rendered, 'unexpanded marker'
        path = out / (name + ('-filtered' if filtered else '') + '.d')
        path.write_text(rendered)
        command = [args.dtrace, '-e', '-Z', '-s', str(path)]
        result = subprocess.run(command, capture_output=True, text=True)
        (path.with_suffix('.log')).write_text(result.stdout + result.stderr)
        print(name, 'filtered' if filtered else 'plain',
              'PASS' if result.returncode == 0 else 'FAIL', flush=True)
        return dict(profile=name, filtered=filtered, status=result.returncode,
                    selectors_checked=count, command=command,
                    source_sha256=hashlib.sha256(content.encode()).hexdigest())

    jobs = [(name, filtered) for name in PROFILES for filtered in (False, True)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        results = list(pool.map(check, jobs))
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print('Results:', out)
    return int(any(r['status'] for r in results))


if __name__ == '__main__':
    raise SystemExit(main())
