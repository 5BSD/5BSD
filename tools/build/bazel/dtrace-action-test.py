#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise a prepared native DTrace Bazel graph without rebuilding its SDK.

The command JSON supplies an explicit Bazel test argv. The workspace must be a
private qualification workspace with a provider source copied into it. Every
change is restored, including after failures. This tests source invalidation
and failure propagation, not complete toolchain or tracing qualification.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
for key in ('workspace', 'command', 'provider', 'changed-provider', 'java-home', 'output'):
    p.add_argument('--' + key, required=True, type=Path)
p.add_argument('--restored-output', type=Path, action='append', default=[],
               help='workspace-relative output whose bytes must match after provider restoration')
a = p.parse_args()
w = a.workspace.resolve(strict=True)
provider = a.provider.resolve(strict=True)
out = a.output.resolve()
if not w.is_relative_to('/usr/obj') or not provider.is_relative_to(w):
    p.error('private workspace and provider below /usr/obj required')
if out.exists() or not out.is_relative_to('/usr/obj') or out.is_relative_to(w):
    p.error('fresh output below /usr/obj outside workspace required')
argv = json.loads(a.command.read_text())['argv']
if 'test' not in argv:
    p.error('a Bazel test command is required')
argv = [x for x in argv if not x.startswith(('--build_event_json_file=', '--execution_log_json_file='))]
env = dict(os.environ, JAVA_HOME=str(a.java_home.resolve(strict=True)), BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1')
out.mkdir(parents=True)
original = provider.read_bytes()
changed = a.changed_provider.resolve(strict=True).read_bytes()
if changed == original:
    p.error("changed provider must differ from the workspace provider")
(out / 'original-provider.d').write_bytes(original)
(out / 'changed-provider.d').write_bytes(changed)
records = []

def entries(path):
    s = path.read_text(); decoder = json.JSONDecoder(); offset = 0
    while offset < len(s):
        while offset < len(s) and s[offset].isspace():
            offset += 1
        if offset == len(s):
            return
        item, offset = decoder.raw_decode(s, offset)
        yield item

def run(name, success=True):
    log = out / (name + '.execution.json')
    cmd = argv + ['--execution_log_json_file=' + str(log),
                  '--build_event_json_file=' + str(out / (name + '.events.json'))]
    with (out / (name + '.stdout')).open('w') as stdout, (out / (name + '.stderr')).open('w') as stderr:
        r = subprocess.run(['/usr/bin/time', '-l', *cmd], cwd=w, env=env, stdout=stdout, stderr=stderr)
    actions = list(entries(log)) if log.exists() else []
    counts = collections.Counter(e.get('mnemonic') for e in actions if not e.get('cacheHit', False))
    record = {'name': name, 'argv': cmd, 'exit_status': r.returncode, 'executed': dict(counts)}
    records.append(record)
    (out / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
    if success != (r.returncode == 0):
        raise RuntimeError(name + ': unexpected status; see ' + str(out))
    # A mutating generator must not alter any recorded compiler object input.
    checked = []
    for action in actions:
        if action.get('mnemonic') != 'BSDDTraceObjects' or action.get('exitCode', 0):
            continue
        for item in action.get('inputs', []):
            if '/_objs/' not in item['path'] or not item['path'].endswith('.o'):
                continue
            path = w / item['path']
            if hashlib.sha256(path.read_bytes()).hexdigest() != item['digest']['hash']:
                raise RuntimeError('generator mutated input: ' + str(path))
            checked.append(item['path'])
    record['preserved_objects'] = checked
    return counts

try:
    run('baseline')
    baseline_outputs = {}
    for relative in a.restored_output:
        if relative.is_absolute() or '..' in relative.parts:
            p.error('restored output must be workspace-relative')
        baseline_outputs[str(relative)] = hashlib.sha256((w / relative).read_bytes()).hexdigest()
    counts = run('noop')
    assert not any(counts[m] for m in ('BSDDTraceHeader', 'BSDDTraceObjects', 'CppCompile'))
    provider.write_bytes(changed)
    counts = run('provider-change')
    assert counts['BSDDTraceHeader'] and counts['BSDDTraceObjects'] and counts['CppCompile']
    provider.write_bytes(original + b'\nthis is deliberately invalid D source !!!\n')
    run('invalid-provider', success=False)
finally:
    provider.write_bytes(original)
run('restored')
restored_outputs = {name: hashlib.sha256((w / name).read_bytes()).hexdigest()
                    for name in baseline_outputs}
comparison = {'baseline': baseline_outputs, 'restored': restored_outputs,
              'status': 'passed' if baseline_outputs == restored_outputs else 'failed'}
(out / 'restored-outputs.json').write_text(json.dumps(comparison, indent=2) + '\n')
if baseline_outputs != restored_outputs:
    raise RuntimeError('restored output bytes differ; see ' + str(out / 'restored-outputs.json'))
(out / 'receipt.json').write_text(json.dumps({'status': 'passed', 'scope': 'prepared DTrace graph: no-op, provider invalidation, original input preservation, syntax failure and recovery', 'records': records, 'limitations': ['No tool/flag/header invalidation matrix yet.', 'No installed tracing activation or full library integration.']}, indent=2) + '\n')
print('PASS: no-op, provider invalidation, input preservation, failure and restoration')
