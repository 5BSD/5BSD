#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare captured default/candidate DTrace actions on identical compiler inputs.

Actions run serially outside Bazel in fresh /usr/obj directories. This measures
transformation cost, not whole-build parallel throughput or physical disk bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--baseline', type=Path, required=True)
p.add_argument('--candidate', type=Path, required=True)
p.add_argument('--component', action='append', required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--trials', type=int, default=5)
p.add_argument('--resource-runner', type=Path, required=True)
a = p.parse_args()
out = a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out == Path('/usr/obj') or a.trials < 3:
    p.error('fresh output below /usr/obj and at least three trials required')
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
checked_inputs = {}
def check(path, expected):
    path = path.resolve(strict=True)
    assert digest(path) == expected, 'action input changed: ' + str(path)
    if str(path) in checked_inputs:
        assert checked_inputs[str(path)] == expected
    checked_inputs[str(path)] = expected
    return str(path)

def load(root, mode):
    root = root.resolve(strict=True)
    receipt = json.loads((root / 'receipt.json').read_text())
    assert digest(root / 'execution.json') == receipt['execution_log_sha256']
    assert digest(root / 'artifacts/manifest.json') == receipt['artifacts']['sha256']
    manifest = json.loads((root / 'artifacts/manifest.json').read_text())
    uri = manifest['targets'][0]['outputs'][0]['uri']
    assert uri.startswith('file://')
    execroot = Path(uri[7:].split('/bazel-out/')[0])
    text = (root / 'execution.json').read_text()
    decoder = json.JSONDecoder(); index = 0; result = {}
    while index < len(text):
        while index < len(text) and text[index].isspace(): index += 1
        if index == len(text): break
        record, index = decoder.raw_decode(text, index)
        mnemonic = 'BSDDTraceObjects' if mode == 'baseline' else 'BSDDTraceArchiveMember'
        if record.get('mnemonic') != mnemonic or record.get('targetLabel') not in a.component:
            continue
        args = record['commandArgs']; inputs = {i['path']: i for i in record['inputs']}
        def resolve(relative):
            return check(execroot / relative, inputs[relative]['digest']['hash'])
        objects = []
        outputs = {}
        if mode == 'baseline':
            cursor = 1
            while args[cursor] == '--copy':
                objects.append(args[cursor + 1]); outputs[args[cursor + 2]] = 'objects/' + Path(args[cursor + 2]).name
                cursor += 3
            provider = args[args.index('-o') + 1]
            outputs[provider] = 'objects/' + Path(provider).name
        else:
            objects = [args[1]]
            outputs[args[2]] = 'objects/' + Path(args[2]).name
            for suffix in ['.dof.o', '.rewrite.o']:
                outputs[args[2] + suffix] = outputs[args[2]] + suffix
        kinds = {obj.endswith('.pic.o') for obj in objects}; assert len(kinds) == 1
        key = record['targetLabel'] + ('/pic' if kinds.pop() else '/regular')
        normalized = []
        for arg in args:
            if arg in outputs:
                normalized.append(outputs[arg])
            elif arg in inputs:
                normalized.append(resolve(arg))
            elif '=' in arg and arg.split('=', 1)[0] in ('cpppath', 'ldpath', 'objcopypath'):
                prefix, relative = arg.split('=', 1)
                normalized.append(prefix + '=' + resolve(relative))
            elif arg.startswith('syslibdir='):
                directory = arg.split('=', 1)[1]
                resolve(directory + '/drti.o')
                normalized.append('syslibdir=' + str(execroot / directory))
            else:
                normalized.append(arg)
        env = {'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'}
        for entry in record['environmentVariables']:
            if entry['name'] == 'LD_LIBRARY_PATH':
                dirs = entry['value'].split(':')
                env['LD_LIBRARY_PATH'] = ':'.join(str(execroot / d) for d in dirs)
                for name in inputs:
                    if str(Path(name).parent) in dirs:
                        resolve(name)
            else:
                env[entry['name']] = entry['value']
        item = {'argv': normalized, 'environment': env,
                'compiler_inputs': {obj: inputs[obj]['digest']['hash'] for obj in objects}}
        result.setdefault(key, []).append(item)
    for group in result.values(): group.sort(key=lambda x: sorted(x['compiler_inputs']))
    return result

graphs = {mode: load(getattr(a, mode), mode) for mode in ('baseline', 'candidate')}
assert graphs['baseline'].keys() == graphs['candidate'].keys()
assert len(graphs['baseline']) == 2 * len(set(a.component))
for key in graphs['baseline']:
    original = {k: v for item in graphs['baseline'][key] for k, v in item['compiler_inputs'].items()}
    candidate = {k: v for item in graphs['candidate'][key] for k, v in item['compiler_inputs'].items()}
    assert original == candidate, key
resource_runner = a.resource_runner.resolve(strict=True)
check(resource_runner, digest(resource_runner))
out.mkdir()
(out / 'normalized-actions.json').write_text(json.dumps(graphs, indent=2) + '\n')
results = []
for trial in range(a.trials):
    for number, key in enumerate(sorted(graphs['baseline'])):
        for mode in (('baseline', 'candidate') if trial % 2 == 0 else ('candidate', 'baseline')):
            directory = out / ('trial-%d-group-%d-%s' % (trial, number, mode))
            (directory / 'objects').mkdir(parents=True)
            actions = []
            for action_number, item in enumerate(graphs[mode][key]):
                log = directory / ('action-%d.log' % action_number)
                usage_path = directory / ('action-%d.resources.json' % action_number)
                with log.open('xb') as stream:
                    process = subprocess.run([str(resource_runner), str(usage_path), '--'] + item['argv'],
                        cwd=directory, env=item['environment'], stdout=stream, stderr=stream,
                        timeout=120)
                usage = json.loads(usage_path.read_text())
                assert process.returncode == usage['exit_status'], str(log)
                actions.append(usage)
                (directory / 'actions.json').write_text(json.dumps(actions, indent=2) + '\n')
                assert usage['exit_status'] == 0, str(log)
            files = [f for f in (directory / 'objects').iterdir() if f.is_file()]
            record = {'trial': trial, 'component': key, 'mode': mode,
                'wall_seconds': sum(x['wall_seconds'] for x in actions),
                'cpu_seconds': sum(x['user_seconds'] + x['system_seconds'] for x in actions),
                'maxrss_kib': max(x['maxrss_kib'] for x in actions),
                'block_inputs': sum(x['block_inputs'] for x in actions),
                'block_outputs': sum(x['block_outputs'] for x in actions),
                'logical_bytes': sum(f.stat().st_size for f in files),
                'allocated_bytes_observed': sum(f.stat().st_blocks * 512 for f in files),
                'files': {f.name: digest(f) for f in files}}
            results.append(record)
            (out / 'trials.json').write_text(json.dumps(results, indent=2) + '\n')
for path, expected in checked_inputs.items():
    assert digest(Path(path)) == expected, 'input changed during benchmark: ' + path
summary = {}
for key in sorted(graphs['baseline']):
    summary[key] = {}
    for mode in ('baseline', 'candidate'):
        rows = [r for r in results if r['component'] == key and r['mode'] == mode]
        # Output identities are relative and should not change across trial roots.
        assert all(r['files'] == rows[0]['files'] for r in rows)
        summary[key][mode] = {field: statistics.median(r[field] for r in rows)
            for field in ('wall_seconds', 'cpu_seconds', 'maxrss_kib', 'block_inputs', 'block_outputs', 'logical_bytes', 'allocated_bytes_observed')}
(out / 'receipt.json').write_text(json.dumps({'status': 'passed', 'scope': __doc__,
    'host': list(os.uname()), 'trials_per_variant': a.trials, 'inputs': checked_inputs,
    'summary': summary, 'limitations': ['Serial isolated transformation actions, not complete Bazel or Make builds.',
    'No cache flushing; cache state and concurrent host load uncontrolled.',
    'Peak RSS is the largest individual action process tree, not aggregate parallel build memory.',
    'Filesystem block-operation counters are not physical-device byte throughput.',
    'Observed st_blocks can lag allocation on ZFS; excludes temporary peak disk and filesystem metadata, and is not a final disk-space claim.',
    'DTrace live registration and runtime performance not measured.']}, indent=2) + '\n')
(out / 'verify.py').write_bytes(Path(__file__).read_bytes())
print(json.dumps(summary, indent=2))
