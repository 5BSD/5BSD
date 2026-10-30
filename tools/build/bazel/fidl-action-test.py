#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify input invalidation in a private, prepared FIDL Bazel workspace.

Cases are explicit JSON inputs: name, path (workspace-relative), old, new,
success (default true), required_actions and forbidden_actions. Each mutation
is restored before the next case. This does not prepare a graph or SDK.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess


def entries(path):
    text = path.read_text()
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        entry, offset = decoder.raw_decode(text, offset)
        yield entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('workspace', 'command', 'cases', 'java-home', 'output'):
        parser.add_argument('--' + key, required=True, type=Path)
    parser.add_argument('--test-label', action='append', required=True, help='exact expected Bazel test labels')
    args = parser.parse_args()
    workspace = args.workspace.resolve(strict=True)
    output = args.output.resolve()
    if not workspace.is_relative_to('/usr/obj'):
        parser.error('private workspace below /usr/obj required')
    if output.exists() or not output.is_relative_to('/usr/obj') or output.is_relative_to(workspace):
        parser.error('fresh output below /usr/obj outside workspace required')
    argv = json.loads(args.command.read_text())['argv']
    if 'test' not in argv:
        parser.error('explicit Bazel test command required')
    argv = [arg for arg in argv if not arg.startswith(('--execution_log_json_file=', '--build_event_json_file='))]
    cases = json.loads(args.cases.read_text())
    if not isinstance(cases, list) or not cases:
        parser.error('nonempty case list required')
    prepared = []
    names = {'baseline', 'noop'}
    for case in cases:
        name = case['name']
        if not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in name) or name in names or name + '-restored' in names:
            parser.error('unique simple case names required')
        names.update((name, name + '-restored'))
        path = (workspace / case['path']).resolve(strict=True)
        if not path.is_relative_to(workspace) or path.stat().st_nlink != 1:
            parser.error('mutation requires private workspace file, not external symlink or hardlink')
        original = path.read_bytes()
        old, new = case['old'].encode(), case['new'].encode()
        if not old or old == new or original.count(old) != 1:
            parser.error('each case must replace one unique nonempty input sequence')
        prepared.append((case, path, original, original.replace(old, new)))
    output.mkdir(parents=True)
    (output / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
    env = dict(os.environ, JAVA_HOME=str(args.java_home.resolve(strict=True)), BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1')
    records = []

    def run(name, success=True, required=(), forbidden=()):
        log = output / (name + '.execution.json')
        command = argv + ['--execution_log_json_file=' + str(log), '--build_event_json_file=' + str(output / (name + '.events.json'))]
        with (output / (name + '.stdout')).open('w') as stdout, (output / (name + '.stderr')).open('w') as stderr:
            result = subprocess.run(['/usr/bin/time', '-l', *command], cwd=workspace, env=env, stdout=stdout, stderr=stderr)
        counts = collections.Counter(e.get('mnemonic') for e in entries(log) if not e.get('cacheHit', False)) if log.exists() else {}
        records.append(dict(name=name, argv=command, exit_status=result.returncode, executed=dict(counts)))
        (output / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        if success != (result.returncode == 0):
            raise RuntimeError(name + ': unexpected exit status')
        if success:
            tests = {}
            for line in (output / (name + '.events.json')).read_text().splitlines():
                event = json.loads(line)
                if 'testSummary' in event:
                    tests[event['id']['testSummary']['label']] = event['testSummary']['overallStatus']
            if set(tests) != set(args.test_label) or set(tests.values()) != {'PASSED'}:
                raise RuntimeError(name + ': expected test inventory/status mismatch')
        for mnemonic in required:
            if not counts.get(mnemonic, 0):
                raise RuntimeError(name + ': action did not execute: ' + mnemonic)
        for mnemonic in forbidden:
            if counts.get(mnemonic, 0):
                raise RuntimeError(name + ': unexpected action: ' + mnemonic)

    run('baseline')
    run('noop', forbidden=['BSDFidlCompile', 'BSDFidlBindings', 'CppCompile', 'CppLink', 'BSDNativeArchive'])
    for case, path, original, changed in prepared:
        try:
            path.write_bytes(changed)
            run(case['name'], case.get('success', True), case.get('required_actions', []), case.get('forbidden_actions', []))
        finally:
            path.write_bytes(original)
        run(case['name'] + '-restored')
        if path.read_bytes() != original:
            raise RuntimeError('restoration mismatch: ' + str(path))
    receipt = dict(runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), test_labels=args.test_label, status='passed', scope='prepared FIDL graph input invalidation and recovery', records=records,
                   inputs=[dict(path=c['path'], original_sha256=hashlib.sha256(o).hexdigest()) for c, p, o, n in prepared],
                   limitations=['No full library or channel runtime qualification.', 'No clean build, remote cache or cross-workspace equivalence claim.'])
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('PASS:', len(cases), 'FIDL input cases, no-op and restoration')


if __name__ == '__main__':
    main()
