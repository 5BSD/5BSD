#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Mutate one disposable textual C input and check native incremental action scope.

Always restores the source, then rebuilds the original graph. This exercises the
local action cache only; it is not remote-cache or hermeticity qualification.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from libmd_environment import digest

spec = importlib.util.spec_from_file_location('action_reader', Path(__file__).with_name('textual-inputs-check.py'))
action_reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(action_reader)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'plan', 'build-command', 'java-home', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--artifact', type=Path, action='append', required=True)
    parser.add_argument('--component', required=True)
    parser.add_argument('--textual-source', required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve(strict=True); out = args.output.resolve()
    if not workspace.is_relative_to('/usr/obj') or out.exists() or not out.is_relative_to('/usr/obj') or out == Path('/usr/obj'):
        raise ValueError('disposable workspace and fresh output below /usr/obj required')
    plan = json.loads(args.plan.read_text())
    selected = [c for c in plan['components'] if c['component'] == args.component]
    if len(selected) != 1:
        raise ValueError('one selected component required')
    affected = {}; hashes = set()
    for record in selected[0]['sources']:
        entries = [entry for entry in record['textual_inputs'] if entry['path'] == args.textual_source]
        primary = record.get('path') == args.textual_source and record['resolution'] == 'source'
        if primary:
            hashes.add(record['sha256'])
        if entries or primary:
            if record['resolution'] != 'source':
                raise ValueError('this incremental test requires source-tree consumers')
            affected['sources/' + record['path']] = len(record['compile_contexts'])
            hashes.update(entry['sha256'] for entry in entries)
    source = workspace/'sources'/args.textual_source
    if not affected or len(hashes) != 1 or not source.resolve(strict=True).is_relative_to(workspace) or digest(source) not in hashes:
        raise ValueError('textual input is not the hash-bound emitted source')
    command = json.loads(args.build_command.read_text())['argv']
    if 'test' not in command or not any(value.startswith('--jobs=') for value in command):
        raise ValueError('recorded native test command with explicit parallelism required')
    env = dict(os.environ, JAVA_HOME=str(args.java_home.resolve(strict=True)), BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1')
    for key in ('LD_LIBRARY_PATH', 'LD_PRELOAD'):env.pop(key, None)
    artifacts={str(path.resolve(strict=True)):digest(path) for path in args.artifact}
    out.mkdir(); original = source.read_bytes()
    def run(phase):
        argv = [('--build_event_json_file='+str(out/(phase+'.events.json')) if value.startswith('--build_event_json_file=') else
                 '--execution_log_json_file='+str(out/(phase+'.execution.json')) if value.startswith('--execution_log_json_file=') else value) for value in command]
        with (out/(phase+'.stdout')).open('w') as stdout, (out/(phase+'.stderr')).open('w') as stderr:
            done = subprocess.run(['/usr/bin/time', '-l', *argv], cwd=workspace, env=env, stdout=stdout, stderr=stderr)
        (out/(phase+'.command.json')).write_text(json.dumps(dict(argv=argv, exit_code=done.returncode), indent=2)+'\n')
        return done.returncode
    try:
        source.write_bytes(b'/* Native textual-input incremental qualification. */\n'+original)
        mutated = run('mutated')
        mutated_artifacts={path:digest(Path(path)) for path in artifacts}
    finally:
        source.write_bytes(original)
    restored = run('restored')
    if mutated or restored or digest(source) not in hashes:
        raise ValueError('mutation or restored native tests failed')
    if mutated_artifacts==artifacts:
        raise ValueError('mutation did not change any selected artifact')
    for path,sha in artifacts.items():
        if digest(Path(path))!=sha:
            (out/'FAILED.json').write_text(json.dumps(dict(status='failed',reason='artifact bytes not restored',artifact=path,expected=sha,actual=digest(Path(path))),indent=2)+'\n')
            raise ValueError('artifact bytes not restored: '+path)
    actual = {}
    for action in action_reader.actions(out/'mutated.execution.json'):
        if action.get('mnemonic') != 'CppCompile' or action.get('cacheHit'):
            continue
        argv = action['commandArgs']; value = argv[argv.index('-c')+1]
        actual[value] = actual.get(value, 0)+1
    if actual != affected:
        raise ValueError('unexpected incremental compile actions: '+repr(actual))
    (out/'receipt.json').write_text(json.dumps(dict(status='passed', scope=__doc__,
        plan_sha256=digest(args.plan), textual_source=args.textual_source,
        original_sha256=digest(source), affected_compile_actions=actual,
        original_graph_rebuilt=True,restored_artifact_sha256=artifacts,mutated_artifact_sha256=mutated_artifacts, driver_sha256=digest(Path(__file__))), indent=2)+'\n')
    print('PASS: exact affected compile actions and restored native tests')


if __name__ == '__main__':
    main()
