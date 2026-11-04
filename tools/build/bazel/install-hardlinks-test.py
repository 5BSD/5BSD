#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual Bazel installation analysis and BSD installer hardlink staging."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import bsd_toolchain
from execution_log import objects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('bazel', 'java-home', 'installer', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--repository-cache', type=Path, required=True)
    parser.add_argument('--distdir', type=Path, action='append', default=[])
    parser.add_argument('--skylib-version', required=True, help='explicit bazel_skylib module pin for copied install rules')
    parser.add_argument('--cache-roundtrip', action='store_true', help='require uncached physical-stage execution and hardlink identity with a configured disk cache and fresh output base')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9][A-Za-z0-9_.+-]*',args.skylib_version):
        parser.error('simple explicit Skylib module version required')
    source = Path(__file__).resolve().parent
    root = args.output.resolve()
    if root.exists() or not root.is_relative_to('/usr/obj'):
        raise ValueError('fresh output below /usr/obj required')
    root.mkdir(parents=True)
    workspace = root / 'workspace'
    workspace.mkdir()
    inputs = {str(Path(__file__)):bsd_toolchain.sha(Path(__file__)),
              str(source/'execution_log.py'):bsd_toolchain.sha(source/'execution_log.py'),
              str(source/'bsd_toolchain.py'):bsd_toolchain.sha(source/'bsd_toolchain.py')}
    lockfile=bsd_toolchain.PINNED_LOCKFILE
    inputs[str(lockfile)]=bsd_toolchain.sha(lockfile)
    shutil.copyfile(lockfile,workspace/'MODULE.bazel.lock')
    cache_before=bsd_toolchain.verify_repository_cache(args.repository_cache)
    staged_cache=bsd_toolchain.stage_repository_cache({'repository_cache':str(args.repository_cache)},root/'repository-cache')
    for name in ('bsd_install.bzl', 'bsd_kyua_metadata.bzl', 'bsd_stage.bzl'):
        path = source / name
        inputs[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        shutil.copyfile(path, workspace / name)
    module_pins=dict(bsd_toolchain.PINNED_MODULES,bazel_skylib=args.skylib_version)
    bsd_toolchain.write_workspace(workspace,'install_links_test',{'modules':module_pins,'lockfile':str(lockfile)},staged_toolchain=False)
    (workspace / 'payload').write_text('hardlink qualification payload\n')
    (workspace / 'tools').mkdir()
    shutil.copy2(args.installer, workspace / 'tools/installer')
    shutil.copy2('/bin/sh', workspace / 'tools/shell')
    env = dict(os.environ, JAVA_HOME=str(args.java_home), LC_ALL='C')
    for tool in [args.bazel,args.installer,Path('/bin/sh')]:
        inputs[str(tool.resolve(strict=True))]=bsd_toolchain.sha(tool)
    results = []
    metadata = dict(owner='root', group='wheel', mode='444', install_tags=['package=test'])

    def run(name, links, error=None):
        lines = ['load(":bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")',
                 'load(":bsd_stage.bzl", "bsd_stage")']
        def rule(rule_name, **attrs):
            lines.append(rule_name + '(' + ', '.join(k+'='+repr(v) for k,v in attrs.items()) + ')')
        rule('bsd_install_file', name='regular', src='payload', destination='/z', **metadata)
        entries = [':regular']
        for index, (destination, target, kind, overrides) in enumerate(links):
            label = 'link_' + str(index)
            rule('bsd_install_link', name=label, destination=destination, target=target,
                 kind=kind, **dict(metadata, **overrides))
            entries.append(':' + label)
        rule('bsd_install_manifest', name='manifest', entries=entries)
        rule('bsd_stage', name='stage', manifests=[':manifest'], installer='tools/installer', shell='tools/shell',
             directories={'/':json.dumps(dict(type='dir',uname='root',gname='wheel',mode='755'))})
        (workspace / 'BUILD.bazel').write_text('\n'.join(lines)+'\n')
        argv = [str(args.bazel), '--batch', '--ignore_all_rc_files',
                '--output_user_root='+str(root/'bazel-user-root'), 'build',
                '--incompatible_autoload_externally=', '--repository_disable_download',
                '--repository_cache='+str(staged_cache), '--lockfile_mode=error',
                '--execution_log_json_file='+str(root/(name+'.execution.json')),
                *['--distdir='+str(p) for p in args.distdir],
                '--jobs='+str(os.cpu_count()), '//:stage', '//:manifest']
        if args.cache_roundtrip:
            argv.insert(-2, '--disk_cache=' + str(root / 'disk-cache'))
        with (root/(name+'.log')).open('w') as log:
            result = subprocess.run(argv, cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT)
        text = (root/(name+'.log')).read_text()
        if error is not None:
            if result.returncode == 0 or error not in text:
                raise AssertionError(name + ': expected analysis rejection: ' + error)
        else:
            if result.returncode:
                raise AssertionError(name + ': Bazel staging failed')
            stage = workspace / 'bazel-bin/stage.root'
            for destination, target, kind, overrides in links:
                if kind == 'hardlink':
                    assert (stage/destination[1:]).samefile(stage/target[1:])
            manifest = json.loads((workspace/'bazel-bin/manifest.json').read_text())
            declared = {v['destination']:v for v in manifest['files']}
            for destination, target, kind, overrides in links:
                assert declared[destination]['link'] == target
            assert (stage/'z').read_bytes() == (workspace/'payload').read_bytes()
        results.append(dict(name=name, status='passed', exit_status=result.returncode,
                            expected_error=error, argv=argv))
        (root/'results.json').write_text(json.dumps(results,indent=2)+'\n')
        if args.cache_roundtrip and error is None:
            # A different output base forces restoration without deleting or
            # mutating the producer's output tree. No host installation occurs.
            restored_argv = [('--output_user_root=' + str(root / 'restored-user-root'))
                             if arg.startswith('--output_user_root=') else ('--execution_log_json_file='+str(root/(name+'-cache-restore.execution.json')) if arg.startswith('--execution_log_json_file=') else arg) for arg in argv]
            with (root / (name + '-cache-restore.log')).open('w') as log:
                restored = subprocess.run(restored_argv, cwd=workspace, env=env,
                                          stdout=log, stderr=subprocess.STDOUT)
            if restored.returncode:
                raise AssertionError(name + ': cache restoration build failed')
            stage = workspace / 'bazel-bin/stage.root'
            observations = []
            for destination, target, kind, overrides in links:
                if kind == 'hardlink':
                    observations.append(dict(destination=destination, target=target,
                        same_inode=(stage/destination[1:]).samefile(stage/target[1:])))
            restore_log = (root / (name + '-cache-restore.log')).read_text()
            stage_actions=[action for action in objects(root/(name+'-cache-restore.execution.json')) if action['mnemonic']=='BSDStageInstall']
            if len(stage_actions)!=1 or stage_actions[0].get('cacheHit') or stage_actions[0].get('exitCode')!=0:
                raise AssertionError(name + ': physical installation must execute instead of restoring a directory artifact')
            evidence=dict(argv=restored_argv,disk_cache_configured=True,stage_executed=True,
                stage_cache_hit=False,links=observations,
                scope='uncached physical materialization under CAS; canonical archive restoration is a separate test',
                status='passed' if all(x['same_inode'] for x in observations) else 'failed')
            (root/(name+'-cache-restore.json')).write_text(json.dumps(evidence,indent=2)+'\n')
            if evidence['status']!='passed':
                raise AssertionError(name + ': physical materialization lost hardlink identity')

    run('chain', [('/a','/b','hardlink',{}),('/b','/z','hardlink',{}),('/c','/b','hardlink',{})])
    run('cycle', [('/a','/b','hardlink',{}),('/b','/a','hardlink',{})], 'hardlink cycle:')
    run('self', [('/a','/a','hardlink',{})], 'hardlink cycle:')
    run('missing', [('/a','/absent','hardlink',{})], 'hardlink must reference a regular payload file or hardlink:')
    run('symlink', [('/a','/b','hardlink',{}),('/b','z','symlink',{})], 'hardlink must reference a regular payload file or hardlink:')
    run('mode', [('/a','/b','hardlink',{'mode':'600'}),('/b','/z','hardlink',{})], 'hardlink inode metadata differs:')
    assert bsd_toolchain.verify_repository_cache(args.repository_cache)==cache_before
    for path, sha in inputs.items():
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == sha
    (root/'receipt.json').write_text(json.dumps(dict(status='passed', scope='native Bazel hardlink analysis and uncached private physical materialization; no canonical archive cache claim', results=results, module_pins=module_pins, module_sha256=bsd_toolchain.sha(workspace/'MODULE.bazel'), input_sha256=inputs, host_installed=False),indent=2)+'\n')
    print(root/'receipt.json')


if __name__ == '__main__':
    main()
