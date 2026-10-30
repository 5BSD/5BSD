#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual Bazel installation analysis and BSD installer hardlink staging."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('bazel', 'java-home', 'installer', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--repository-cache', type=Path, required=True)
    parser.add_argument('--distdir', type=Path, action='append', required=True)
    parser.add_argument('--cache-roundtrip', action='store_true', help='also require hardlink identity after disk-cache restoration into a fresh output base')
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    root = args.output.resolve()
    if root.exists() or not root.is_relative_to('/usr/obj'):
        raise ValueError('fresh output below /usr/obj required')
    root.mkdir(parents=True)
    workspace = root / 'workspace'
    workspace.mkdir()
    inputs = {}
    for name in ('bsd_install.bzl', 'bsd_kyua_metadata.bzl', 'bsd_stage.bzl'):
        path = source / name
        inputs[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        shutil.copyfile(path, workspace / name)
    (workspace / 'MODULE.bazel').write_text('module(name="install_links_test")\n')
    (workspace / 'payload').write_text('hardlink qualification payload\n')
    (workspace / 'tools').mkdir()
    shutil.copy2(args.installer, workspace / 'tools/installer')
    shutil.copy2('/bin/sh', workspace / 'tools/shell')
    env = dict(os.environ, JAVA_HOME=str(args.java_home), LC_ALL='C')
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
                '--repository_cache='+str(args.repository_cache),
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
                             if arg.startswith('--output_user_root=') else arg for arg in argv]
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
            if 'disk cache hit' not in restore_log:
                raise AssertionError(name + ': no disk-cache restoration was observed')
            evidence = dict(argv=restored_argv, disk_cache_hit=True, links=observations,
                            status='passed' if all(x['same_inode'] for x in observations) else 'failed')
            (root / (name + '-cache-restore.json')).write_text(json.dumps(evidence, indent=2) + '\n')
            if evidence['status'] != 'passed':
                raise AssertionError(name + ': disk-cache restoration lost hardlink identity')

    run('chain', [('/a','/b','hardlink',{}),('/b','/z','hardlink',{}),('/c','/b','hardlink',{})])
    run('cycle', [('/a','/b','hardlink',{}),('/b','/a','hardlink',{})], 'hardlink cycle:')
    run('self', [('/a','/a','hardlink',{})], 'hardlink cycle:')
    run('missing', [('/a','/absent','hardlink',{})], 'hardlink must reference a regular payload file or hardlink:')
    run('symlink', [('/a','/b','hardlink',{}),('/b','z','symlink',{})], 'hardlink must reference a regular payload file or hardlink:')
    run('mode', [('/a','/b','hardlink',{'mode':'600'}),('/b','/z','hardlink',{})], 'hardlink inode metadata differs:')
    for path, sha in inputs.items():
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == sha
    (root/'receipt.json').write_text(json.dumps(dict(status='passed', scope='native Bazel hardlink analysis and private staging', results=results, input_sha256=inputs, host_installed=False),indent=2)+'\n')
    print(root/'receipt.json')


if __name__ == '__main__':
    main()
