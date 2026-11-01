#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise directory-entry type invalidation through Bazel repository rules.

Usage: bazel-dirent-invalidation-test.py --bazel PATH --output-root DIR
       --java-home DIR [--goroot DIR]
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bazel', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--goroot', type=Path)
    args = parser.parse_args()
    args.output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='bazel-dirent-', dir=args.output_root) as tmp:
        root = Path(tmp) / 'workspace'
        watched, targets = root / 'watched', root / 'targets'
        watched.mkdir(parents=True)
        targets.mkdir()
        source = watched / 'entry'
        source.write_text('same directory-entry name\n')
        target_dir = targets / 'directory-target'
        target_dir.mkdir()
        (target_dir / 'inside').write_text('target\n')
        target_file = targets / 'file-target'
        target_file.write_text('target\n')
        (root / 'MODULE.bazel').write_text('''module(name = "dirent_invalidation_test")
watch_repo = use_repo_rule("//:watch_repo.bzl", "watch_repo")
watch_repo(name = "watched", directory = %s)
''' % json.dumps(str(watched)))
        (root / 'BUILD.bazel').write_text('exports_files(["README"])\n')
        (root / 'README').write_text('entry type invalidation integration test\n')
        (root / 'watch_repo.bzl').write_text('''def _impl(ctx):
    directory = ctx.path(ctx.attr.directory)
    entries = directory.readdir(watch = "yes")
    rows = [{"name": e.basename, "is_dir": e.is_dir, "realpath": str(e.realpath)} for e in entries]
    ctx.file("inventory.json", json.encode(rows) + "\\n")
    ctx.file("BUILD.bazel", 'exports_files(["inventory.json"])\\n')
watch_repo = repository_rule(implementation = _impl, attrs = {"directory": attr.string(mandatory = True)})
''')
        env = dict(os.environ, JAVA_HOME=str(args.java_home), LC_ALL='C')
        if args.goroot:
            env['GOROOT'] = str(args.goroot)
        output_user_root = args.output_root / 'bazel-output-user-root'
        command = [str(args.bazel), '--output_user_root=' + str(output_user_root),
                   'build', '@watched//:inventory.json']
        output_base = None
        stages = []

        def build(label):
            start = time.monotonic()
            result = subprocess.run(command, cwd=root, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=180)
            if result.returncode:
                raise RuntimeError(label + ' failed (exit %d):\n%s' %
                                   (result.returncode, result.stdout[-12000:]))
            stages.append({"stage": label, "elapsed_seconds": time.monotonic() - start})
            nonlocal output_base
            if output_base is None:
                info = subprocess.run([str(args.bazel), '--output_user_root=' + str(output_user_root),
                                       'info', 'output_base'], cwd=root, env=env, text=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=180)
                output_base = Path(info.stdout.strip())
            inventories = list((output_base / 'external').glob('*/inventory.json'))
            if len(inventories) != 1:
                raise AssertionError('expected one generated repository inventory, found: ' +
                                     repr([str(path) for path in inventories]))
            inventory = inventories[0]
            return json.loads(inventory.read_text())

        def verify(label, expected_dir, expected_realpath):
            rows = build(label)
            assert len(rows) == 1 and rows[0]['name'] == 'entry', (label, rows)
            assert rows[0]['is_dir'] is expected_dir, (label, rows)
            assert rows[0]['realpath'] == str(expected_realpath), (label, rows)
            return rows

        try:
            verify('regular-file', False, source)
            source.unlink()
            source.mkdir()
            (source / 'inside').write_text('directory\n')
            verify('file-to-directory', True, source)
            (source / 'inside').unlink()
            source.rmdir()
            source.symlink_to(target_dir, target_is_directory=True)
            verify('directory-to-symlink', True, target_dir)
            source.unlink()
            source.write_text('same directory-entry name\n')
            verify('symlink-to-file', False, source)
            source.unlink()
            source.symlink_to(target_file)
            verify('file-to-symlink', False, target_file)
            report = {"bazel_version": subprocess.check_output([str(args.bazel), '--version'], text=True).strip(),
                      "command": command, "stages": stages,
                      "scope": "Same-name directory-entry type transitions; no compilation, installer execution or system installation"}
            report['result'] = 'PASS'
            report_path = args.output_root / 'result.json'
            report_path.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2))
        finally:
            subprocess.run([str(args.bazel), '--output_user_root=' + str(output_user_root), 'shutdown'],
                           cwd=root, env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=60, check=False)


if __name__ == '__main__':
    main()
