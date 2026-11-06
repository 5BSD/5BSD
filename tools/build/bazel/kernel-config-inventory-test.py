#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare config's selected-input API with independently expanded Make OBJS.

This migration qualification invokes Make only as an independent oracle.
Native kernel configuration and linking must never use this discovery path.
The caller supplies a fresh output directory; all commands and failures remain.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--make', default='/usr/bin/make')
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    tool = args.config.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(argv, cwd, success=True):
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
        commands.append(dict(argv=argv, cwd=str(cwd), status=result.returncode,
                             stdout=result.stdout, stderr=result.stderr))
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        assert (result.returncode == 0) == success, commands[-1]
        return result.stdout

    cases = []
    for arch in ('amd64', 'arm64', 'riscv'):
        conf = source / 'sys' / arch / 'conf'
        for disabled in ((), ('ZSTDIO',), ('NFS_ROOT',), ('ZSTDIO', 'NFS_ROOT'), ('TCP_HHOOK',)):
            name = arch + '-' + ('-'.join(disabled) if disabled else 'default')
            dest = out / name
            dest.mkdir()
            config = out / (name + '.conf')
            config.write_text('include "GENERIC"\n' + ''.join(
                'nooptions ' + option + '\n' for option in disabled))
            argv = [str(tool), '-g', '-d', str(dest), '-s', str(source / 'sys'),
                    '-I', str(conf), str(config)]
            run(argv, conf)
            original = {p.name: digest(p) for p in dest.iterdir() if p.is_file()}
            assert 'kernel-inputs.json' not in original
            run([str(tool), '-J', *argv[1:]], conf)
            assert all(digest(dest / name) == sha for name, sha in original.items())
            manifest_path = dest / 'kernel-inputs.json'
            manifest = json.loads(manifest_path.read_text())
            assert manifest['format'] == 1
            assert manifest['machine'] == arch
            assert manifest['kernel_identity'] == 'GENERIC'
            assert manifest['machine_arch'] == {
                'amd64': 'amd64', 'arm64': 'aarch64', 'riscv': 'riscv64'}[arch]
            entries = manifest['inputs']
            assert entries and all(e['origin'] in ('kernel', 'generated') for e in entries)
            assert all(bool(e['flags'] & 2) == (e['object'] is None) for e in entries)
            objects = [e['object'] for e in entries if e['object'] is not None]
            assert len(objects) == len(set(objects))
            query = [args.make, '-C', str(dest), '-m', str(source / 'share/mk'),
                     'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
                     'SRC_ENV_CONF=/dev/null', '-V', '${OBJS}']
            expected = run(query, source).split()
            assert objects == expected, name + ': resolved object order differs from Make'
            before = (digest(manifest_path), manifest_path.stat().st_mtime_ns)
            run([str(tool), '-J', *argv[1:]], conf)
            assert before == (digest(manifest_path), manifest_path.stat().st_mtime_ns)
            cases.append(dict(case=name, objects=len(objects), inputs=len(entries),
                              manifest_sha256=digest(manifest_path)))
    # Exercise public files extensions and JSON escaping with parser-owned text.
    custom = out / 'custom'
    custom.mkdir()
    recipe = 'printf "quoted" ' + chr(92) + 'q' + chr(9) + 'argument'
    depends = 'dep' + chr(92) + 'path' + chr(9) + 'other'
    files = out / 'custom.files'
    files.write_text("inventory_fixture.c standard local obj-prefix \"fixture_\" "
                     + "compile-with '" + recipe + "' dependency '" + depends + "'\n"
                     + 'inventory_fixture.h standard local no-obj\n')
    config = out / 'custom.conf'
    config.write_text('include "GENERIC"\nfiles "' + str(files) + '"\n')
    argv = [str(tool), '-J', '-d', str(custom), '-s', str(source / 'sys'),
            '-I', str(source / 'sys/amd64/conf'), str(config)]
    run(argv, source / 'sys/amd64/conf')
    entries = json.loads((custom / 'kernel-inputs.json').read_text())['inputs']
    row, header = entries[-2:]
    assert row == dict(source='inventory_fixture.c', origin='generated',
                       object='fixture_inventory_fixture.o', flags=0,
                       compile_with=recipe, depends=depends), row
    assert header['object'] is None and header['origin'] == 'generated'
    # Failed writes must stop generation rather than returning a valid receipt.
    (custom / 'kernel-inputs.json.new').mkdir()
    run(argv, source / 'sys/amd64/conf', False)
    assert 'kernel-inputs.json.new' in commands[-1]['stderr']
    for option in (['-i'], ['-m'], ['-x', '/nonexistent-config-test-kernel']):
        run([str(tool), '-J', *option, 'GENERIC'], source / 'sys/amd64/conf', False)
        assert '-J requires configuration file generation' in commands[-1]['stderr']
    (out / 'receipt.json').write_text(json.dumps(dict(
        status='passed', cases=cases, config_sha256=digest(tool),
        test_sha256=digest(Path(__file__)),
        scope='Parser inventory order, no-obj metadata, option selection, unchanged ordinary outputs, deterministic writes and incompatible modes; no kernel build or runtime claim.'), indent=2) + '\n')
    print(json.dumps(cases))


if __name__ == '__main__':
    main()
