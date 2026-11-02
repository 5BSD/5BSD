#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check native kernel staging against an independent Make install inventory.

The Make build must use the same declared compiler filename/config/version
inputs. ELF payloads use strict controlled kernel parity and separate debug CRC
checks; ordinary scripts must match bytes. No host installation or tar extraction.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import shlex
import stat
import tarfile


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('archive', 'manifest', 'make-stage', 'make-metalog', 'source-root', 'output'):
        parser.add_argument('--' + key, required=True, type=Path)
    parser.add_argument('--kernel-path', required=True)
    parser.add_argument('--debug-path', required=True)
    parser.add_argument('--epoch', required=True, type=int)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = args.source_root.resolve(strict=True)
    stage = args.make_stage.resolve(strict=True)
    parity = load('kernel_parity', 'elf-kernel-parity-test.py')
    debug_check = load('kernel_debug', 'elf-debug-check.py')
    manifest = json.loads(args.manifest.read_text())
    assert manifest['format'] == 1
    records = {r['destination'].lstrip('/'): r for r in manifest['files']}
    assert len(records) == len(manifest['files'])
    declared_files = {p: r for p, r in records.items() if r['type'] == 'file'}
    expected_files = {p.relative_to(stage).as_posix(): p for p in stage.rglob('*') if p.is_file()}
    assert set(declared_files) == set(expected_files), 'native/Make file inventory differs'
    metadata = {}
    for line in args.make_metalog.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        path, *fields = shlex.split(line)
        assert path.startswith('./')
        metadata[path[2:]] = dict(field.split('=', 1) for field in fields)
    uid = {s.split(':')[0]: int(s.split(':')[2]) for s in (source / 'etc/master.passwd').read_text().splitlines() if s and not s.startswith('#')}
    gid = {s.split(':')[0]: int(s.split(':')[2]) for s in (source / 'etc/group').read_text().splitlines() if s and not s.startswith('#')}
    needed_dirs = {'.'}
    for path in expected_files:
        needed_dirs.update(str(p) for p in PurePosixPath(path).parents)
    kernel_name, debug_name = args.kernel_path.lstrip('/'), args.debug_path.lstrip('/')
    assert kernel_name in expected_files and debug_name in expected_files
    native_files = {}
    with tarfile.open(args.archive) as archive:
        members = archive.getmembers()
        table = {m.name: m for m in members}
        assert len(table) == len(members), 'duplicate archive member'
        assert {m.name for m in members if m.isfile()} == set(expected_files)
        assert {m.name for m in members if m.isdir()} == needed_dirs
        assert all(m.isdir() or m.isfile() for m in members)
        for member in members:
            assert not member.name.startswith('/') and '..' not in PurePosixPath(member.name).parts
            assert member.uid == uid[member.uname] and member.gid == gid[member.gname]
            assert member.mtime == args.epoch
            assert member.pax_headers.get('SCHILY.fflags', '') in ('', 'none')
            if member.name in metadata:
                expected = metadata[member.name]
                assert member.uname == expected['uname'] and member.gname == expected['gname']
                assert member.mode == int(expected['mode'], 8)
            if member.name in records:
                record = records[member.name]
                assert member.uname == record['owner'] and member.gname == record['group']
                assert member.mode == int(record['mode'], 8)
            if member.isdir():
                assert member.mode == stat.S_IMODE((stage / member.name).stat().st_mode)
            if member.isfile():
                with archive.extractfile(member) as file:
                    data = file.read()
                native_files[member.name] = data
                if member.name not in (kernel_name, debug_name):
                    assert data == expected_files[member.name].read_bytes(), member.name
    kernel, debug = out / PurePosixPath(kernel_name).name, out / PurePosixPath(debug_name).name
    kernel.write_bytes(native_files[kernel_name])
    debug.write_bytes(native_files[debug_name])
    comparison = parity.compare(parity.read_elf(kernel), parity.read_elf(expected_files[kernel_name]))
    own_debug = debug_check.verify(kernel, debug, kernel=True)
    make_debug = debug_check.verify(expected_files[kernel_name], expected_files[debug_name], kernel=True)
    receipts = {path: hashlib.sha256(data).hexdigest() for path, data in native_files.items()}
    (out / 'receipt.json').write_text(json.dumps(dict(status='passed', files=receipts,
        native_kernel_parity=comparison, native_debug=own_debug, make_debug=make_debug,
        metadata_entries=len(metadata), archive_sha256=hashlib.sha256(args.archive.read_bytes()).hexdigest(),
        manifest_sha256=hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        epoch=args.epoch, scope='Exact file inventory, script bytes, modes/named/numeric owners, source-policy ancestors, explicit epoch and controlled kernel/debug artifact checks; no host install or pkgbase creation.'), indent=2) + '\n')
    print('Kernel staging matches Make file inventory, scripts, ownership/modes and controlled ELF/debug contracts')


if __name__ == '__main__':
    main()
