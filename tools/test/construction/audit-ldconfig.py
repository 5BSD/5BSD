#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Audit whether ldconfig alone provides strict generation construction semantics.

Only writes a fresh private work directory. A failed strict-construction gate
is not a claim that ordinary ldconfig's documented tolerant behavior is a bug.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def directories(path):
    data = path.read_bytes()
    if len(data) < 128:
        raise ValueError('truncated hints header')
    endian = '<' if struct.unpack('<I', data[:4])[0] == 0x746e6845 else '>'
    magic, version, table, size, offset, length = struct.unpack(endian + '6I', data[:24])
    if (magic != 0x746e6845 or version != 1 or table < 128 or
            table + size != len(data) or offset + length + 1 > size):
        raise ValueError('invalid hints bounds or format')
    value = data[table + offset:table + offset + length + 1]
    if not value.endswith(b'\0') or b'\0' in value[:-1]:
        raise ValueError('invalid hints directory string')
    return value[:-1].decode().split(':') if length else []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ldconfig', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True,
                        help='existing root-owned library directory, read only during this audit')
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--strict', action='store_true', help='exercise explicit -S mode')
    args = parser.parse_args()
    tool, directory = args.ldconfig.resolve(strict=True), args.directory.resolve(strict=True)
    if not tool.is_file() or not directory.is_dir():
        parser.error('requires executable file and existing directory')
    work = args.work.absolute()
    work.mkdir(mode=0o700, parents=False, exist_ok=False)
    tool_hash = digest(tool)
    options = ['-elf', '-S'] if args.strict else ['-elf']
    report = dict(result='RUNNING', scope='strict library-hints construction audit',
                  tool=str(tool), tool_sha256=tool_hash, directory=str(directory),
                  runtime_bip_tested=False, cases=[])
    try:
        baseline = work / 'baseline.hints'
        command = [str(tool), *options, '-f', str(baseline), str(directory)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode != 0 or directories(baseline) != [str(directory)]:
            raise ValueError('positive control failed: ' + result.stderr)
        report['cases'].append(dict(name='valid-directory', command=command,
            exit_code=result.returncode, result='PASS', directories=directories(baseline)))
        missing = work / 'absent-library-directory'
        cases = [('missing-only', [missing]), ('valid-and-missing', [directory, missing])]
        if args.strict:
            alias = work / 'alias'; alias.symlink_to(directory)
            listing = work / 'list'; listing.write_text(str(directory) + '\n')
            writable = work / 'writable'; writable.mkdir(); writable.chmod(0o777)
            cases.extend([('writable-directory', [writable]), ('symlink', [alias]), ('directory-list', [listing]),
                          ('duplicate', [directory, directory]),
                          ('relative', ['.']), ('insecure-option', ['-i', directory]),
                          ('merge-option', ['-m', directory]), ('no-directory', [])])
        for name, paths in cases:
            target = work / (name + '.hints')
            target.write_bytes(baseline.read_bytes())
            before = digest(target)
            command = [str(tool), *options, '-f', str(target), *map(str, paths)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            preserved = target.is_file() and digest(target) == before
            report['cases'].append(dict(name=name, command=command,
                exit_code=result.returncode, stderr=result.stderr,
                previous_output_preserved=preserved,
                directories=directories(target) if target.is_file() else None,
                result='PASS' if result.returncode > 0 and preserved else 'FAIL'))
        if digest(tool) != tool_hash:
            raise ValueError('generator changed during audit')
        report['result'] = 'PASS' if all(c['result'] == 'PASS' for c in report['cases']) else 'FAIL'
    except BaseException as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
