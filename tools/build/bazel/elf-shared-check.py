#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare bounded shared-object metadata with an explicit maintained-Make artifact."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def parse(text):
    def field(label):
        values = re.findall(r'^\s*' + re.escape(label) + r':\s*(.+)$', text, re.M)
        if len(values) != 1:
            raise ValueError('missing or ambiguous ELF field: ' + label)
        return values[0].strip()

    needed = re.findall(r'\(NEEDED\)[^\n]*\[([^\]]+)\]', text)
    sonames = re.findall(r'\(SONAME\)[^\n]*\[([^\]]+)\]', text)
    if len(sonames) != 1 or len(needed) != len(set(needed)):
        raise ValueError('ambiguous shared-library identity/dependencies')
    stack = [line.split() for line in text.splitlines() if line.strip().startswith('GNU_STACK ')]
    if len(stack) != 1:
        raise ValueError('explicit GNU_STACK segment required')
    loads = [line.split() for line in text.splitlines() if line.strip().startswith('LOAD ')]
    if not loads:
        raise ValueError('ELF LOAD segments required')
    return {'class': field('Class'), 'data': field('Data'), 'osabi': field('OS/ABI'),
            'machine': field('Machine'), 'type': field('Type').split()[0],
            'needed': sorted(needed), 'soname': sonames[0],
            'relro': bool(re.search(r'^\s*GNU_RELRO\s', text, re.M)),
            'now': bool(re.search(r'\(FLAGS(?:_1)?\)[^\n]*\b(?:BIND_NOW|NOW)\b', text)),
            'textrel': bool(re.search(r'\(TEXTREL\)|\(FLAGS\)[^\n]*\bTEXTREL\b', text)),
            'search_path': bool(re.search(r'\((?:RPATH|RUNPATH)\)', text)),
            'executable_stack': 'E' in ''.join(stack[0][6:-1]),
            'writable_executable_load': any('W' in ''.join(row[6:-1]) and
                                            'E' in ''.join(row[6:-1]) for row in loads)}


def validate(candidate, reference, soname):
    for label, record in [('candidate', candidate), ('reference', reference)]:
        if record['type'] != 'DYN' or record['soname'] != soname:
            raise ValueError(label + ': incorrect shared-object type or SONAME')
        if not record['relro'] or not record['now']:
            raise ValueError(label + ': RELRO and immediate binding required')
        if any(record[key] for key in ('textrel', 'search_path', 'executable_stack', 'writable_executable_load')):
            raise ValueError(label + ': unsafe or installation-specific ELF metadata')
    for key in ('class', 'data', 'osabi', 'machine', 'needed'):
        if candidate[key] != reference[key]:
            raise ValueError('Make shared metadata mismatch: ' + key)


def inspect(tool, artifact):
    command = [str(tool), '-h', '-l', '-d', str(artifact)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=True, env={'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'})
    with artifact.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(artifact), 'sha256': digest, 'command': command,
            'stdout': result.stdout, 'stderr': result.stderr, 'metadata': parse(result.stdout)}


def compare(tool, artifact, reference, soname):
    candidate = inspect(tool, artifact)
    baseline = inspect(tool, reference)
    validate(candidate['metadata'], baseline['metadata'], soname)
    with tool.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'scope': 'shared-object-metadata-comparison', 'readelf': str(tool),
            'readelf_sha256': digest, 'candidate': candidate, 'make_reference': baseline,
            'runtime_qualified': False, 'full_abi_parity': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('readelf', 'library', 'make-library', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--soname', required=True)
    a = p.parse_args()
    result = compare(a.readelf.resolve(strict=True), a.library.resolve(strict=True),
                     a.make_library.resolve(strict=True), a.soname)
    with a.output.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
