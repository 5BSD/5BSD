#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare Bazel programs and static archives with explicit maintained-Make artifacts.

Programs: ELF identity, PIE/interpreter, ordered NEEDED dependencies, hardening, imported and
exported dynamic symbols with versions.  Archives: member set and the defined
and undefined symbols of each member.  Section contents are recorded so byte
differences can be explained; byte parity is not required.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import qualification_artifacts

ENV = {'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(argv):
    return subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, check=True, env=ENV).stdout


def parse_program(text, program=True, static=False):
    def field(label):
        values = re.findall(r'^\s*' + re.escape(label) + r':\s*(.+)$', text, re.M)
        if len(values) != 1:
            raise ValueError('missing or ambiguous ELF field: ' + label)
        return values[0].strip()

    interp = re.findall(r'\[Requesting program interpreter: ([^\]]+)\]', text)
    needed = re.findall(r'\(NEEDED\)[^\n]*\[([^\]]+)\]', text)
    stack = [line.split() for line in text.splitlines() if line.strip().startswith('GNU_STACK ')]
    loads = [line.split() for line in text.splitlines() if line.strip().startswith('LOAD ')]
    sonames = re.findall(r'\(SONAME\)[^\n]*\[([^\]]+)\]', text)
    if static:
        if not program or interp or sonames or needed or re.search(r'^\s*DYNAMIC\s', text, re.M):
            raise ValueError('static program has dynamic linking metadata')
    if program and not static and len(interp) != 1:
        raise ValueError('program interpreter metadata ambiguous')
    if not program and (interp or len(sonames) != 1):
        raise ValueError('shared object needs one SONAME and no interpreter')
    if len(stack) != 1 or not loads or len(needed) != len(set(needed)):
        raise ValueError('stack, LOAD or NEEDED metadata ambiguous')
    flags1 = re.findall(r'\(FLAGS_1\)\s+(.*)$', text, re.M)
    imports, exports = set(), set()
    for line in text.splitlines():
        match = re.match(r'^\s*\d+:\s+\S+\s+\d+\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)', line)
        if not match:
            continue
        kind, binding, visibility, index, name = match.groups()
        if binding not in ('GLOBAL', 'WEAK'):
            continue
        (imports if index == 'UND' else exports).add((name, kind, binding, visibility))
    requirements, provider = set(), None
    for line in text.splitlines():
        match = re.search(r'Version:\s+\d+\s+File:\s+(\S+)\s+Cnt:', line)
        if match:
            provider = match.group(1)
            continue
        match = re.search(r'^\s*0x[0-9a-f]+:\s+Name:\s+(\S+)\s+Flags:', line)
        if match:
            if provider is None:
                raise ValueError('version requirement without provider file')
            requirements.add((provider, match.group(1)))
    requirements = sorted(requirements)
    # Version definitions (a versioned library exports name@VERSION).
    definitions = sorted(set(re.findall(r'^\s*0x[0-9a-f]+:\s+Rev:\s+\d+\s+Flags:\s+\S+\s+'
                                        r'Index:\s+\d+\s+Cnt:\s+\d+\s+Name:\s+(\S+)', text, re.M)))
    search_paths = re.findall(r'\((RPATH|RUNPATH)\)[^\n]*\[(.*)\]\s*$', text, re.M)
    if len(search_paths) != len(re.findall(r'\((?:RPATH|RUNPATH)\)', text)):
        raise ValueError('unsupported runtime search path metadata')
    return {'class': field('Class'), 'data': field('Data'), 'osabi': field('OS/ABI'),
            'machine': field('Machine'), 'type': field('Type').split()[0],
            'interpreter': interp[0] if interp else None, 'soname': sonames[0] if sonames else None,
            'version_definitions': definitions,
            'needed_order': needed, 'needed': sorted(needed),
            'pie': bool(flags1 and 'PIE' in flags1[0].split()),
            'relro': bool(re.search(r'^\s*GNU_RELRO\s', text, re.M)),
            'now': bool(re.search(r'\(FLAGS(?:_1)?\)[^\n]*\b(?:BIND_NOW|NOW)\b', text)),
            'textrel': bool(re.search(r'\(TEXTREL\)|\(FLAGS\)[^\n]*\bTEXTREL\b', text)),
            'search_path': bool(search_paths), 'search_paths': search_paths,
            'executable_stack': 'E' in ''.join(stack[0][6:-1]),
            'writable_executable_load': any('W' in ''.join(r[6:-1]) and 'E' in ''.join(r[6:-1])
                                            for r in loads),
            'imports': sorted(imports), 'exports': sorted(exports),
            'version_requirements': requirements}


def sections(objcopy, readelf, artifact, scratch):
    # Keep the call interface for existing comparison drivers. Readelf supplies
    # the actual section offsets/sizes; hash bounded file ranges directly instead
    # of copying the complete ELF once per section through objcopy and scratch.
    text = run([readelf, '-S', '-W', artifact])
    count = re.search(r'There (?:are|is) (\d+) section headers?', text)
    if count is None:
        raise ValueError('missing ELF section header count')
    indexes = []
    descriptors = []
    for line in text.splitlines():
        row = re.match(r'^\s*\[\s*(\d+)\]\s+(.*)$', line)
        if row is None:
            continue
        indexes.append(int(row[1]))
        if int(row[1]) == 0:
            continue
        fields = re.match(r'^(\S+)\s+(\S+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+', row[2])
        if fields is None:
            raise ValueError('unsupported ELF section row')
        name, kind, offset, size = fields.groups()
        if kind not in ('NULL', 'NOBITS'):
            descriptors.append((name, int(offset, 16), int(size, 16)))
    if indexes != list(range(int(count[1]))):
        raise ValueError('incomplete or unordered ELF section table')
    result = {}
    with Path(artifact).open('rb') as stream:
        stream.seek(0, 2)
        length = stream.tell()
        for name, offset, size in descriptors:
            if name in result or offset > length or size > length - offset:
                raise ValueError('duplicate or out-of-bounds ELF section')
            stream.seek(offset)
            remaining = size
            value = hashlib.sha256()
            while remaining:
                data = stream.read(min(1024 * 1024, remaining))
                if not data:
                    raise ValueError('truncated ELF section')
                value.update(data)
                remaining -= len(data)
            result[name] = {'sha256': value.hexdigest(), 'size': size}
    return result


def compare_program(readelf, objcopy, candidate, reference, scratch, *, expected_search_paths=None, static=False):
    records = {}
    for key, path in (('candidate', candidate), ('make_reference', reference)):
        text = run([readelf, '-h', '-l', '-d', '-W', '--dyn-syms', '--version-info', path])
        records[key] = {'path': str(path), 'sha256': sha(path), 'metadata': parse_program(text, static=static),
                        'sections': sections(objcopy, readelf, path, scratch)}
    a, b = records['candidate']['metadata'], records['make_reference']['metadata']
    if expected_search_paths is not None and not isinstance(expected_search_paths, (list, tuple)):
        raise ValueError('runtime search path contract must be a list or tuple')
    expected = [] if expected_search_paths is None else list(expected_search_paths)
    if static and expected:
        raise ValueError('static program cannot have runtime search paths')
    for label, record in (('candidate', a), ('reference', b)):
        if static:
            if record['type'] != 'EXEC' or record['pie']:
                raise ValueError(label + ': fixed static executable required')
        elif record['type'] != 'DYN' or not record['pie']:
            raise ValueError(label + ': PIE executable required')
        if not record['relro'] or (not static and not record['now']):
            raise ValueError(label + ': RELRO and immediate binding required')
        if [value for kind, value in record['search_paths']] != expected:
            raise ValueError(label + ': unexpected runtime search path')
        if any(record[k] for k in ('textrel', 'executable_stack',
                                   'writable_executable_load')):
            raise ValueError(label + ': unsafe or installation-specific ELF metadata')
    for key in ('search_paths', 'class', 'data', 'osabi', 'machine', 'interpreter', 'needed', 'imports',
                'exports', 'version_requirements'):
        if a[key] != b[key]:
            raise ValueError('Make program metadata mismatch: ' + key)
    if a['needed_order'] != b['needed_order']:
        raise ValueError('Make program metadata mismatch: needed_order: ' +
                         json.dumps({'candidate': a['needed_order'], 'make': b['needed_order']}))
    sa, sb = records['candidate']['sections'], records['make_reference']['sections']
    differing = sorted(n for n in set(sa) | set(sb) if sa.get(n) != sb.get(n))
    return {'scope': 'program-metadata-comparison', 'linkage': 'static' if static else 'dynamic', 'expected_search_paths': expected, 'readelf_sha256': sha(readelf),
            **records, 'needed_order_equal': a['needed_order'] == b['needed_order'],
            'byte_identical': sha(candidate) == sha(reference),
            'section_names_equal': sorted(sa) == sorted(sb), 'differing_sections': differing,
            'runtime_qualified': False, 'full_abi_parity': False}


def compare_shared(readelf, objcopy, candidate, reference, soname, scratch):
    """Shared library: SONAME, NEEDED, hardening, dynamic imports/exports with
    their symbol versions, version definitions and requirements, sections."""
    records = {}
    for key, path in (('candidate', candidate), ('make_reference', reference)):
        text = run([readelf, '-h', '-l', '-d', '-W', '--dyn-syms', '--version-info', path])
        records[key] = {'path': str(path), 'sha256': sha(path),
                        'metadata': parse_program(text, program=False),
                        'sections': sections(objcopy, readelf, path, scratch)}
    a, b = records['candidate']['metadata'], records['make_reference']['metadata']
    for label, record in (('candidate', a), ('reference', b)):
        if record['type'] != 'DYN' or record['soname'] != soname:
            raise ValueError(label + ': incorrect shared-object type or SONAME')
        if not record['relro'] or not record['now']:
            raise ValueError(label + ': RELRO and immediate binding required')
        if any(record[k] for k in ('textrel', 'search_path', 'executable_stack',
                                   'writable_executable_load')):
            raise ValueError(label + ': unsafe or installation-specific ELF metadata')
    for key in ('class', 'data', 'osabi', 'machine', 'soname', 'needed', 'imports', 'exports',
                'version_definitions', 'version_requirements'):
        if a[key] != b[key]:
            raise ValueError('Make shared library metadata mismatch: ' + key + ': ' +
                             json.dumps({'bazel_only': sorted(set(map(str, a[key])) - set(map(str, b[key])))[:20],
                                         'make_only': sorted(set(map(str, b[key])) - set(map(str, a[key])))[:20]}))
    if a['needed_order'] != b['needed_order']:
        raise ValueError('Make shared library metadata mismatch: needed_order: ' +
                         json.dumps({'candidate': a['needed_order'], 'make': b['needed_order']}))
    sa, sb = records['candidate']['sections'], records['make_reference']['sections']
    differing = sorted(n for n in set(sa) | set(sb) if sa.get(n) != sb.get(n))
    return {'scope': 'shared-library-metadata-comparison', 'readelf_sha256': sha(readelf),
            **records, 'needed_order_equal': a['needed_order'] == b['needed_order'],
            'exports_versioned': any('@' in x[0] for x in a['exports']),
            'byte_identical': sha(candidate) == sha(reference),
            'section_names_equal': sorted(sa) == sorted(sb), 'differing_sections': differing,
            'runtime_qualified': False, 'full_abi_parity': False}


def stem(member):
    for suffix in ('.nopic.o', '.pic.o', '.pieo', '.o'):
        if member.endswith(suffix):
            return member[:-len(suffix)]
    raise ValueError('unexpected archive member: ' + member)


def parse_archive(nm, artifact):
    symbols = {}
    for line in run([nm, '-A', '--format=posix', artifact]).splitlines():
        match = re.match(r'^.*\[([^\]]+)\]:\s+(\S+)\s+(\S)\b', line)
        if not match:
            raise ValueError('unparsed nm line: ' + line)
        member, name, kind = match.groups()
        symbols.setdefault(stem(member), set()).add((name, kind))
    return {member: sorted(values) for member, values in sorted(symbols.items())}


def compare_archive(nm, ar, candidate, reference):
    records = {}
    for key, path in (('candidate', candidate), ('make_reference', reference)):
        members = run([ar, 't', path]).split()
        if len(members) != len(set(members)):
            raise ValueError(key + ': duplicate archive members')
        identities = [stem(member) for member in members]
        if len(identities) != len(set(identities)):
            raise ValueError(key + ': ambiguous normalized archive members')
        records[key] = {'path': str(path), 'sha256': sha(path), 'members': members,
                        'symbols': parse_archive(nm, path)}
    a, b = records['candidate'], records['make_reference']
    if [stem(m) for m in a['members']] != [stem(m) for m in b['members']]:
        raise ValueError('archive member set or order differs from Make reference')
    if a['symbols'] != b['symbols']:
        raise ValueError('archive member symbols differ from Make reference')
    return {'scope': 'archive-member-symbol-comparison', **records,
            'byte_identical': sha(candidate) == sha(reference)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kind', choices=('program', 'archive'), required=True)
    for name in ('readelf', 'objcopy', 'nm', 'ar', 'make-artifact', 'output'):
        p.add_argument('--' + name, type=Path)
    selection = p.add_mutually_exclusive_group(required=True)
    selection.add_argument('--candidate', type=Path, help='explicit raw file; no qualification binding')
    selection.add_argument('--qualification', type=Path, help='completed native qualification directory')
    p.add_argument('--target', help='explicit captured target label')
    p.add_argument('--output-suffix', help='unique literal suffix of its captured output name')
    p.add_argument('--static-program', action='store_true', help='require a fixed static executable with no interpreter or dynamic dependencies')
    p.add_argument('--expected-search-path', action='append', default=[],
                   help='explicit expected program RPATH/RUNPATH value; candidate and Make tags must still agree')
    a = p.parse_args()
    if a.kind != 'program' and a.static_program:
        p.error('--static-program requires program comparison')
    if a.kind != 'program' and a.expected_search_path:
        p.error('--expected-search-path requires program comparison')
    if a.qualification is not None:
        if not a.target or not a.output_suffix:
            p.error('--qualification requires --target and --output-suffix')
        a.candidate, binding = qualification_artifacts.resolve(a.qualification, a.target, a.output_suffix)
    else:
        if a.target is not None or a.output_suffix is not None:
            p.error('captured target/output selection requires --qualification')
        binding = {'source': 'explicit-unbound-file'}
    if a.kind == 'program':
        scratch = a.output.with_suffix('.scratch')
        scratch.mkdir()
        result = compare_program(a.readelf, a.objcopy, a.candidate, a.make_artifact, scratch, expected_search_paths=a.expected_search_path, static=a.static_program)
        scratch.rmdir()
    else:
        result = compare_archive(a.nm, a.ar, a.candidate, a.make_artifact)
    if binding['source'] == 'qualification-capture':
        if result['candidate']['sha256'] != binding['sha256'] or sha(a.candidate) != binding['sha256']:
            raise ValueError('captured artifact changed during comparison')
    result['candidate_binding'] = binding
    with a.output.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
