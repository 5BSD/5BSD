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
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
from collections import Counter

import qualification_artifacts

ENV = {'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(argv):
    return subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, check=True, env=ENV).stdout


def parse_program(text, program=True, static=False, *, allow_missing_soname=False):
    if type(allow_missing_soname) is not bool:
        raise ValueError("missing SONAME selection must be boolean")
    if program and allow_missing_soname:
        raise ValueError("missing SONAME selection requires a shared object")
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
    if not program and (interp or len(sonames) > 1 or (not allow_missing_soname and len(sonames) != 1)):
        raise ValueError('shared object needs one SONAME and no interpreter')
    if len(stack) != 1 or not loads or len(needed) != len(set(needed)):
        raise ValueError('stack, LOAD or NEEDED metadata ambiguous')
    flags1 = re.findall(r'\(FLAGS_1\)\s+(.*)$', text, re.M)
    flags = re.findall(r'\(FLAGS\)\s+(.*)$', text, re.M)
    if len(flags1) > 1 or len(flags) > 1:
        raise ValueError('ambiguous ELF dynamic flags')
    def flag_names(rows):
        text = rows[0].removeprefix('Flags:').strip() if rows else ''
        return sorted(word for word in text.split() if word not in ('None', 'none', '0x0'))
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
    # VER_FLG_BASE names the link output, not a public symbol version. The
    # runtime loader explicitly skips it when constructing its version table
    # (rtld.c: rtld_verify_object_versions). Preserve it as descriptive metadata.
    version_rows = re.findall(r'^\s*0x[0-9a-f]+:\s+Rev:\s+(\d+)\s+Flags:\s+(.*?)\s+'
                              r'Index:\s+(\d+)\s+Cnt:\s+(\d+)\s+Name:\s+(\S+)\s*$', text, re.M)
    if len(version_rows) != len(re.findall(r'^\s*0x[0-9a-f]+:\s+Rev:', text, re.M)):
        raise ValueError('unsupported version definition row')
    definitions, bases, indexes = [], [], set()
    for revision, flags, index, count, name in version_rows:
        index = int(index)
        if revision != '1' or not index or index in indexes or int(count) < 1:
            raise ValueError('invalid or duplicate version definition')
        indexes.add(index)
        if 'BASE' in flags.split():
            if flags != 'BASE' or index != 1 or count != '1':
                raise ValueError('invalid base version definition')
            bases.append(name)
        else:
            if index == 1 or name in definitions:
                raise ValueError('invalid or duplicate public version definition')
            definitions.append(name)
    if len(bases) > 1:
        raise ValueError('ambiguous base version definition')
    definitions.sort()
    search_paths = re.findall(r'\((RPATH|RUNPATH)\)[^\n]*\[(.*)\]\s*$', text, re.M)
    if len(search_paths) != len(re.findall(r'\((?:RPATH|RUNPATH)\)', text)):
        raise ValueError('unsupported runtime search path metadata')
    return {'class': field('Class'), 'data': field('Data'), 'osabi': field('OS/ABI'),
            'machine': field('Machine'), 'type': field('Type').split()[0],
            'interpreter': interp[0] if interp else None, 'soname': sonames[0] if sonames else None,
            'version_definitions': definitions, 'version_base_definition': bases[0] if bases else None,
            'needed_order': needed, 'needed': sorted(needed),
            'pie': bool(flags1 and 'PIE' in flags1[0].split()),
            'dynamic_flags': flag_names(flags), 'dynamic_flags_1': flag_names(flags1),
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
                        'metadata': parse_program(text, program=False, allow_missing_soname=soname is None),
                        'sections': sections(objcopy, readelf, path, scratch)}
    a, b = records['candidate']['metadata'], records['make_reference']['metadata']
    for label, record in (('candidate', a), ('reference', b)):
        if record['type'] != 'DYN' or record['soname'] != soname:
            raise ValueError(label + ': incorrect shared-object type or SONAME')
        if record['pie']:
            raise ValueError(label + ': shared object must not declare PIE executable')
        if soname is not None and record['version_base_definition'] not in (None, soname):
            raise ValueError(label + ': base version identity differs from SONAME')
        if not record['relro'] or not record['now']:
            raise ValueError(label + ': RELRO and immediate binding required')
        if any(record[k] for k in ('textrel', 'search_path', 'executable_stack',
                                   'writable_executable_load')):
            raise ValueError(label + ': unsafe or installation-specific ELF metadata')
    for key in ('class', 'data', 'osabi', 'machine', 'soname', 'needed', 'imports', 'exports',
                'version_definitions', 'version_requirements', 'dynamic_flags', 'dynamic_flags_1'):
        if a[key] != b[key]:
            raise ValueError('Make shared library metadata mismatch: ' + key + ': ' +
                             json.dumps({'bazel_only': sorted(set(map(str, a[key])) - set(map(str, b[key])))[:20],
                                         'make_only': sorted(set(map(str, b[key])) - set(map(str, a[key])))[:20]}))
    if a['needed_order'] != b['needed_order']:
        raise ValueError('Make shared library metadata mismatch: needed_order: ' +
                         json.dumps({'candidate': a['needed_order'], 'make': b['needed_order']}))
    if bool(a['version_base_definition']) != bool(b['version_base_definition']):
        raise ValueError('Make shared library metadata mismatch: version base presence')
    sa, sb = records['candidate']['sections'], records['make_reference']['sections']
    differing = sorted(n for n in set(sa) | set(sb) if sa.get(n) != sb.get(n))
    return {'scope': 'shared-library-metadata-comparison', 'readelf_sha256': sha(readelf),
            **records, 'needed_order_equal': a['needed_order'] == b['needed_order'],
            'exports_versioned': any('@' in x[0] for x in a['exports']),
            'version_base_names_equal': a['version_base_definition'] == b['version_base_definition'],
            'version_base_scope': 'descriptive link-output identity, retained separately from public symbol versions',
            'byte_identical': sha(candidate) == sha(reference),
            'section_names_equal': sorted(sa) == sorted(sb), 'differing_sections': differing,
            'runtime_qualified': False, 'full_abi_parity': False}



def compare_relocatable(candidate, reference):
    """Exact allocated bytes and symbolic relocations, excluding debug-only data.

    Reuse the boot object's maintained contract, preserving duplicate section
    occurrences and all external symbol fields. This neither loads a module nor
    normalizes code, relocation addends, build IDs or DTrace path IDs.
    """
    from elf_object_contract import contract
    records = {}
    for key, path in (('candidate', candidate), ('make_reference', reference)):
        data = Path(path).read_bytes()
        records[key] = {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(),
                        'contract': contract(data, allow_duplicate_sections=True)}
    a, b = records['candidate']['contract'], records['make_reference']['contract']
    differences = [key for key in sorted(set(a) | set(b)) if a.get(key) != b.get(key)]
    return {'scope': 'exact-relocatable-allocated-symbol-relocation-comparison',
            **records, 'differences': differences,
            'status': 'review-required' if differences else 'passed',
            'debug_qualified': False, 'runtime_qualified': False}


def stem(member):
    for suffix in ('.nopic.o', '.pic.o', '.nossppico', '.pico', '.pieo', '.o'):
        if member.endswith(suffix):
            return member[:-len(suffix)]
    raise ValueError('unexpected archive member: ' + member)


def parse_archive(nm, artifact):
    symbols = {}
    for line in run([nm, '-A', '--special-syms', '--format=posix', artifact]).splitlines():
        match = re.match(r'^.*\[([^\]]+)\]:\s+(\S+)\s+(\S)\b', line)
        if not match:
            raise ValueError('unparsed nm line: ' + line)
        member, name, kind = match.groups()
        # ELF permits repeated local names after relocatable linking. Preserve
        # their multiplicity so an extra definition/reference cannot disappear.
        symbols.setdefault(stem(member), []).append((name, kind))
    return {member: sorted(values) for member, values in sorted(symbols.items())}


class AmbiguousDtraceAliases(ValueError):
    pass


def _archive_symbol_groups(symbols):
    ordinary, aliases = {}, {}
    for member, entries in symbols.items():
        ordinary[member] = []
        for name, kind in entries:
            match = re.fullmatch(r'\$dtrace([0-9]+)\.(.+)', name)
            if match:
                key, function = match.groups()
                aliases.setdefault(key, []).append((member, function, kind))
            else:
                ordinary[member].append((name, kind))
        ordinary[member].sort()
    return ordinary, {key: tuple(sorted(entries)) for key, entries in aliases.items()}


def compare_archive_symbols(candidate, reference, *, candidate_contexts=None, reference_contexts=None):
    """Map path IDs by the complete symbol graph and optional validated DOF context.

    Ambiguous graphs require actual relocated probe/function evidence, never an
    arbitrary ordering of IDs. Contexts are constructed internally from emitted
    DOF and bounded hidden function definitions with checked patched-site bytes.
    """
    if candidate == reference and candidate_contexts is None and reference_contexts is None:
        return []

    def contract(symbols, contexts):
        ordinary, aliases = _archive_symbol_groups(symbols)
        contexts = contexts or {}
        if set(contexts) - set(aliases):
            raise ValueError('DOF context names an absent archive alias ID')
        signatures = {}
        for key, entries in aliases.items():
            signature = (entries, tuple(sorted(contexts.get(key, []))))
            if signature in signatures:
                raise AmbiguousDtraceAliases('ambiguous DTrace archive alias incidence graph')
            signatures[signature] = key
        return ordinary, signatures

    a, a_aliases = contract(candidate, candidate_contexts)
    b, b_aliases = contract(reference, reference_contexts)
    if a != b or set(a_aliases) != set(b_aliases):
        raise ValueError('archive member symbols differ from Make reference')
    result = []
    for signature in sorted(a_aliases):
        row = {'candidate_id': a_aliases[signature], 'reference_id': b_aliases[signature],
               'incidence': signature[0]}
        if signature[1]:
            row['validated_dof_context'] = list(signature[1])
        result.append(row)
    return result


def dof_alias_contexts(metadata, member):
    """Join validated DOF bindings to unique emitted probe records.

    Function addresses locate the records within each input only. Matching uses
    probe schema/sites, exact function bytes/size and ELF binding/type/visibility.
    No address or arbitrary ID ordering determines the cross-input mapping.
    """
    contexts = {}
    for binding in metadata['relocatable_metadata']['bindings']:
        symbol = binding['symbol']
        match = re.fullmatch(r'\$dtrace([0-9]+)\.(.+)', symbol['name'])
        if match is None:
            continue  # Non-path-derived weak aliases are compared verbatim.
        matches = [probe for probe in metadata['probe_locations']
                   if probe['address'] == symbol['value'] and probe['function'] == match[2]
                   and probe['offsets'] == binding['ordinary_offsets']
                   and probe['enabled_offsets'] == binding['enabled_offsets']]
        if len(matches) != 1:
            raise ValueError('DOF alias binding requires a unique emitted probe context')
        probe = {key: value for key, value in matches[0].items() if key != 'address'}
        providers = [row for row in metadata['providers'] if row['name'] == probe['provider']]
        if len(providers) != 1:
            raise ValueError('DOF alias binding requires unique provider attributes')
        context = {'member': member, 'probe': probe, 'provider_attributes': providers[0]['attributes'],
                   'function_sha256': binding['function_sha256'],
                   'size': symbol['size'], 'type': symbol['type'],
                   'binding': symbol['binding'], 'visibility': symbol['visibility']}
        contexts.setdefault(match[1], []).append(json.dumps(context, sort_keys=True))
    return contexts


def _ambiguous_definition_members(symbols):
    unused, aliases = _archive_symbol_groups(symbols)
    groups = {}
    for signature in aliases.values():
        groups[signature] = groups.get(signature, 0) + 1
    return {member for signature, count in groups.items() if count > 1
            for member, function, kind in signature if kind in ('T', 't', 'W')}


def archive_dof_contexts(ar, path, record):
    """Resolve ambiguous merged members with their co-located emitted DOF.

    If the metadata is absent, unresolved or ambiguous, qualification stays
    rejected. This does not infer a module identity from its pathname or filename.
    """
    selected = _ambiguous_definition_members(record['symbols'])
    if not selected:
        raise ValueError('ambiguous archive aliases have no defined function member')
    spec = importlib.util.spec_from_file_location('archive_dof_inventory',
        Path(__file__).with_name('dtrace-dof-inventory.py'))
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    contexts = {}
    occurrences = Counter()
    for index, member in enumerate(record['members']):
        occurrences[member] += 1
        identity = str(index) + ':' + stem(member)
        if identity not in selected:
            continue
        # archive_record has already validated all extraction names as basenames.
        with tempfile.TemporaryDirectory(prefix='archive-dof-context-') as directory:
            subprocess.run([str(ar), 'xN', str(occurrences[member]),
                            str(Path(path).resolve()), member], cwd=directory,
                           env=ENV, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            obj = Path(directory) / member
            if not obj.is_file() or obj.is_symlink():
                raise ValueError('DOF extraction did not produce a regular object')
            metadata = parser.inventory(obj, relocatable=True)
            for key, rows in dof_alias_contexts(metadata, identity).items():
                contexts.setdefault(key, []).extend(rows)
    return contexts


def archive_record(nm, ar, path):
    """Preserve duplicate occurrences using LLVM ar's public xN interface.

    Bulk nm is sufficient for unique names. Its archive prefixes cannot identify
    repeated names, so read those instances separately in private directories.
    No archive-controlled pathname may escape the extraction directory.
    """
    members = run([ar, 't', path]).splitlines()
    spellings = {}
    for member in members:
        if not member or Path(member).name != member or member.startswith('-'):
            raise ValueError('unsafe archive member pathname: ' + member)
        identity = stem(member)
        if identity in spellings and spellings[identity] != member:
            raise ValueError('ambiguous normalized archive members')
        spellings[identity] = member
    counts = Counter(members)
    bulk = parse_archive(nm, path)
    if set(bulk) - set(spellings):
        raise ValueError('nm reported an unlisted archive member')
    symbols = {}
    occurrences = Counter()
    for index, member in enumerate(members):
        identity = stem(member)
        occurrences[member] += 1
        # An ordinal key binds DTrace definitions/references to this occurrence,
        # rather than merging symbols from different objects with the same name.
        key = str(index) + ':' + identity
        if counts[member] == 1:
            symbols[key] = bulk.get(identity, [])
            continue
        with tempfile.TemporaryDirectory(prefix='archive-occurrence-') as directory:
            subprocess.run([str(ar), 'xN', str(occurrences[member]),
                            str(Path(path).resolve()), member], cwd=directory,
                           env=ENV, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            extracted = Path(directory) / member
            if not extracted.is_file() or extracted.is_symlink():
                raise ValueError('archive occurrence extraction did not produce a regular object')
            entries = []
            for line in run([nm, '--special-syms', '--format=posix', extracted]).splitlines():
                match = re.match(r'^(\S+)\s+(\S)\b', line)
                if not match:
                    raise ValueError('unparsed occurrence nm line: ' + line)
                entries.append(match.groups())
            symbols[key] = sorted(entries)
    return {'path': str(path), 'sha256': sha(path), 'members': members,
            'symbols': symbols}


def compare_archive(nm, ar, candidate, reference):
    records = {key: archive_record(nm, ar, path)
               for key, path in (('candidate', candidate), ('make_reference', reference))}
    a, b = records['candidate'], records['make_reference']
    if [stem(m) for m in a['members']] != [stem(m) for m in b['members']]:
        raise ValueError('archive member set or order differs from Make reference')
    try:
        aliases = compare_archive_symbols(a['symbols'], b['symbols'])
    except AmbiguousDtraceAliases:
        a['dof_alias_contexts'] = archive_dof_contexts(ar, candidate, a)
        b['dof_alias_contexts'] = archive_dof_contexts(ar, reference, b)
        aliases = compare_archive_symbols(a['symbols'], b['symbols'],
            candidate_contexts=a['dof_alias_contexts'], reference_contexts=b['dof_alias_contexts'])
    return {'scope': 'archive-member-symbol-comparison', **records,
            'dtrace_alias_mapping': aliases,
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
