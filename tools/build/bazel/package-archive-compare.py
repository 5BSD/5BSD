#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Compare indexed package manifests, raw metadata and streamed payload bytes.

No extraction, target execution, filename exclusions or output normalization.
A passing comparison means equal logical archives, not equal compressed bytes.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import stat
from urllib.parse import unquote

import archive_headers
import package_index
from package_index import packages


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def canonical(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('nonempty safe archive path required')
    if value.startswith('//'):
        raise ValueError('noncanonical archive path')
    if value.startswith('./'):
        value = value[2:]
    value = '/' if value == '.' else '/' + value.lstrip('/').rstrip('/')
    if str(PurePosixPath(value)) != value or '..' in PurePosixPath(value).parts:
        raise ValueError('noncanonical archive path')
    return value


def path_mapping(values):
    if not isinstance(values, (dict, list)):
        raise ValueError('manifest path map or list required')
    result = {}
    for name in values:
        decoded = unquote(name, encoding='utf-8', errors='strict')
        if not decoded.startswith('/'):
            raise ValueError('absolute manifest path required')
        path = canonical(decoded)
        if path in result:
            raise ValueError('decoded manifest path collision')
        result[path] = values[name] if isinstance(values, dict) else True
    return result


def snapshot(path, tar, *, library=archive_headers.LIBRARY):
    manifest = json.loads(subprocess.check_output([str(tar), '-xOf', str(path), '+MANIFEST']),
                          object_pairs_hook=unique_object)
    for key in ('files', 'directories', 'config'):
        if key in manifest:
            manifest[key] = path_mapping(manifest[key])
    headers = {}
    metadata_seen = set()
    for row in archive_headers.read(path, payload_digests=True, library=library):
        if row['acl_types'] or row['xattr_count']:
            raise ValueError('extended ACL/xattr metadata requires a qualified reader: ' + path.name)
        raw = row['pathname']
        if raw in ('+MANIFEST', '+COMPACT_MANIFEST'):
            if raw in metadata_seen:
                raise ValueError('duplicate package metadata entry')
            metadata_seen.add(raw)
            continue
        name = canonical(raw)
        if name in headers:
            raise ValueError('duplicate archive payload entry: ' + name)
        record = dict(row)
        record.pop('pathname')
        headers[name] = record
    if '+MANIFEST' not in metadata_seen:
        raise ValueError('package manifest missing')
    expected = set(manifest.get('files', {})) | set(manifest.get('directories', {}))
    if set(headers) != expected:
        raise ValueError('archive/manifest path coverage differs: ' + path.name)
    files = set(manifest.get('files', {}))
    directories = set(manifest.get('directories', {}))
    if files & directories:
        raise ValueError('package path declared as both file and directory')
    for name, row in headers.items():
        if stat.S_ISDIR(row['mode']) != (name in directories):
            raise ValueError('archive/manifest object type differs: ' + name)
        if row['hardlink'] is not None:
            target = name
            seen = set()
            while target in headers and headers[target]['hardlink'] is not None:
                if target in seen:
                    raise ValueError('cyclic archive hardlink: ' + name)
                seen.add(target)
                target = canonical(headers[target]['hardlink'])
            if target not in headers or not stat.S_ISREG(headers[target]['mode']) or 'data_sha256' not in headers[target]:
                raise ValueError('archive hardlink lacks a regular payload target: ' + name)
    return manifest, headers


def compare(reference, candidate):
    """Report every differing top-level field or per-path field without waivers."""
    differences = []
    for section, before, after in [('manifest', reference[0], candidate[0]),
                                    ('entries', reference[1], candidate[1])]:
        for key in sorted(set(before) | set(after)):
            if key not in before or key not in after:
                differences.append(dict(section=section, key=key, kind='presence',
                                        reference=before.get(key), candidate=after.get(key)))
            elif before[key] != after[key]:
                if section == 'entries' or key in ('files', 'directories', 'config'):
                    for field in sorted(set(before[key]) | set(after[key])):
                        if field not in before[key] or field not in after[key] or before[key][field] != after[key][field]:
                            differences.append(dict(section=section, key=key, field=field,
                                kind='value', reference=before[key].get(field), candidate=after[key].get(field)))
                else:
                    differences.append(dict(section=section, key=key, kind='value',
                                            reference=before[key], candidate=after[key]))
    return differences


def logical_entries(headers):
    """Describe payloads/inode groups independently of first stored link choice.

    Keep each path's owner, permissions, flags and timestamps. Raw headers remain
    separately compared; this view neither rewrites archives nor waives fields.
    It does not simulate package installation or final inode metadata resolution.
    """
    roots, groups = {}, {}
    for name, row in headers.items():
        target = name
        seen = set()
        while target in headers and headers[target]['hardlink'] is not None:
            if target in seen:
                raise ValueError('cyclic archive hardlink: ' + name)
            seen.add(target)
            target = canonical(headers[target]['hardlink'])
        if row['hardlink'] is not None and (target not in headers or 'data_sha256' not in headers[target]):
            raise ValueError('archive hardlink lacks a regular payload target: ' + name)
        roots[name] = target
        if row['hardlink'] is not None or stat.S_ISREG(row['mode']):
            groups.setdefault(target, []).append(name)
    result = {}
    for name, row in headers.items():
        value = dict(row)
        value.pop('hardlink')
        target = roots[name]
        if target in groups:
            original = headers[target]
            value['mode'] = stat.S_IFREG | stat.S_IMODE(row['mode'])
            value['size'] = original['size']
            value['data_sha256'] = original['data_sha256']
            value['hardlink_group'] = sorted(groups[target])
        result[name] = value
    return result


def logical_compare(reference, candidate):
    return compare((reference[0], logical_entries(reference[1])),
                   (candidate[0], logical_entries(candidate[1])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('reference', 'candidate', 'output', 'tar'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--library', type=Path, default=archive_headers.LIBRARY, help='explicit libarchive inspection library; default is the system library')
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('fresh output directory required')
    roots = [args.reference.resolve(strict=True), args.candidate.resolve(strict=True)]
    output = args.output.resolve()
    if any(output.is_relative_to(root) or root.is_relative_to(output) for root in roots):
        raise ValueError('output must not overlap package inputs')
    tar = args.tar.resolve(strict=True)
    library = args.library.resolve(strict=True)
    bindings = {str(root / 'index.json'): digest(root / 'index.json') for root in roots}
    bindings[str(tar)] = digest(tar)
    bindings[str(Path(__file__).resolve())] = digest(__file__)
    bindings[str(Path(archive_headers.__file__).resolve())] = digest(archive_headers.__file__)
    bindings[str(Path(package_index.__file__).resolve())] = digest(package_index.__file__)
    bindings[str(library)] = digest(library)
    sets = [{p.name: p for p in packages(root)} for root in roots]
    args.output.mkdir(parents=True)
    source_inputs = args.output / 'source-inputs'
    source_inputs.mkdir()
    captured_sources = {}
    for source in [Path(__file__).resolve(), Path(archive_headers.__file__).resolve(), Path(package_index.__file__).resolve()]:
        destination = source_inputs / source.name
        if destination.exists():
            raise ValueError('source capture basename collision')
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != bindings[str(source)]:
            raise ValueError('source changed before capture: ' + str(source))
        destination.write_bytes(data)
        captured_sources[str(source)] = dict(file=str(destination.relative_to(args.output)), sha256=bindings[str(source)])
    report = dict(format=1, status='running', scope='Indexed package logical archive comparison: all manifests, named/numeric owners, mode/flags/links, available timestamps and streamed regular payload SHA-256; refuses unmodeled ACL/xattrs; not compressed-byte equality, installed inode ownership, runtime or reference build provenance',
                  reference=str(roots[0]), candidate=str(roots[1]), bindings=bindings, source_inputs=captured_sources, packages={},
                  missing_candidate=sorted(set(sets[0])-set(sets[1])),
                  extra_candidate=sorted(set(sets[1])-set(sets[0])))
    def save():
        (args.output / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
    save()
    counts = Counter()
    logical_counts = Counter()
    details = args.output / 'packages'
    details.mkdir()
    try:
        for name in sorted(set(sets[0]) & set(sets[1])):
            report['active_package'] = name
            before, after = sets[0][name], sets[1][name]
            hashes = [digest(before), digest(after)]
            snapshots = [snapshot(before, tar, library=library), snapshot(after, tar, library=library)]
            differences = compare(*snapshots)
            logical = logical_compare(*snapshots)
            if [digest(before), digest(after)] != hashes:
                raise ValueError('package changed during comparison: ' + name)
            record = dict(reference_sha256=hashes[0], candidate_sha256=hashes[1],
                archive_bytes_equal=hashes[0] == hashes[1], differences=differences, logical_differences=logical,
                reference_entries=len(snapshots[0][1]), candidate_entries=len(snapshots[1][1]))
            detail = details / (name + '.json')
            detail.write_text(json.dumps(record, indent=2) + '\n')
            report['packages'][name] = dict(reference_sha256=hashes[0], candidate_sha256=hashes[1],
                differences=len(differences), logical_differences=len(logical), detail=str(detail.relative_to(args.output)),
                detail_sha256=digest(detail), archive_bytes_equal=hashes[0] == hashes[1])
            counts.update((r['section'], r.get('field', 'presence') if r['section']=='entries' else r['key'])
                          for r in differences)
            logical_counts.update((r['section'], r.get('field', 'presence') if r['section']=='entries' else r['key'])
                                  for r in logical)
            # One shard per package avoids rewriting all earlier diagnostics
            # after every archive. A flushed journal preserves partial progress.
            with (args.output / 'progress.jsonl').open('a') as journal:
                journal.write(json.dumps(dict(package=name, **report['packages'][name])) + '\n')
        for root, selected in zip(roots, sets):
            if set(packages(root)) != set(selected.values()):
                raise ValueError('package selection changed')
        for path, value in bindings.items():
            if digest(path) != value:
                raise ValueError('comparison input changed: ' + path)
        report.pop('active_package', None)
        report['difference_counts'] = {section + ':' + field: count for (section, field), count in sorted(counts.items())}
        report['logical_difference_counts'] = {section + ':' + field: count for (section, field), count in sorted(logical_counts.items())}
        report['logical_status'] = 'differences-found' if report['missing_candidate'] or report['extra_candidate'] or logical_counts else 'passed'
        different = report['missing_candidate'] or report['extra_candidate'] or counts
        report['status'] = 'differences-found' if different else 'passed'
    except Exception as error:
        report.update(status='failed', error=str(error))
        save()
        raise
    save()
    print(args.output / 'review.json')
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
