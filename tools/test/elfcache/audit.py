#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Offline ELF dependency/cache coverage audit. Never executes staged programs.

This is a default-directory audit, not an rtld resolver: RPATH/RUNPATH, libmap,
service-granted directories and dynamically computed dlopen names need review.
Cache integrity here means bytes match the stage; use elfcache verify for trust.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

DIRECTORIES = ('/lib', '/usr/lib')
SCAN = ('bin', 'sbin', 'usr/bin', 'usr/sbin', 'lib', 'usr/lib', 'Capabilities')


def cache_entries(path):
    with open(path, 'rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        head = stream.read(64)
        if len(head) != 64:
            raise ValueError('short cache header')
        magic, version, count, length, alignment, stride, reserved = struct.unpack('<8sIIQII32s', head)
        if (magic != b'5BSDELF\0' or version != 2 or not 0 < count <= 4096 or
                length != size or size > 4 * 1024**3 or alignment != 65536 or
                stride != 192 or any(reserved)):
            raise ValueError('invalid cache header')
        result = {}
        previous = (-1, b'')
        for _ in range(count):
            raw = stream.read(192)
            if len(raw) != 192:
                raise ValueError('short cache index')
            directory, reserved, offset, length, source_length, digest, rawname = struct.unpack('<IIQQQ32s128s', raw)
            name, separator, _ = rawname.partition(b'\0')
            if (directory > 1 or reserved or not separator or not name or
                    b'/' in name or name in (b'.', b'..') or
                    (directory, name) <= previous or offset % alignment or
                    offset < 64 + count * stride or length < 52 or
                    offset + length > size or source_length < length):
                raise ValueError('invalid cache index entry')
            previous = directory, name
            result[DIRECTORIES[directory] + '/' + os.fsdecode(name)] = (offset, length, digest, source_length)
        for name, (offset, length, digest, source_length) in result.items():
            stream.seek(offset)
            actual = hashlib.sha256()
            remaining = length
            while remaining:
                chunk = stream.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError('truncated cache payload')
                actual.update(chunk)
                remaining -= len(chunk)
            if actual.digest() != digest:
                raise ValueError('cache payload digest mismatch: ' + name)
        return result


def inside(root, path):
    # Resolve absolute symlinks as the staged system would, never against the
    # build host's /Capabilities or /lib. Bound links and reject root escapes.
    pending = list(path.relative_to(root).parts)
    resolved, links = root, 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.', '/'):
            continue
        if part == '..':
            if resolved == root:
                raise ValueError('path escapes staged root: ' + str(path))
            resolved = resolved.parent
            continue
        candidate = resolved / part
        candidate.lstat()
        if candidate.is_symlink():
            links += 1
            if links > 40:
                raise ValueError('symlink loop: ' + str(path))
            target = Path(os.readlink(candidate))
            if target.is_absolute():
                resolved = root
            pending = list(target.parts) + pending
        else:
            resolved = candidate
    return resolved


def audit(root, cache, readelf):
    root = root.resolve(strict=True)
    index = cache_entries(cache)
    objects, errors, escaped = {}, [], []
    for directory in SCAN:
        for parent, dirs, files in os.walk(root / directory, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d != '.debug' and
                             Path(parent) / d != root / 'usr/lib/debug')
            for name in sorted(files):
                path = Path(parent) / name
                logical = '/' + str(path.relative_to(root))
                try:
                    real = inside(root, path)
                    if not real.is_file():
                        continue
                    with real.open('rb') as stream:
                        if stream.read(4) != b'\x7fELF':
                            continue
                except (OSError, ValueError) as exc:
                    escaped.append({'path': logical, 'error': str(exc)})
                    continue
                proc = subprocess.run([readelf, '-d', str(real)], text=True,
                                      capture_output=True, env={**os.environ, 'LC_ALL': 'C'})
                if proc.returncode:
                    errors.append({'path': logical, 'error': proc.stderr.strip()})
                    continue
                needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', proc.stdout)
                search = re.findall(r'\((?:RUNPATH|RPATH)\).*?\[([^\]]*)\]', proc.stdout)
                objects[logical] = {'needed': needed, 'search_paths': search}
    edges, missing, review = [], [], []
    digests = {}
    for path, obj in sorted(objects.items()):
        if obj['search_paths']:
            review.append({'path': path, 'reason': 'ELF search path', 'value': obj['search_paths']})
        for name in obj['needed']:
            candidates = [name] if name.startswith('/') else [d + '/' + name for d in DIRECTORIES]
            if '/' in name and not name.startswith('/'):
                review.append({'path': path, 'reason': 'relative DT_NEEDED pathname', 'value': name})
                candidates = []
            resolved = next((p for p in candidates if p in objects), None)
            status = 'missing-library' if resolved is None else 'not-cached'
            if resolved in index:
                if resolved not in digests:
                    with inside(root, root / resolved.lstrip('/')).open('rb') as stream:
                        length = index[resolved][1]
                        actual = hashlib.sha256()
                        while length:
                            chunk = stream.read(min(length, 1024 * 1024))
                            if not chunk:
                                break
                            actual.update(chunk)
                            length -= len(chunk)
                        digests[resolved] = (actual.digest() if not length and
                            os.fstat(stream.fileno()).st_size == index[resolved][3] else None)
                status = 'covered' if digests[resolved] == index[resolved][2] else 'different-bytes'
            edge = {'consumer': path, 'needed': name, 'resolved': resolved, 'status': status}
            edges.append(edge)
            if status != 'covered':
                missing.append(edge)
    # Every scanned library is a consumer too: this includes indirect edges,
    # cycles and plugins even when no executable directly names those plugins.
    used = {edge['resolved'] for edge in edges if edge['status'] == 'covered'}
    modules = [p for p, o in objects.items() if '.so' in Path(p).name and p not in index]
    return {'schema': 1, 'root': str(root), 'cache': str(Path(cache).resolve()),
            'scope': 'All DT_NEEDED edges in standard BSD program/library and capability trees; default /lib,/usr/lib resolution.',
            'limitations': ['No signature trust assertion; run elfcache verify separately.',
                            'Runtime dlopen/fdlopen, libmap, loader hints and descriptor-granted directories require workload/configuration review.',
                            'Coverage does not imply loader eligibility or demonstrated performance savings.'],
            'summary': {'elf_objects': len(objects), 'capability_objects': sum(p.startswith('/Capabilities/') for p in objects),
                        'cache_entries': len(index), 'dependency_edges': len(edges), 'covered_edges': len(edges)-len(missing),
                        'uncovered_edges': len(missing), 'referenced_cache_entries': len(used),
                        'search_path_reviews': len(review), 'read_errors': len(errors), 'unresolved_paths': len(escaped)},
            'uncovered': missing, 'search_path_review': review, 'uncached_module_candidates': sorted(modules),
            'unreferenced_cache_entries': sorted(set(index)-used), 'errors': errors,
            'unresolved_paths': escaped, 'dependencies': edges}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--readelf', default='/usr/bin/readelf')
    args = parser.parse_args()
    report = audit(args.root, args.cache, args.readelf)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['summary'], sort_keys=True))
    return int(bool(report['uncovered'] or report['errors'] or report['unresolved_paths']))


if __name__ == '__main__':
    raise SystemExit(main())
