#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Review indexed packages with the maintained ELF/archive contract checker.

Diagnostic scope: non-debug installed programs, libraries and static archives.
Other ELF kinds, unmodeled paths and failures remain explicit. This never executes
payloads or establishes runtime, debug-link, instruction or full ABI parity.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile

from package_index import packages
from qualification_artifacts import digest, resolve


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load('elf_artifact_check', 'elf-artifact-check.py')
comparison = load('package_archive_compare', 'package-archive-compare.py')


def materialize(package, directory, inventory, tar, errors):
    """Stream an archive-to-tar conversion; never extract member-named paths."""
    selected, counts, seen = {}, Counter(), set()
    with errors.open('wb') as stderr:
        process = subprocess.Popen([str(tar), '-cf', '-', '@' + str(package)],
                                   stdout=subprocess.PIPE, stderr=stderr)
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                for member in archive:
                    path = comparison.canonical(member.name)
                    if path in seen:
                        raise ValueError('duplicate archive path: ' + path)
                    seen.add(path)
                    if not member.isfile():
                        counts['nonregular'] += 1
                        continue
                    if path in ('/+MANIFEST', '/+COMPACT_MANIFEST'):
                        counts['package_metadata'] += 1
                        continue
                    record = inventory.get(path)
                    if record is None:
                        counts['unmodeled_regular'] += 1
                        continue
                    if 'dbg' in record['tags']:
                        counts['debug_regular_separate_scope'] += 1
                        continue
                    with archive.extractfile(member) as stream:
                        header = stream.read(64)
                        kind = ('archive' if header.startswith(b'!<arch>\n') else
                                'elf' if header.startswith(b'\x7fELF') else None)
                        if kind is None:
                            counts['other_regular'] += 1
                            continue
                        target = directory / hashlib.sha256(path.encode()).hexdigest()
                        with target.open('xb') as output:
                            output.write(header)
                            shutil.copyfileobj(stream, output, length=1024 * 1024)
                        if target.stat().st_size != member.size:
                            raise ValueError('truncated selected archive payload')
                    counts[kind] += 1
                    selected[path] = (target, kind)
            # tarfile stops at the end marker, before the producer necessarily
            # writes its final record padding. Drain that pipe before wait().
            while padding := process.stdout.read(65536):
                if any(padding):
                    raise ValueError('nonzero archive conversion trailing data')
            if process.wait():
                raise ValueError('archive conversion failed: ' + str(errors))
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait()
    return selected, counts


def review_pair(name, reference, candidate, inventory, args):
    detail = dict(package=name, results={}, counts={})
    with tempfile.TemporaryDirectory(prefix='package-elf-', dir=args.output) as temporary:
        work = Path(temporary)
        tables = []
        for label, package in [('reference', reference), ('candidate', candidate)]:
            root = work / label
            root.mkdir()
            selected, counts = materialize(package, root, inventory, args.tar,
                                           args.output / (name + '.' + label + '.stderr'))
            detail['counts'][label] = dict(counts)
            tables.append(selected)
        detail['selection_difference'] = sorted(set(tables[0]) ^ set(tables[1]))
        for path in sorted(set(tables[0]) & set(tables[1])):
            baseline, kind = tables[0][path]
            product, candidate_kind = tables[1][path]
            result = dict(reference_sha256=digest(baseline), candidate_sha256=digest(product), kind=kind)
            try:
                if kind != candidate_kind:
                    raise ValueError('artifact kinds differ')
                if kind == 'archive':
                    result['comparison'] = checker.compare_archive(args.nm, args.ar, product, baseline)
                else:
                    with product.open('rb') as stream:
                        header = stream.read(20)
                    if header[4:6] != b'\x02\x01':
                        raise ValueError('unhandled ELF encoding/class')
                    elf_type = struct.unpack_from('<H', header, 16)[0]
                    if elf_type not in (2, 3):
                        raise ValueError('ELF type not covered by program/shared contract: ' + str(elf_type))
                    raw = checker.run([args.readelf, '-h', '-l', '-d', '-W', '--dyn-syms', '--version-info', product])
                    # The actual SONAME/interpreter distinguish ordinary libraries,
                    # programs and static executables; no pathname whitelist.
                    program = '[Requesting program interpreter:' in raw or elf_type == 2
                    metadata = checker.parse_program(raw, program=program,
                                                     static=program and '[Requesting program interpreter:' not in raw)
                    if program:
                        result['comparison'] = checker.compare_program(args.readelf, args.objcopy,
                            product, baseline, work, static=metadata['interpreter'] is None)
                    else:
                        result['comparison'] = checker.compare_shared(args.readelf, args.objcopy,
                            product, baseline, metadata['soname'], work)
                result['status'] = 'passed'
            except (ValueError, subprocess.CalledProcessError) as error:
                result.update(status='review-required', error=str(error))
                if kind == 'archive':
                    result['archive_evidence'] = {}
                    for label, artifact in [('candidate', product), ('reference', baseline)]:
                        evidence = dict(members=checker.run([args.ar, 't', artifact]).splitlines())
                        try:
                            evidence.update(checker.archive_record(args.nm, args.ar, artifact))
                        except (ValueError, subprocess.CalledProcessError) as parse_error:
                            evidence['symbol_parse_error'] = str(parse_error)
                        result['archive_evidence'][label] = evidence
            detail['results'][path] = result
    destination = args.output / (name + '.json')
    destination.write_text(json.dumps(detail, indent=2) + '\n')
    return name, dict(detail=destination.name, sha256=digest(destination),
                     statuses=dict(Counter(r['status'] for r in detail['results'].values())),
                     counts=detail['counts'], selection_difference=detail['selection_difference'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('reference', 'candidate', 'qualification', 'output', 'tar', 'readelf', 'objcopy', 'nm', 'ar'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--inventory-target', required=True)
    parser.add_argument('--inventory-output', required=True)
    parser.add_argument('--jobs', type=int, required=True)
    args = parser.parse_args()
    if args.jobs < 1:
        raise ValueError('positive jobs required')
    if args.output.exists():
        raise ValueError('fresh output required')
    for key in ('reference', 'candidate', 'qualification', 'output', 'tar', 'readelf', 'objcopy', 'nm', 'ar'):
        setattr(args, key, getattr(args, key).resolve())
    if any(args.output.is_relative_to(p) or p.is_relative_to(args.output)
           for p in (args.reference, args.candidate, args.qualification)):
        raise ValueError('output overlaps inputs')
    roots = [dict((p.name, p) for p in packages(root)) for root in (args.reference, args.candidate)]
    if roots[0].keys() != roots[1].keys():
        raise ValueError('package sets differ; complete archive comparison required first')
    source, binding = resolve(args.qualification, args.inventory_target, args.inventory_output)
    inventory = {}
    for records in json.loads(source.read_text())['packages'].values():
        for record in records:
            if record['type'] != 'dir':
                path = record['destination']
                if path in inventory:
                    raise ValueError('duplicate inventory payload')
                inventory[path] = record
    inputs = [Path(__file__).resolve(), Path(checker.__file__), Path(comparison.__file__),
              Path(__file__).with_name('package_index.py'), Path(__file__).with_name('qualification_artifacts.py'),
              args.tar, args.readelf, args.objcopy, args.nm, args.ar,
              args.reference/'index.json', args.candidate/'index.json',
              *roots[0].values(), *roots[1].values()]
    bindings = {str(p): digest(p) for p in inputs}
    args.output.mkdir()
    report = dict(status='running', scope=__doc__, inventory_binding=binding, bindings=bindings, packages={})
    sources = args.output/'source-inputs'
    sources.mkdir()
    for source in inputs:
        if source.suffix == '.py':
            shutil.copyfile(source, sources/source.name)
    (args.output/'review.json').write_text(json.dumps(report, indent=2)+'\n')
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(review_pair, name, roots[0][name], roots[1][name], inventory, args)
                   for name in sorted(roots[0])]
        for future in futures:
            name, result = future.result()
            report['packages'][name] = result
    if any(digest(Path(p)) != expected for p, expected in bindings.items()):
        raise ValueError('review input changed')
    report['status'] = ('review-required' if any(
        p['statuses'].get('review-required') or p['selection_difference'] or
        any(c.get('unmodeled_regular') for c in p['counts'].values())
        for p in report['packages'].values()) else 'passed-selected-contracts')
    (args.output/'review.json').write_text(json.dumps(report, indent=2)+'\n')
    print(args.output/'review.json')
    return int(report['status'] == 'review-required')


if __name__ == '__main__':
    raise SystemExit(main())
