#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Locate native package declarations for configured world metadata.

This is a review queue, never a build/install coverage or completion gate.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path

FIELDS = {
    'program': ('PROG', 'PROG_CXX', 'PROGS', 'PROGS_CXX'),
    'library': ('LIB', 'SHLIB_NAME'),
    'script': ('SCRIPTS',),
    'tests': ('ATF_TESTS_C', 'ATF_TESTS_CXX', 'ATF_TESTS_SH',
              'PLAIN_TESTS_C', 'PLAIN_TESTS_CXX', 'PLAIN_TESTS_SH'),
    'headers': ('INCS',),
    'manuals': ('MAN',),
    'file_groups': ('FILESGROUPS', 'CONFGROUPS'),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def survey(src, metadata):
    summary_path = metadata / 'summary.json'
    summary = json.loads(summary_path.read_text())
    records_path = metadata / 'components.jsonl'
    if summary['status'] != 'queried' or summary['failed_components']:
        raise ValueError('successful complete metadata survey required')
    bindings = dict(summary['input_sha256'])
    bindings[str(summary_path)] = digest(summary_path)
    bindings[str(records_path)] = summary['records_sha256']

    def verify():
        for name, sha in bindings.items():
            if digest(Path(name)) != sha:
                raise ValueError('survey input changed: ' + name)

    verify()
    rows = [json.loads(line) for line in records_path.read_text().splitlines()]
    inventory = json.loads(Path(summary['inventory']).read_text())
    if (len(rows) != summary['directory_count'] or
            len({r['component'] for r in rows}) != len(rows) or
            {r['component'] for r in rows} != set(inventory['directories'])):
        raise ValueError('metadata directory inventory mismatch')
    counts = collections.Counter()
    report = []
    for row in rows:
        relative = Path(row['component'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('invalid component path')
        directory = (src / relative).resolve(strict=True)
        if not directory.is_relative_to(src):
            raise ValueError('component escapes source tree')
        local = [p for p in (directory / 'BUILD.bazel', directory / 'BUILD') if p.is_file()]
        ancestors = []
        for parent in directory.parents:
            if not parent.is_relative_to(src):
                break
            ancestors = [p for p in (parent / 'BUILD.bazel', parent / 'BUILD') if p.is_file()]
            if ancestors:
                break
        for path in local + ancestors:
            bindings[str(path)] = digest(path)
        values = row.get('metadata', {})
        kinds = [kind for kind, keys in FIELDS.items()
                 if any(values.get(key, '').strip() for key in keys)]
        presence = 'local' if local else 'ancestor_only' if ancestors else 'no_package'
        counts[presence] += 1
        for kind in kinds:
            counts[kind + ':' + presence] += 1
        report.append({
            'component': str(relative), 'categories': kinds,
            'declared_outputs': {key: values[key] for keys in FIELDS.values()
                                 for key in keys if values.get(key, '').strip()},
            'local_build_files': [str(p.relative_to(src)) for p in local],
            'nearest_ancestor_build_files': [str(p.relative_to(src)) for p in ancestors],
            'review_state': 'unverified action/install/test mapping',
        })
    verify()
    return {
        'format': 1, 'status': 'surveyed',
        'scope': 'configured metadata versus package-file presence only',
        'counts': dict(sorted(counts.items())), 'records': report,
        'input_sha256': bindings,
        'limitations': [
            'BUILD presence does not prove native actions, tests or installation.',
            'Ancestor packages may own child outputs; missing local files are not missing binaries.',
            'Counts describe directories, not programs, libraries or completion percentages.',
            'Only the supplied configuration is surveyed.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = survey(args.src.resolve(strict=True), args.metadata.resolve(strict=True))
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'status': result['status'], 'counts': result['counts']}, indent=2))


if __name__ == '__main__':
    main()
