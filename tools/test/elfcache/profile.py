#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Rank loader observations; input is bsdinstruments loader-libraries output from one VM capture.

Preserve DTrace stderr alongside the capture: buffer drops invalidate coverage.
Elapsed times include instrumentation and scheduling, exclude relocation/init.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

REASONS = ('outside-cache-dirs', 'cache-unavailable', 'not-listed',
           'size-changed', 'mapping-failed', 'ineligible', 'bytes-changed', 'hit',
           'source-signature-failed')


def summarize(lines):
    events, errors = [], []
    markers = {"ELFPROFILE_BEGIN": [], "ELFPROFILE_END": []}
    for number, line in enumerate(lines, 1):
        fields = line.rstrip('\n').split('\t')
        # DTrace %S includes an escaped terminating NUL in string output.
        fields = [f[:-2] if f.endswith(r'\0') else f for f in fields]
        if (len(fields) == 2 and fields[0] in markers and fields[1] in ('1', '2')):
            markers[fields[0]].append(fields[1])
            if len(markers[fields[0]]) != 1:
                errors.append({'line': number, 'error': 'duplicate capture marker; captures must not be concatenated'})
            continue
        if not ((fields[0] == 'ELFLOAD1' and len(fields) == 14) or
                (fields[0] == 'ELFLOAD2' and len(fields) == 16)):
            if line.strip():
                errors.append({'line': number, 'error': 'unrecognized or malformed record'})
            continue
        try:
            timestamp, pid, tid = map(int, fields[1:4])
            flags, reason, size, lookup, cache, mapping = map(int, fields[5:11])
            if min(timestamp, pid, tid, flags, reason, size, lookup, cache, mapping) < 0 or reason >= len(REASONS) or flags & ~63:
                raise ValueError('invalid field')
            device, inode = map(int, fields[11:13]) if fields[0] == 'ELFLOAD2' else (0, 0)
            if min(device, inode) < 0:
                raise ValueError('invalid file identity')
            events.append((timestamp, number, pid, fields[4], flags, reason,
                           size, lookup, cache, mapping, device, inode,
                           *fields[13 if fields[0] == 'ELFLOAD2' else 11:]))
        except ValueError:
            errors.append({'line': number, 'error': 'invalid numeric field'})
    begin, end = markers['ELFPROFILE_BEGIN'], markers['ELFPROFILE_END']
    if len(begin) == len(end) == 1 and begin != end:
        errors.append({'error': 'capture marker versions disagree'})
    # DTrace per-CPU buffers need not be emitted in timestamp order. Require
    # unique matching markers, not textual placement before/after each event.
    complete = len(begin) == len(end) == 1 and begin == end
    generations, libraries, programs = Counter(), {}, {}
    starts = 0
    for event in sorted(events):
        _, _, pid, program, flags, reason, size, lookup, cache, mapping, device, inode, path, requested, consumer = event
        if flags & 1:
            generations[pid] += 1
            programs[pid] = path
            starts += 1
            continue
        # Join only recorded file identity within this capture; names alone do
        # not prove that descriptor and absolute paths name the same library.
        display = ('descriptor:' if flags & 16 else '') + path
        key = ('file', device, inode, size) if inode else ('path', display)
        row = libraries.setdefault(key, {'library': display, 'file_device': device, 'file_inode': inode,
            'paths': set(), 'loads': 0, 'failed': 0,
            'dynamic_loads': 0, 'sizes': set(), 'processes': set(), 'programs': set(),
            'consumers': set(), 'requested': set(), 'outcomes': Counter(),
            'lookup_ns': 0, 'cache_ns': 0, 'map_ns': 0, 'incomplete_records': 0,
            'missing_exec_marker': 0})
        row['paths'].add(display)
        row['loads'] += 1
        row['failed'] += bool(flags & 4)
        row['dynamic_loads'] += bool(flags & 2)
        row['sizes'].add(size)
        row['processes'].add((pid, generations[pid]))
        row['programs'].add(programs.get(pid, program))
        if consumer:
            row['consumers'].add(consumer)
        row['requested'].add(requested)
        row['outcomes'][REASONS[reason]] += 1
        row['incomplete_records'] += bool(flags & (8 | 32))
        row['missing_exec_marker'] += not generations[pid]
        if not flags & 32:
            row['lookup_ns'] += lookup
            row['cache_ns'] += cache
            row['map_ns'] += mapping
    rows = []
    for row in libraries.values():
        row['process_count'] = len(row.pop('processes'))
        row['program_count'] = len(row['programs'])
        for field in ('paths', 'sizes', 'programs', 'consumers', 'requested'):
            row[field] = sorted(row[field])
        absolute = [p for p in row['paths'] if p.startswith('/')]
        row['library'] = absolute[0] if absolute else row['paths'][0]
        row['outcomes'] = dict(row['outcomes'])
        rows.append(row)
    rows.sort(key=lambda row: (-row['program_count'], -row['process_count'], -row['loads'], row['library']))
    return {'schema': 2, 'complete_capture_markers': complete,
            'exec_markers': starts, 'records': len(events), 'errors': errors,
            'ranking': 'Distinct executable names, then process/exec instances, then loads.',
            'limitations': ['Validate collector stderr for DTrace drops/errors.',
                'Only observed workloads; missing events are not evidence of no use.',
                'Names are DTrace %S escaped; truncated names cannot establish identity.',
                'Device/inode/size joins apply only within a quiescent VM capture; these are not cryptographic identities.',
                'Descriptor-only paths still need generation inventory resolution.',
                'Timings exclude relocations and constructors; instrumentation affects timings.',
                'User-generated observations are not trusted policy or executable identities.'],
            'libraries': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--library-list', type=Path, help='Write observed absolute cache candidates; review descriptor names separately.')
    parser.add_argument('--min-programs', type=int, default=1)
    parser.add_argument('--collector-errors', type=Path,
                        help='Saved bsdinstruments stderr; required and empty for candidate selection.')
    args = parser.parse_args()
    if args.min_programs < 1:
        parser.error('--min-programs must be positive')
    report = summarize(args.capture.read_text().splitlines(keepends=True))
    report['collector_diagnostics_checked'] = args.collector_errors is not None
    if args.collector_errors is not None:
        diagnostics = args.collector_errors.read_bytes()
        report['collector_diagnostics_bytes'] = len(diagnostics)
        if diagnostics.strip():
            report['errors'].append({'error': 'collector stderr contains diagnostics; capture is not eligible for selection'})
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    if args.library_list:
        if args.collector_errors is None:
            parser.error('--library-list requires --collector-errors from this capture')
        if report['errors'] or not report['complete_capture_markers']:
            parser.error('cannot select from an incomplete or corrupt capture')
        candidates = []
        for row in report['libraries']:
            for name in row['paths']:
                parent, _, leaf = name.rpartition('/')
                if (parent in ('/lib', '/usr/lib') and leaf and
                        all(c.isascii() and (c.isalnum() or c in '._+-') for c in leaf) and
                        row['program_count'] >= args.min_programs and
                        not row['incomplete_records'] and not row['failed'] and
                        not row['missing_exec_marker']):
                    candidates.append(name)
        args.library_list.write_text(''.join(name + '\n' for name in sorted(set(candidates))))
    print('programs processes loads cache_hits library')
    for row in report['libraries']:
        print(row['program_count'], row['process_count'], row['loads'], row['outcomes'].get('hit', 0), row['library'])
    return int(bool(report['errors'] or not report['complete_capture_markers']))


if __name__ == '__main__':
    raise SystemExit(main())
