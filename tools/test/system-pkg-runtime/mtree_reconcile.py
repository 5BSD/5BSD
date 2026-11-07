# SPDX-License-Identifier: BSD-2-Clause
"""Reconcile raw mtree diagnostics only against independently exercised changes."""
import re


def flagset(value):
    return set(value.split(',')) - {'none'}


def reconcile(log, specification, verified_hashes, consumed, archive_tracking):
    baseline = {}
    for line in specification.decode().splitlines():
        fields = line.split()
        path = '/' if fields[0] == '.' else fields[0][1:]
        baseline[path] = dict(field.split('=', 1) for field in fields[1:] if '=' in field)
    if (set(verified_hashes) | set(consumed)) - baseline.keys():
        raise ValueError('reconciliation proof refers to an undeclared object')
    if set(verified_hashes) & set(consumed):
        raise ValueError('changed and consumed objects must be distinct')
    changes, seen, missing = [], set(), set()
    current = None
    pending = False
    for line in log.decode('utf-8').splitlines():
        absent = re.fullmatch(r'\./(.+) missing', line)
        if absent:
            if pending:raise ValueError('incomplete mtree diagnostic')
            path = '/' + absent[1]
            if path not in consumed or path in missing:
                raise ValueError('unexplained missing baseline object: '+path)
            missing.add(path); current = None
            changes.append(dict(path=path, field='consumed'))
            continue
        if line.startswith('\t'):
            if current is None:
                raise ValueError('unattributed mtree diagnostic')
            reason = line.strip()
        else:
            if pending:raise ValueError('incomplete mtree diagnostic')
            heading = re.fullmatch(r'([^:]+):[ \t]*(.*)', line)
            if heading is None:
                raise ValueError('unrecognized mtree diagnostic: '+line)
            current = '/' if heading[1] == '.' else '/' + heading[1]
            if current not in baseline:
                raise ValueError('diagnostic outside declared baseline: '+current)
            reason = heading[2]
            if not reason:
                pending=True
                continue
        flags = re.fullmatch(r'flags \("([^"]+)" is not "([^"]+)"\)', reason)
        content = re.fullmatch(r'sha256digest \(0x([a-f0-9]{64}), 0x([a-f0-9]{64})\)', reason)
        if flags:
            old, new = map(flagset, flags.groups())
            if (not archive_tracking or old ^ new != {'uarch'} or old != flagset(baseline[current]['flags']) or
                    old - {'uarch'} != new - {'uarch'}):
                raise ValueError('unexplained file flag change: '+current)
            field = 'zfs_archive'
        elif content:
            if (current not in verified_hashes or content[1] != baseline[current].get('sha256digest') or
                    content[2] != verified_hashes[current]):
                raise ValueError('unexplained baseline content change: '+current)
            field = 'verified_content'
        else:
            raise ValueError('unexplained mtree difference: '+current+': '+reason)
        if (current, field) in seen:
            raise ValueError('duplicate mtree difference')
        pending=False
        seen.add((current, field))
        changes.append(dict(path=current, field=field))
    if pending:raise ValueError('incomplete mtree diagnostic')
    if missing != set(consumed):
        raise ValueError('audit did not report every independently verified consumed object')
    return changes
