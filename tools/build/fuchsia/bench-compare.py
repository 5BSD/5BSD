#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Summarize or compare ipc_bench results (one JSON line per run).

  bench-compare.py [--markdown] FILE           medians over the file's trials
  bench-compare.py [--markdown] BEFORE AFTER   deltas of the medians

Runs are grouped by (name, mode); each metric's median over the trials is
reported with its run-to-run spread (min..max) for p50 and p99.
"""
import json
import statistics
import sys

METRICS = ['p50_us', 'p99_us', 'calls_per_second', 'client_allocations_per_call',
           'server_allocations_per_call', 'client_bytes_per_call',
           'server_bytes_per_call', 'client_syscalls_per_call',
           'server_syscalls_per_call']


def load(path):
    groups = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith('{'):
                continue
            r = json.loads(line)
            groups.setdefault((r['name'], r['mode']), []).append(r)
    return groups


def median(runs, key):
    values = [r[key] for r in runs if r.get(key) is not None]
    if not values:
        return None
    return statistics.median(values)


def spread(runs, key):
    values = [r[key] for r in runs if r.get(key) is not None]
    if len(values) < 2:
        return ''
    return '%.1f..%.1f' % (min(values), max(values))


def summary(groups):
    out = {}
    for key, runs in groups.items():
        s = {m: median(runs, m) for m in METRICS}
        s['spread_p50'] = spread(runs, 'p50_us')
        s['spread_p99'] = spread(runs, 'p99_us')
        s['trials'] = len(runs)
        s['unit'] = runs[0].get('sample_unit', 'call')
        s['events'] = runs[0].get('events_per_burst', 0)
        s['fds'] = runs[0].get('fds', 0)
        s['message_bytes'] = runs[0].get('message_bytes', 0)
        out[key] = s
    return out


def num(v, fmt='%.1f'):
    return '-' if v is None else fmt % v


def table(rows, header, markdown):
    widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
    if markdown:
        print('| ' + ' | '.join(header) + ' |')
        print('|' + '|'.join('---' for _ in header) + '|')
        for r in rows:
            print('| ' + ' | '.join(str(c) for c in r) + ' |')
        return
    fmt = '  '.join('%%-%ds' % w for w in widths)
    print(fmt % tuple(header))
    for r in rows:
        print(fmt % tuple(str(c) for c in r))


def show(path, markdown):
    s = summary(load(path))
    header = ['scenario', 'mode', 'unit', 'bytes', 'p50 us (spread)', 'p99 us (spread)',
              'per s', 'allocs c/s', 'alloc bytes c/s', 'syscalls c/s', 'n']
    rows = []
    for (name, mode), v in s.items():
        rows.append([name, mode, v['unit'], v['message_bytes'],
                     '%s (%s)' % (num(v['p50_us'], '%.2f'), v['spread_p50']),
                     '%s (%s)' % (num(v['p99_us'], '%.2f'), v['spread_p99']),
                     num(v['calls_per_second'], '%.0f'),
                     '%s / %s' % (num(v['client_allocations_per_call'], '%.2f'),
                                  num(v['server_allocations_per_call'], '%.2f')),
                     '%s / %s' % (num(v['client_bytes_per_call'], '%.0f'),
                                  num(v['server_bytes_per_call'], '%.0f')),
                     '%s / %s' % (num(v['client_syscalls_per_call'], '%.2f'),
                                  num(v['server_syscalls_per_call'], '%.2f')),
                     v['trials']])
    table(rows, header, markdown)


def delta(a, b, lower_is_better=True, fmt='%.2f'):
    if a is None or b is None:
        return '-'
    if a == 0:
        return '%s -> %s' % (fmt % a, fmt % b)
    change = (b - a) / a * 100
    return '%s -> %s (%+.1f%%)' % (fmt % a, fmt % b, change)


def compare(before, after, markdown):
    sa, sb = summary(load(before)), summary(load(after))
    header = ['scenario', 'mode', 'p50 us', 'p99 us', 'per s', 'allocs c/s', 'syscalls c/s']
    rows = []
    for key in sa:
        if key not in sb:
            continue
        a, b = sa[key], sb[key]
        rows.append([key[0], key[1],
                     delta(a['p50_us'], b['p50_us']),
                     delta(a['p99_us'], b['p99_us']),
                     delta(a['calls_per_second'], b['calls_per_second'], False, '%.0f'),
                     '%s / %s' % (delta(a['client_allocations_per_call'], b['client_allocations_per_call']),
                                  delta(a['server_allocations_per_call'], b['server_allocations_per_call'])),
                     '%s / %s' % (delta(a['client_syscalls_per_call'], b['client_syscalls_per_call']),
                                  delta(a['server_syscalls_per_call'], b['server_syscalls_per_call']))])
    table(rows, header, markdown)
    missing = sorted(set(sb) - set(sa)), sorted(set(sa) - set(sb))
    if missing[0]:
        print('only in AFTER: ' + ', '.join('%s/%s' % k for k in missing[0]))
    if missing[1]:
        print('only in BEFORE: ' + ', '.join('%s/%s' % k for k in missing[1]))


def main(argv):
    markdown = '--markdown' in argv
    args = [a for a in argv if a != '--markdown']
    if len(args) == 1:
        show(args[0], markdown)
    elif len(args) == 2:
        compare(args[0], args[1], markdown)
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main(sys.argv[1:])
