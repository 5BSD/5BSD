#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Validate and summarize one completed paired cache VM run; no savings claim."""
import argparse
import json
import math
from pathlib import Path
import statistics

MAX_LOG = 64 * 1024 * 1024


def summarize(directory, warmup_rounds=1):
    if warmup_rounds < 0:
        raise ValueError('warmup rounds must be nonnegative')
    directory = Path(directory)
    serial_path = directory / 'serial.log'
    if serial_path.stat().st_size > MAX_LOG:
        raise ValueError('serial log exceeds size bound')
    serial = serial_path.read_text(errors='strict')
    endings = [line.strip() for line in serial.splitlines()
               if line.startswith('ELFCACHE_VM_END')]
    if endings != ['ELFCACHE_VM_END failures=0'] or 'CHECK FAIL' in serial:
        raise ValueError('run did not complete all VM checks successfully')
    records = {}
    measurement_order = {}
    for line in serial.splitlines():
        fields = line.split()
        if not fields or fields[0] not in ('MEASURE', 'CPU'):
            continue
        row = {}
        for field in fields[1:]:
            name, sep, value = field.partition('=')
            if not sep or name in row:
                raise ValueError('malformed or duplicate measurement field')
            row[name] = value
        try:
            mode, number = row['mode'], int(row['round'])
        except (KeyError, ValueError) as exc:
            raise ValueError('missing mode or round') from exc
        if mode not in ('ordinary', 'cache') or number < 0:
            raise ValueError('invalid mode or round')
        key = fields[0], mode, number
        if key in records:
            raise ValueError('duplicate measurement row')
        records[key] = row
        if fields[0] == 'MEASURE':
            measurement_order.setdefault(number, []).append(mode)
    rounds = sorted({key[2] for key in records})
    if not rounds or rounds != list(range(len(rounds))):
        raise ValueError('missing or noncontiguous rounds')
    pairs = []
    configuration = None
    for number in rounds:
        values = {}
        for mode in ('ordinary', 'cache'):
            try:
                row = records['MEASURE', mode, number]
                cpu = records['CPU', mode, number]
                workers, page_size = int(row['workers']), int(row['page_size'])
                elapsed = float(row['startup_seconds'])
                if (workers <= 0 or page_size < 4096 or page_size & (page_size - 1) or
                        int(cpu['workers']) != workers or not math.isfinite(elapsed) or elapsed <= 0 or
                        int(row['cache_processes']) != (workers if mode == 'cache' else 0)):
                    raise ValueError('inconsistent worker, page or cache mapping counts')
                if configuration is not None and configuration != (workers, page_size):
                    raise ValueError('worker count or page size changed within run')
                configuration = workers, page_size
                user, system = int(cpu['user_us']), int(cpu['system_us'])
                backing = int(row['cache_backing_pages'])
                if min(user, system, backing) < 0:
                    raise ValueError('negative CPU or backing residency')
                values[mode] = {
                    'startup_seconds': elapsed,
                    'cpu_seconds': (user + system) / 1_000_000,
                    'anonymous_object_growth_bytes': int(row['anonymous_object_growth_pages']) * page_size,
                    'unique_object_growth_bytes': int(row['unique_object_growth_pages']) * page_size,
                    'cache_backing_bytes': backing * page_size,
                }
                if values[mode]['cpu_seconds'] <= 0:
                    raise ValueError('zero worker CPU time')
            except (KeyError, ValueError) as exc:
                raise ValueError(f'invalid {mode} round {number}: {exc}') from exc
        if number < warmup_rounds:
            continue
        ordinary, cache = values['ordinary'], values['cache']
        pairs.append({
            'round': number, 'order': measurement_order[number], **values,
            'startup_ratio_cache_over_ordinary': cache['startup_seconds'] / ordinary['startup_seconds'],
            'cpu_ratio_cache_over_ordinary': cache['cpu_seconds'] / ordinary['cpu_seconds'],
            'anonymous_growth_difference_bytes': cache['anonymous_object_growth_bytes'] - ordinary['anonymous_object_growth_bytes'],
            'unique_growth_difference_bytes': cache['unique_object_growth_bytes'] - ordinary['unique_object_growth_bytes'],
        })
    if len(pairs) < 3:
        raise ValueError('at least three complete measured pairs are required after warmup')
    metadata = json.loads((directory / 'run.json').read_text())
    metrics = ('startup_ratio_cache_over_ordinary', 'cpu_ratio_cache_over_ordinary',
               'anonymous_growth_difference_bytes', 'unique_growth_difference_bytes')
    return {
        'schema': 'org.5bsd.elfcache.measurement.v1',
        'run_directory': str(directory.resolve()),
        'workers': configuration[0], 'page_size': configuration[1],
        'warmup_rounds_excluded': warmup_rounds,
        'paired_rounds': pairs,
        'pair_order_counts': {mode + '-first': sum(pair['order'][0] == mode for pair in pairs)
                              for mode in ('ordinary', 'cache')},
        'medians': {name: statistics.median(pair[name] for pair in pairs) for name in metrics},
        'provenance': metadata,
        'interpretation': [
            'Ratios above one mean the cache mode was slower or used more CPU.',
            'Positive growth differences mean greater observed residency growth in cache mode.',
            'Residency growth is a system delta including observer effects, not private process RSS.',
            'The cache backing exists in both modes; these deltas do not measure its full retention cost.',
            'Warm paired rounds do not establish cold-boot savings or statistical significance.',
            'Pair order counts expose fixed-order captures; counterbalance trial order in new runs.',
            'Inspect host load and repeat on an otherwise quiet host before a performance conclusion.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_directory', type=Path)
    parser.add_argument('--warmup-rounds', type=int, default=1)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = summarize(args.run_directory, args.warmup_rounds)
        with args.output.open('x') as stream:
            json.dump(result, stream, indent=2, allow_nan=False)
            stream.write('\n')
    except (OSError, ValueError) as exc:
        parser.exit(1, f'measure: {exc}\n')
    print(json.dumps(result['medians'], sort_keys=True))


if __name__ == '__main__':
    main()
