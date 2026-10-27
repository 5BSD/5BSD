#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare serial/parallel configuration exports without masking graph changes."""
import argparse
from collections import Counter
import json
from pathlib import Path
from libmd_environment import digest


def compare(left, right):
    def normalized(plan):
        if plan.get('format') != 1 or plan.get('status') != 'configured':
            raise ValueError('configured format-1 component plan required')
        result = dict(plan)
        for field in ('elapsed_seconds', 'configuration_jobs'):
            result.pop(field, None)
        environment = dict(result['build_environment'])
        commands = environment.pop('commands')
        if not commands or any(command['status'] != 0 for command in commands):
            raise ValueError('successful configuration query inventory required')
        result['build_environment'] = environment
        return result, Counter(json.dumps(command, sort_keys=True) for command in commands)
    left_graph, left_queries = normalized(left)
    right_graph, right_queries = normalized(right)
    if left_graph != right_graph:
        raise ValueError('configuration content differs')
    if left_queries != right_queries:
        raise ValueError('configuration query inventory differs')
    return {'status': 'passed', 'queries': sum(left_queries.values()),
            'scope': 'configuration equality excluding elapsed time, worker count and query order; not build qualification'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--left', type=Path, required=True)
    parser.add_argument('--right', type=Path, required=True)
    args = parser.parse_args()
    paths = [args.left.resolve(strict=True), args.right.resolve(strict=True)]
    before = [digest(path) for path in paths]
    result = compare(*(json.loads(path.read_text()) for path in paths))
    if before != [digest(path) for path in paths]:
        raise ValueError('configuration receipt changed during comparison')
    result['plans'] = [{'path': str(path), 'sha256': sha} for path, sha in zip(paths, before)]
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
