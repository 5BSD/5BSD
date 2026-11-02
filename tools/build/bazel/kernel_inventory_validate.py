# SPDX-License-Identifier: BSD-2-Clause
"""Reject drift between explicit native metadata and parser-resolved inputs."""
import json
from pathlib import Path
import sys


def validate(actual, expected):
    if not isinstance(actual, dict) or type(actual.get('format')) is not int or actual['format'] != 1:
        raise ValueError('unsupported kernel inventory format')
    if actual != expected:
        for field in ('kernel_identity', 'machine', 'machine_arch'):
            if actual.get(field) != expected.get(field):
                raise ValueError('kernel inventory identity mismatch: ' + field)
        actual_rows, expected_rows = actual.get('inputs', []), expected['inputs']
        for index, (left, right) in enumerate(zip(actual_rows, expected_rows)):
            if left != right:
                raise ValueError('kernel inventory drift at input %d: parser=%r native=%r' % (index, left, right))
        raise ValueError('kernel inventory drift: native selection or schema differs from parser')
    return dict(format=1, status='passed', kernel_identity=actual['kernel_identity'],
                machine=actual['machine'], machine_arch=actual['machine_arch'],
                selected_inputs=len(actual['inputs']),
                selected_objects=sum(row['object'] is not None for row in actual['inputs']))


def main():
    actual, expected, output = map(Path, sys.argv[1:])
    result = validate(json.loads(actual.read_text()), json.loads(expected.read_text()))
    output.write_text(json.dumps(result, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
