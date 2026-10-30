#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Bind cold populated-state readback to its selected receipts and unchanged disk."""
import argparse
import hashlib
import json
from pathlib import Path
from state_readback import selection


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def collect(work, selected, disk):
    work, selected, disk = Path(work), Path(selected), Path(disk)
    if selected.is_symlink() or not selected.is_file() or disk.is_symlink() or not disk.is_file():
        raise ValueError('selected state evidence and disk must be regular nonsymlink files')
    selected_bytes = selected.read_bytes()
    document = json.loads(selected_bytes)
    rows, initialized = selection(document)
    if not initialized:
        raise ValueError('populated-state acceptance requires completed initialization')
    expected = document['output_disk_sha256']
    result_bytes = (work / 'result.json').read_bytes()
    serial_bytes = (work / 'serial.log').read_bytes()
    result = json.loads(result_bytes)
    serial_hash = hashlib.sha256(serial_bytes).hexdigest()
    if (result.get('result') != 'PASS' or result.get('forced_termination') is not False or
            result.get('qemu_exit') != 0 or result.get('input_disk_readonly') is not True or
            result.get('input_disk') != str(disk.resolve(strict=True)) or
            result.get('input_disk_sha256') != expected or
            result.get('input_disk_final_sha256') != expected or
            result.get('serial_sha256') != serial_hash):
        raise ValueError('cold-readback VM did not finish with the selected unchanged input')
    prefix = 'STATE_READBACK_PASS '
    reports = [json.loads(line[len(prefix):]) for line in serial_bytes.decode().splitlines()
               if line.startswith(prefix)]
    if len(reports) != 1:
        raise ValueError('requires exactly one cold-readback report')
    report = reports[0]
    selected_hash = hashlib.sha256(selected_bytes).hexdigest()
    if (not isinstance(report, dict) or report.get('contents_verified') is not True or
            report.get('runtime_qualified') is not False or
            type(report.get('bindings')) is not int or report['bindings'] != len(rows) or
            report.get('allocation_sha256') != selected_hash or
            report.get('expected_disk_sha256') != expected):
        raise ValueError('cold-readback report differs from selected populated state')
    if digest(disk) != expected:
        raise ValueError('state disk changed after VM readback')
    return dict(format=1, scope='populated-state-cold-readback', result='PASS',
        disk_sha256=expected, initialization_sha256=selected_hash,
        vm_result_sha256=hashlib.sha256(result_bytes).hexdigest(), serial_sha256=serial_hash,
        report=report, generation_authenticated=False, runtime_qualified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('vm-work', 'initialization', 'input-disk', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error('output must be new')
    report = collect(args.vm_work, args.initialization, args.input_disk)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')


if __name__ == '__main__':
    main()
