#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run an explicit maintained digest-driver inventory against a private library."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('library', 'soname', 'inventory', 'tests', 'output'):
        parser.add_argument('--' + name, required=True, type=str if name == 'soname' else Path)
    parser.add_argument('--references', type=Path, help='separate maintained reference directory; defaults to tests')
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    inventory = args.inventory.resolve(strict=True)
    tests = args.tests.resolve(strict=True)
    references = (args.references or args.tests).resolve(strict=True)
    output = args.output.absolute()
    if not re.fullmatch(r'[A-Za-z0-9_.+-]+', args.soname):
        parser.error('soname must be a library basename')
    if output.exists() or not output.resolve().is_relative_to('/usr/obj'):
        parser.error('output must be a fresh path under /usr/obj')
    if ':' in str(output) or '\n' in str(output):
        parser.error('output cannot contain loader path separators or newlines')
    data = json.loads(inventory.read_text())
    names = [entry['program'] for entry in data['drivers']]
    if not names or len(set(names)) != len(names):
        parser.error('inventory must contain unique drivers')
    inputs = {str(library): digest(library), str(inventory): digest(inventory)}
    cases = []
    for name in names:
        if not re.fullmatch(r'[A-Za-z0-9_]+driver', name):
            parser.error('invalid driver basename: ' + name)
        driver, reference = tests / name, references / (name[:-6] + '.ref')
        for path, parent in ((driver, tests), (reference, references)):
            if not path.resolve(strict=True).is_relative_to(parent):
                parser.error('test input escapes selected test tree')
            inputs[str(path)] = digest(path)
        if driver.stat().st_mode & 0o6000:
            parser.error('privileged test drivers are not supported')
        cases.append((name, driver, reference))
    output.mkdir(parents=True)
    private_lib = output / args.soname
    private_lib.symlink_to(library)
    environment = {'PATH': '/bin:/usr/bin', 'LC_ALL': 'C', 'LD_LIBRARY_PATH': str(output)}
    receipt = {'scope': 'explicit digest-driver inventory against selected shared library; not installation/package qualification',
               'status': 'running', 'inputs': inputs, 'checks': []}
    try:
        for name, driver, reference in cases:
            trace = subprocess.run([str(driver)], env={**environment, 'LD_TRACE_LOADED_OBJECTS': '1'},
                                   capture_output=True, text=True, timeout=20)
            (output / (name + '.loader.txt')).write_text(trace.stdout + trace.stderr)
            # Match the resolved library field, not an incidental substring.
            selected = any(line.strip().split()[:3] == [args.soname, '=>', str(private_lib)]
                           for line in trace.stdout.splitlines())
            if trace.returncode or not selected:
                raise RuntimeError(name + ': selected library was not loaded')
            result = subprocess.run([str(driver)], env=environment, capture_output=True, timeout=20)
            (output / (name + '.stdout')).write_bytes(result.stdout)
            (output / (name + '.stderr')).write_bytes(result.stderr)
            passed = result.returncode == 0 and result.stdout == reference.read_bytes()
            receipt['checks'].append({'driver': name, 'status': result.returncode, 'passed': passed})
            if not passed:
                raise RuntimeError(name + ': digest output differs from reference')
        for path, expected in inputs.items():
            if digest(Path(path)) != expected:
                raise RuntimeError('input changed during qualification: ' + path)
        receipt['status'] = 'passed'
    except Exception as error:
        receipt['status'] = 'failed'
        receipt['error'] = str(error)
        raise
    finally:
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'drivers': len(cases), 'receipt': str(output / 'receipt.json')}))


if __name__ == '__main__':
    main()
