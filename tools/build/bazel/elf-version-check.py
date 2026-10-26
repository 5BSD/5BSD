#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare versioned dynamic symbol interfaces against an explicit Make artifact."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess


def parse(text):
    symbols = []
    for line in text.splitlines():
        match = re.match(r'^\s*\d+:\s+\S+\s+\d+\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)', line)
        if not match:
            continue
        kind, binding, visibility, index, name = match.groups()
        if binding in ('GLOBAL', 'WEAK') and index != 'UND':
            symbols.append((name, kind, binding, visibility))
    definitions = re.findall(r'Flags:\s+\w+\s+Index:\s+\d+\s+Cnt:\s+\d+\s+Name:\s+(\S+)', text)
    if not symbols or not definitions:
        raise ValueError('versioned dynamic interface missing')
    if len(symbols) != len(set(symbols)) or len(definitions) != len(set(definitions)):
        raise ValueError('ambiguous versioned interface')
    return {'exports': sorted(symbols), 'definitions': sorted(definitions)}


def compare(tool, candidate, reference, soname):
    helper = Path(__file__).with_name('elf-shared-check.py')
    spec = importlib.util.spec_from_file_location('elf_shared_check', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.compare(tool, candidate, reference, soname)
    for key, path in [('candidate', candidate), ('make_reference', reference)]:
        command = [str(tool), '--dyn-syms', '--version-info', str(path)]
        inspection = subprocess.run(command, text=True, check=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env={'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'})
        result[key]['version_command'] = command
        result[key]['version_stdout'] = inspection.stdout
        result[key]['version_stderr'] = inspection.stderr
        result[key]['versioned_interface'] = parse(inspection.stdout)
    if result['candidate']['versioned_interface'] != result['make_reference']['versioned_interface']:
        raise ValueError('versioned exported interface differs from Make reference')
    result['scope'] = 'versioned-exports-and-shared-metadata-comparison'
    # Symbol/version names and ELF metadata do not prove full calling-convention ABI parity.
    result['full_abi_parity'] = False
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('readelf', 'library', 'make-library', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--soname', required=True)
    a = p.parse_args()
    result = compare(a.readelf.resolve(strict=True), a.library.resolve(strict=True),
                     a.make_library.resolve(strict=True), a.soname)
    with a.output.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
