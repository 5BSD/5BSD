#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise kernel debug checks against real split artifacts, including rejection."""
import argparse
import importlib.util
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--debug', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('elf_debug_check', Path(__file__).with_name('elf-debug-check.py'))
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    result = checker.verify(args.binary, args.debug, kernel=True)
    cases = []

    def reject(name, operation, message):
        try:
            operation()
        except ValueError as error:
            assert message in str(error), str(error)
            cases.append(dict(case=name, diagnostic=str(error)))
        else:
            raise AssertionError(name + ': invalid kernel debug pairing accepted')

    reject('userland-mode', lambda: checker.verify(args.binary, args.debug),
           'installed binary retains static symbol sections')
    reject('module-mode', lambda: checker.verify(args.binary, args.debug, module=True),
           'kernel module must be relocatable or shared ELF')
    reject('conflicting-modes', lambda: checker.verify(args.binary, args.debug, module=True, kernel=True),
           'choose kernel or module')
    changed = bytearray(args.debug.read_bytes())
    changed[-1] ^= 1
    corrupt = out / args.debug.name
    corrupt.write_bytes(changed)
    reject('corrupt-debug', lambda: checker.verify(args.binary, corrupt, kernel=True),
           'debug link CRC differs')
    wrong_name = out / 'wrong-name.debug'
    wrong_name.write_bytes(args.debug.read_bytes())
    reject('wrong-name', lambda: checker.verify(args.binary, wrong_name, kernel=True),
           'debug link name differs')
    (out / 'receipt.json').write_text(json.dumps(dict(status='passed', positive=result, rejected=cases), indent=2) + '\n')
    print('Kernel debug pairing and five real-artifact rejection cases passed')


if __name__ == '__main__':
    main()
