#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect real regular/private standalone archives without executing target code."""
import argparse
import os
from pathlib import Path
import subprocess
import unittest
from elf_object_contract import contract

parser = argparse.ArgumentParser()
for name in ['regular', 'private', 'ar']:
    parser.add_argument('--' + name, required=True)
parser.add_argument('--runtime', nargs='+', required=True)
args = parser.parse_args()
root = Path(os.environ['TEST_SRCDIR'])
regular, private, ar = [root / value for value in [args.regular, args.private, args.ar]]
runtime = [root / p for p in args.runtime]
env = dict(LC_ALL='C', LD_LIBRARY_PATH=':'.join(sorted({str(p.resolve().parent) for p in runtime})))


def objects(archive):
    names = subprocess.check_output([str(ar), 't', str(archive)], env=env, text=True).splitlines()
    if not names or len(names) != len(set(names)):
        raise ValueError('nonempty archive with unique member names required')
    return {name: contract(subprocess.check_output([str(ar), 'p', str(archive), name], env=env)) for name in names}


archives = [objects(regular), objects(private)]


def defined(members):
    return {symbol['name'] for entry in members.values() for symbol in entry['external'] if symbol['section'] != 0}


class StandaloneArchive(unittest.TestCase):
    def test_every_member_is_actual_ia32(self):
        for members in archives:
            for name, entry in members.items():
                with self.subTest(member=name):
                    self.assertEqual(entry['identity']['elf_class'], 1)
                    self.assertEqual(entry['identity']['machine'], 3)

    def test_standalone_api_and_assembler_are_present(self):
        for members in archives:
            self.assertTrue({'_setjmp.o', 'hypervisor.o', 'ffs_subr.o', 'zfs.o'} <= members.keys())
            self.assertTrue({'_setjmp', '_longjmp', 'open', 'close'} <= defined(members))

    def test_verifier_is_private_to_efi_context(self):
        symbols = {'verify_file', 'br_rsa_i31_public'}
        self.assertFalse(symbols & defined(archives[0]))
        self.assertTrue(symbols <= defined(archives[1]))

    def test_no_host_stack_protector_dependency(self):
        for members in archives:
            undefined = {symbol['name'] for entry in members.values() for symbol in entry['external'] if symbol['section'] == 0}
            self.assertFalse({'__stack_chk_fail', '__stack_chk_guard'} & undefined)


if __name__ == '__main__':
    unittest.main(argv=[__file__], verbosity=2)
