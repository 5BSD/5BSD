# SPDX-License-Identifier: BSD-2-Clause
"""Inspect the standalone archive; this is not firmware runtime qualification."""
import argparse
from pathlib import Path
import struct
import subprocess
import sys
import unittest

parser = argparse.ArgumentParser()
for name in ('archive', 'ar', 'nm'):
    parser.add_argument('--' + name, required=True, type=Path)
parser.add_argument('--machine', required=True, type=int)
parser.add_argument('--tool-inputs', required=True, nargs='+', type=Path)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining


def run(tool, *options, member=None, binary=False):
    runtime = [p for p in args.tool_inputs if p.resolve() not in [args.ar.resolve(), args.nm.resolve()]]
    env = {'LC_ALL': 'C'}
    if runtime:
        env['LD_LIBRARY_PATH'] = ':'.join(sorted({str(p.resolve(strict=True).parent) for p in runtime}))
    command = [str(tool), *options, str(args.archive)] + ([member] if member else [])
    return subprocess.run(command, env=env, check=True,
                          capture_output=True, text=not binary, timeout=20).stdout


def symbols(text):
    return {fields[0] for line in text.splitlines() if len(fields := line.split()) >= 2
            and len(fields[1]) == 1 and fields[1].isalpha()}


class BiosPlatform(unittest.TestCase):
    def test_make_selected_member_order(self):
        expected = 'amd64_tramp bio biosacpi biosdisk biosmem biosmemdisk biospci biospnp biossmap bootinfo bootinfo32 bootinfo64 comconsole devicename elf32_freebsd elf64_freebsd i386_copy i386_module multiboot multiboot_tramp nullconsole pxe pxetramp relocater_tramp spinconsole time textvidc vbe vidconsole teken'.split()
        self.assertEqual(run(args.ar, 't').splitlines(), [name + '.o' for name in expected])

    def test_every_member_target_abi(self):
        members = run(args.ar, 't').splitlines()
        self.assertTrue(members, 'empty archive')
        self.assertEqual(len(members), len(set(members)), 'duplicate member names')
        for member in members:
            data = run(args.ar, 'p', member=member, binary=True)
            with self.subTest(member=member):
                self.assertGreaterEqual(len(data), 64)
                self.assertEqual(data[:6], b'\x7fELF' + bytes([1 if args.machine == 3 else 2, 1]))
                self.assertEqual(struct.unpack_from('<H', data, 16)[0], 1)
                self.assertEqual(struct.unpack_from('<H', data, 18)[0], args.machine)
                if args.machine == 243:
                    self.assertEqual(struct.unpack_from('<I', data, 48)[0] & 6, 0,
                                     'loader RISC-V ABI must be soft float')

    def test_platform_api_and_stack_policy(self):
        undefined = symbols(run(args.nm, '--format=posix', '--undefined-only'))
        self.assertNotIn('__stack_chk_fail', undefined)
        defined = symbols(run(args.nm, '--format=posix', '--extern-only', '--defined-only'))
        self.assertTrue({'amd64_tramp', 'comconsole', 'biospci_read_config', 'pxe_enable', 'teken_init'} <= defined)


if __name__ == '__main__':
    unittest.main()
