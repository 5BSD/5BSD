# SPDX-License-Identifier: BSD-2-Clause
"""Inspect native EFI archive/terminal generation; no firmware execution."""
import argparse
from pathlib import Path
import struct
import subprocess
import sys
import unittest

parser = argparse.ArgumentParser()
for name in ('archive', 'ar', 'nm', 'awk', 'generator', 'sequences', 'state-header'):
    parser.add_argument('--' + name, required=True, type=Path)
parser.add_argument('--clock', required=True)
parser.add_argument('--zfs', required=True, choices=['yes', 'no'])
parser.add_argument('--machine', required=True, type=int)
parser.add_argument('--tool-inputs', required=True, nargs='+', type=Path)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining
EXPECTED = "delay devicename devpath efi_console efi_driver_utils efichar eficom efienv efihttp efinet efipart efizfs env errno handles libefi wchar teken".split()


def run(tool, *options, member=None, binary=False):
    runtime = [p for p in args.tool_inputs if p.resolve() not in [args.ar.resolve(), args.nm.resolve(), args.awk.resolve()]]
    env = {'LC_ALL': 'C'}
    if runtime:
        env['LD_LIBRARY_PATH'] = ':'.join(sorted({str(p.resolve(strict=True).parent) for p in runtime}))
    command = [str(tool), *options, str(args.archive)] + ([member] if member else [])
    return subprocess.run(command, env=env, check=True,
                          capture_output=True, text=not binary, timeout=20).stdout


def symbols(text):
    return {fields[0] for line in text.splitlines() if len(fields := line.split()) >= 2
            and len(fields[1]) == 1 and fields[1].isalpha()}


class EfiLibrary(unittest.TestCase):
    def test_make_selected_archive_members(self):
        self.assertEqual(run(args.ar, 't').splitlines(), [name + '.o' for name in EXPECTED] + [args.clock])

    def test_every_member_target_abi(self):
        for member in run(args.ar, 't').splitlines():
            data = run(args.ar, 'p', member=member, binary=True)
            with self.subTest(member=member):
                self.assertGreaterEqual(len(data), 64)
                self.assertEqual(data[:6], b'\x7fELF' + bytes([1 if args.machine == 3 else 2, 1]))
                self.assertEqual(struct.unpack_from('<H', data, 16)[0], 1)
                self.assertEqual(struct.unpack_from('<H', data, 18)[0], args.machine)
                if args.machine == 243:
                    self.assertEqual(struct.unpack_from('<I', data, 48)[0] & 6, 0,
                                     'loader RISC-V ABI must be soft float')

    def test_firmware_api_and_zfs_selection(self):
        defined = symbols(run(args.nm, '--format=posix', '--extern-only', '--defined-only'))
        self.assertTrue({'efi_getdev', 'efi_find_handle', 'efi_init_environment', 'teken_input', 'efi_time_init'} <= defined)
        self.assertEqual('efizfs_get_zfsinfo_list' in defined, args.zfs == 'yes')
        undefined = symbols(run(args.nm, '--format=posix', '--undefined-only'))
        self.assertNotIn('__stack_chk_fail', undefined)

    def test_terminal_generator_matches_original_recipe(self):
        runtime = [p for p in args.tool_inputs if p.resolve() not in [args.ar.resolve(), args.nm.resolve(), args.awk.resolve()]]
        env = {'LC_ALL': 'C'}
        if runtime:
            env['LD_LIBRARY_PATH'] = ':'.join(sorted({str(p.resolve(strict=True).parent) for p in runtime}))
        original = subprocess.run([str(args.awk), '-f', str(args.generator), str(args.sequences)],
                                  env=env, check=True, capture_output=True, timeout=20).stdout
        self.assertEqual(args.state_header.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
