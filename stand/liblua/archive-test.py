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
EXPECTED = "lapi lcode lctype ldebug ldo ldump lfunc lgc llex lmem lobject lopcodes lparser lstate lstring ltable ltm lundump lvm lzio lauxlib lbaselib lstrlib loadlib lerrno lpager lstd lutils gfx_utils lfs lhash".split()


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


class StandaloneLua(unittest.TestCase):
    def test_make_selected_archive_members(self):
        self.assertEqual(run(args.ar, 't').splitlines(), [name + '.o' for name in EXPECTED])

    def test_every_member_target_abi(self):
        for member in run(args.ar, 't').splitlines():
            data = run(args.ar, 'p', member=member, binary=True)
            with self.subTest(member=member):
                self.assertGreaterEqual(len(data), 64)
                self.assertEqual(data[:6], b'\x7fELF\x02\x01')
                self.assertEqual(struct.unpack_from('<H', data, 16)[0], 1)
                self.assertEqual(struct.unpack_from('<H', data, 18)[0], args.machine)
                if args.machine == 243:
                    self.assertEqual(struct.unpack_from('<I', data, 48)[0] & 6, 0,
                                     'loader RISC-V ABI must be soft float')

    def test_loader_api_and_stdio_isolation(self):
        defined = symbols(run(args.nm, '--format=posix', '--extern-only', '--defined-only'))
        self.assertTrue({'lua_newstate', 'luaL_newstate', 'luaopen_loader', 'lua_loader_fopen'} <= defined)
        undefined = symbols(run(args.nm, '--format=posix', '--undefined-only'))
        self.assertFalse({'__stack_chk_fail', 'fopen', 'fclose', 'fread', 'opendir', 'closedir'} & undefined)


if __name__ == '__main__':
    unittest.main()
