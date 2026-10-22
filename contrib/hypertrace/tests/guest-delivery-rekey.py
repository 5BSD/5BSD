#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the real durable guest journal code and resumed rekey."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
tests = Path(__file__).resolve().parent
command = [
    'c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
    '-Wno-unused-parameter', '-fsanitize=address,undefined',
    '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
    '-Wl,--wrap=fsync', '-Wl,--unresolved-symbols=ignore-all',
    '-I' + str(root / 'usr.sbin/dtraced'),
    '-I' + str(root / 'sys/dev/dttransport'),
    '-I' + str(root / 'sys'),
    '-I' + str(root / 'contrib/libucl/include'),
    str(tests / 'guest-delivery-rekey.cc'),
    str(root / 'usr.sbin/dtraced/dtraced_directory.cc'),
    '-o', str(out / 'guest-delivery-rekey-test'),
    '-lcrypto', '-lutil', '-pthread',
]
subprocess.run(command, check=True)
subprocess.run([str(out / 'guest-delivery-rekey-test')], check=True,
               timeout=30)
