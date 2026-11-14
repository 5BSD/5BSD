# SPDX-License-Identifier: BSD-2-Clause
"""Inspect real target/host preprocessing without executing target code."""
import os
from pathlib import Path
import platform
import re
import struct
import sys


def inspect(path, cpu, pointer_bytes):
    text = path.read_text()
    values = {}
    for key in ('CPU', 'POINTER_BYTES', 'OS_VERSION'):
        found = re.findall(r'^BSD_CPP_' + key + r' ([A-Za-z0-9_]+)$', text, re.M)
        if len(found) != 1:
            raise ValueError('one expanded ' + key + ' required')
        values[key] = found[0]
    if values['CPU'] != cpu or int(values['POINTER_BYTES']) != pointer_bytes:
        raise ValueError('preprocessor selected the wrong ABI')
    if int(values['OS_VERSION']) <= 0:
        raise ValueError('declared OS header version required')


root = Path(os.environ['TEST_SRCDIR'])
target, host = [root / name for name in sys.argv[1:3]]
inspect(target, sys.argv[3], 8)
host_cpu = {'x86_64': 'amd64', 'amd64': 'amd64', 'arm64': 'aarch64',
            'aarch64': 'aarch64', 'riscv64': 'riscv64'}[platform.machine()]
inspect(host, host_cpu, struct.calcsize('P'))
try:
    inspect(target, 'deliberately_wrong_cpu', 8)
except ValueError:
    pass
else:
    raise AssertionError('incorrect ABI accepted')
print('Target and execution preprocessing use their declared ABI and OS headers')
