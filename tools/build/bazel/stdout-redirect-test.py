#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check the declared generator launcher, including failure propagation."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--helper', type=Path, required=True)
args = parser.parse_args()
helper = args.helper.resolve(strict=True)
with tempfile.TemporaryDirectory(prefix='bsd-redirect-') as directory:
    root = Path(directory)
    for executable in (False, True):
        target = root / ('executable' if executable else 'data')
        command = [str(helper)] + (['--executable'] if executable else [])
        subprocess.run(command + [str(target), '/usr/bin/printf', '%s', 'literal $data; no shell'], check=True)
        assert target.read_bytes() == b'literal $data; no shell'
        assert bool(target.stat().st_mode & 0o111) == executable
    missing = subprocess.run([str(helper), str(root / 'missing'), str(root / 'no-generator')], capture_output=True)
    assert missing.returncode != 0
    partial = root / 'partial'
    failure = subprocess.run([str(helper), '--executable', str(partial), '/bin/sh', '-c', 'printf partial; exit 17'], capture_output=True)
    assert failure.returncode == 17 and partial.read_bytes() == b'partial'
    invalid = subprocess.run([str(helper), '--executable'], capture_output=True)
    assert invalid.returncode != 0
    source = root / 'input'
    source.write_bytes(bytes(range(256)) * 17)
    for executable in (False, True):
        target = root / ('stdin-executable' if executable else 'stdin-data')
        command = [str(helper)] + (['--executable'] if executable else [])
        subprocess.run(command + ['--stdin', str(source), str(target), '/bin/cat'], check=True)
        assert target.read_bytes() == source.read_bytes()
        assert bool(target.stat().st_mode & 0o111) == executable
    target = root / 'missing-input-output'
    missing_input = subprocess.run([str(helper), '--stdin', str(root / 'absent'), str(target), '/bin/cat'], capture_output=True)
    assert missing_input.returncode != 0 and not target.exists()
    failure = subprocess.run([str(helper), '--stdin', str(source), str(root / 'stdin-failure'), '/bin/sh', '-c', 'cat; exit 19'], capture_output=True)
    assert failure.returncode == 19
    assert (root / 'stdin-failure').read_bytes() == source.read_bytes()
print('PASS: output modes, literal data, declared stdin, missing inputs/tools, child failures and usage errors')
