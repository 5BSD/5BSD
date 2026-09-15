#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run Pi Wi-Fi host regressions; requires FreeBSD make/config and a C compiler.

The fixtures compile production function bodies with fake hardware dependencies.
They do not replace a kernel boot, WITNESS checks or tests on a Raspberry Pi.
"""
from pathlib import Path
import resource
import subprocess
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
failed = []
scripts = sorted(Path(__file__).resolve().parent.glob('*_test.py'))
for script in scripts:
    print(f'Running {script.name}', flush=True)
    try:
        subprocess.run([sys.executable, str(script)], check=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        failed.append(script.name)
print(f'{len(scripts) - len(failed)}/{len(scripts)} regression scripts passed.', flush=True)
if failed:
    print('Failed: ' + ', '.join(failed), file=sys.stderr)
    sys.exit(1)
