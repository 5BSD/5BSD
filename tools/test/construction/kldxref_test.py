# SPDX-License-Identifier: BSD-2-Clause
"""Adapt the unchanged module audit CLI to Bazel's runfiles and output protocol."""
import os
from pathlib import Path
import runpy
import shutil
import sys

root = Path(sys.argv[1]).absolute()
mode = sys.argv[2]
# Select the candidate loader environment only after the SDK Python has started.
# Each audit's kldxref subprocess inherits this; Python itself uses its SDK runtime.
os.environ['LD_LIBRARY_PATH'] = str(root / 'lib')
work = Path(os.environ['TEST_TMPDIR']) / 'audit'
sys.argv = [str(root / 'audit.py'), '--kldxref', str(root / 'kldxref'), '--work', str(work)]
if mode == 'kldxref':
    sys.argv += ['--module', str(root / 'fixtures/pnp-0.ko')]
else:
    sys.argv += ['--fixtures', str(root / 'fixtures')]
try:
    runpy.run_path(str(root / 'audit.py'), run_name='__main__')
finally:
    # Only regular reports belong in collected outputs. Audit work may contain
    # deliberately hostile filesystem objects (including FIFOs and symlinks).
    report = work / 'result.json'
    if report.is_file():
        shutil.copyfile(report, Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']) / 'result.json')
