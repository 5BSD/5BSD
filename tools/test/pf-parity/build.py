#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build one PF parity image and bind it to its staged test selection."""
import argparse
from pathlib import Path
import re
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('directory', type=Path)
p.add_argument('tag')
a = p.parse_args()
b = a.directory.resolve()
if not str(b).startswith('/usr/obj/') or not re.fullmatch(r'[a-z0-9-]+', a.tag):
    p.error('use an object directory and alphanumeric tag')
meta = b/(a.tag+'-stage.json')
if meta.exists() or (b/('guest-'+a.tag+'.img')).exists():
    p.error('tag already exists; preserve prior evidence')
# Read before image construction. Do not modify this stage concurrently.
content = (b/'stage.json').read_bytes()
with meta.open('xb') as stream:
    stream.write(content)
subprocess.run([sys.executable, '/usr/src/tools/test/pf-consolidation/build-image.py',
                str(b), a.tag], check=True)
if (b/'stage.json').read_bytes() != content:
    raise RuntimeError('stage changed during construction; image is not qualified')
