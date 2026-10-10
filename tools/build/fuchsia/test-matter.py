#!/usr/bin/env python3.12
"""Run the imported Matter IDL tooling tests; this is not a Matter device test."""
import argparse
import os
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--src', type=Path, default=Path('/usr/src'))
p.add_argument('--python', default='/usr/obj/5bsd-matter-tools/bin/python')
a = p.parse_args()
source = a.src / 'contrib/connectedhomeip/scripts/py_matter_idl'
env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(source))
subprocess.run([a.python, '-m', 'unittest', 'discover', '-s', str(source / 'matter/idl'),
                '-p', 'test_*.py', '-v'], env=env, check=True)
