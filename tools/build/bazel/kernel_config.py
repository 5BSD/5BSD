# SPDX-License-Identifier: BSD-2-Clause
"""Invoke config without embedding an absolute action root into its Makefile."""
import os
from pathlib import Path
import subprocess
import sys

program, config, anchor, output = [Path(p).absolute() for p in sys.argv[1:5]]
debug = sys.argv[5] == '1'
libraries = [Path(p).absolute() for p in sys.argv[6:]]
env = dict(os.environ)
if libraries:
    env['LD_LIBRARY_PATH'] = ':'.join(dict.fromkeys(str(p.parent) for p in libraries))
# config uses -s only for the generated Makefile's S variable. Relative to its
# output directory, this remains usable and independent of the action root.
source_root = anchor.parent.parent
command = [str(program)] + (['-g'] if debug else [])
command += ['-d', str(output), '-s', os.path.relpath(source_root, output), config.name]
subprocess.run(command, cwd=config.parent, env=env, check=True)
