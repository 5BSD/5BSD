# SPDX-License-Identifier: BSD-2-Clause
"""Run makeobjops with declared tools, preserving errors and stable provenance."""
import os
from pathlib import Path
import subprocess
import sys

awk, generator, interface, tools = [Path(p).absolute() for p in sys.argv[1:5]]
libraries = [Path(p).absolute() for p in sys.argv[5:]]
env = dict(os.environ, PATH=str(tools), LC_ALL="C")
if libraries:
    env["LD_LIBRARY_PATH"] = ":".join(dict.fromkeys(str(p.parent) for p in libraries))
# makeobjops calls system(), whose /bin/sh is a host execution dependency.
# Its mv/rm commands resolve only through the declared tool directory.
subprocess.run([str(awk), "-f", str(generator), interface.name, "-c", "-h"],
               cwd=interface.parent, env=env, check=True)
