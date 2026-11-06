# SPDX-License-Identifier: BSD-2-Clause
"""Invoke config without embedding an absolute action root into its Makefile."""
import json
import os
from pathlib import Path
import subprocess
import sys
from kernel_options import validate_directory

program, config, anchor, output = [Path(p).absolute() for p in sys.argv[1:5]]
identity = Path(sys.argv[5]).absolute()
debug = sys.argv[6] == '1'
overrides = Path(sys.argv[7]).absolute()
manifest = Path(sys.argv[8]).absolute()
expectation = Path(sys.argv[9]).absolute()
libraries = [Path(p).absolute() for p in sys.argv[10:]]
env = dict(os.environ)
if libraries:
    env['LD_LIBRARY_PATH'] = ':'.join(dict.fromkeys(str(p.parent) for p in libraries))
# config uses -s only for the generated Makefile's S variable. Relative to its
# output directory, this remains usable and independent of the action root.
source_root = anchor.parent.parent
# Keep the original parser and include resolution. A declared override list
# controls both native config and Bazel source selection.
active_config = overrides if overrides.read_text() else config
command = [str(program), '-J'] + (['-g'] if debug else [])
command += ['-d', str(output), '-s', os.path.relpath(source_root, output), str(active_config)]
subprocess.run(command, cwd=config.parent, env=env, check=True)
validate_directory(output, json.loads(expectation.read_text()))

# Ask the same parser for the resolved identity; do not parse its Makefile.
result = subprocess.run([str(program), '-i', '-s', str(source_root), str(active_config)],
                        cwd=config.parent, env=env, check=True, capture_output=True)
identity.write_bytes(result.stdout)

# Forward the parser-owned inventory as an explicit artifact, not a tree lookup.
manifest.write_bytes((output / "kernel-inputs.json").read_bytes())
