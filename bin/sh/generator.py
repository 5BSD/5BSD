#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Execute a shell build generator in its declared output directory."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir', required=True)
parser.add_argument('--tool', required=True)
parser.add_argument('--tool-path')
parser.add_argument('--argument', action='append', default=[])
args = parser.parse_args()
command = [str(Path(p).resolve(strict=True)) for p in [args.tool, *args.argument]]
directory = Path(args.output_dir).absolute()
directory.mkdir(parents=True, exist_ok=True)
environment = dict(os.environ, LC_ALL='C', TMPDIR=str(directory),
                   PATH=str(Path(args.tool_path).absolute()) if args.tool_path else '')
result = subprocess.run(command, cwd=directory, env=environment, stderr=subprocess.PIPE)
sys.stderr.buffer.write(result.stderr)
# These four maintained generators have no successful stderr diagnostics.
# Shell pipelines can otherwise hide a missing subprocess behind a zero exit.
raise SystemExit(result.returncode or (1 if result.stderr else 0))
