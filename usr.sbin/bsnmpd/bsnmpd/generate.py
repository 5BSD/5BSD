#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run gensnmptree with explicit inputs and a declared output directory."""
import argparse
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--generator", type=Path, required=True)
p.add_argument("--source", type=Path, required=True)
p.add_argument("--include", type=Path, action="append", default=[])
p.add_argument("--output-dir", type=Path, required=True)
p.add_argument("--symbol", action="append", default=[])
a = p.parse_args()
generator = a.generator.resolve(strict=True)
source = a.source.resolve(strict=True)
includes = [str(path.resolve(strict=True).parent) for path in a.include]
out = a.output_dir.resolve()
out.mkdir(parents=True, exist_ok=True)
command = [str(generator)]
for directory in dict.fromkeys(includes):
    command += ["-I", directory]
with source.open("rb") as stream:
    subprocess.run(command + ["-l", "-f"], stdin=stream, cwd=out, check=True)
with source.open("rb") as stream, (out / "oid.h").open("wb") as output:
    subprocess.run(command + ["-e", *a.symbol], stdin=stream, stdout=output, cwd=out, check=True)
