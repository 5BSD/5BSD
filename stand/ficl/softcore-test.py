#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare the declared generator with Make's ordered concatenation recipe."""
import argparse
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--generated", required=True)
parser.add_argument("--awk", required=True)
parser.add_argument("--script", required=True)
parser.add_argument("--sources", nargs="+", required=True)
args = parser.parse_args()
actual = Path(args.generated).read_bytes()
prefix = b"** Last update: "
lines = [line for line in actual.splitlines() if line.startswith(prefix)]
assert len(lines) == 1, "missing or repeated generation metadata"
datestamp = lines[0][len(prefix):].decode()
parts = [Path(name).read_bytes() for name in args.sources]
assert len(parts) == 6 and all(p.endswith(b"\n") for p in parts), "ordered concatenation requires newline-terminated inputs"
# Independent original recipe: one byte stream, not the rule's file operands.
reference = subprocess.run([args.awk, "-f", args.script, "-v", "datestamp=" + datestamp],
    input=b"".join(parts), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    env=dict(os.environ, LC_ALL="C"), check=True).stdout
assert actual == reference, "generated C differs from original concatenation recipe"
assert b"void ficlCompileSoftCore(FICL_SYSTEM *pSys)" in actual
print("PASS: ordered softwords, explicit metadata and complete original AWK output")
