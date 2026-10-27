# SPDX-License-Identifier: BSD-2-Clause
"""Generate the upstream test registry from explicitly selected test sources."""
import sys
from pathlib import Path
output, *sources = sys.argv[1:]
lines = []
for source in sources:
    lines.extend(line for line in Path(source).read_text().splitlines(keepends=True) if "DEFINE_TEST" in line)
if not lines:
    raise SystemExit("empty libarchive test registry")
Path(output).write_text("".join(lines))
