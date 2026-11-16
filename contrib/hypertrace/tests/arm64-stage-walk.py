#!/usr/bin/env python3.12
"""Run the production Arm64 stage-one walker against guarded 16K tables."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / "sys/arm64/vmm/vmm_arm64.c").read_text()
# The table-page helpers, then the walker and vmmops_gla2gpa(); the
# probe-context stage 2 helpers between them are tested by
# arm64-hypertrace-copy.py.
start = source.index("/* Inline: the probe context walk calls it")
end = source.index("\n/*\n * DTrace probe context can neither fault", start)
walk_start = source.index("/* log2 of the number of bytes in a page table entry */")
walk_end = source.index("\n/*\n * Copy len bytes to or from guest virtual",
    walk_start)
fixture = Path(__file__).with_suffix(".c").read_text()
program = fixture.replace("/* FUNCTION */",
    source[start:end] + "\n" + source[walk_start:walk_end], 1)
with tempfile.TemporaryDirectory(prefix="hypertrace-arm64-walk-") as directory:
    path = Path(directory)
    (path / "walk.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "walk.c"),
                    "-o", str(path / "walk")], check=True)
    subprocess.run([str(path / "walk")], check=True)
