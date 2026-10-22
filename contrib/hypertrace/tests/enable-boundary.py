#!/usr/bin/env python3.12
"""Compile and execute the current libdtrace enable body with a bounded driver."""
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[3]
source = (root / "cddl/contrib/opensolaris/lib/libdtrace/common/dt_program.c").read_text()
start = source.index("int\ndtrace_program_exec(")
end = source.index("\nint\ndtrace_vprobes_create(", start)
body = source[start:end]

with tempfile.TemporaryDirectory(prefix="hypertrace-enable-") as scratch:
    scratch = pathlib.Path(scratch)
    (scratch / "enable-boundary-impl.inc").write_text(body)
    binary = scratch / "enable-boundary"
    subprocess.run(
        ["cc", "-std=gnu11", "-fsanitize=address,undefined", "-Wall",
         "-Wextra", "-Werror", "-Wno-unused-variable",
         "-I", str(scratch), str(pathlib.Path(__file__).with_suffix(".c")),
         "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)
print("enable boundary: pass")
