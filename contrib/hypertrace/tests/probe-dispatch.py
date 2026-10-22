#!/usr/bin/env python3.12
"""Exercise the production virtual-probe result and VM lifetime checks."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / "sys/cddl/dev/hypertrace/hypertrace.c").read_text()
start = source.index("int\nhypertrace_probe(")
end = source.index("\n/*\n * Get the thread ID of the VM.", start)
fixture = Path(__file__).with_suffix(".c").read_text()
program = fixture.replace("/* FUNCTION */", source[start:end], 1)
with tempfile.TemporaryDirectory(prefix="hypertrace-probe-dispatch-") as directory:
    path = Path(directory)
    (path / "dispatch.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "dispatch.c"),
                    "-o", str(path / "dispatch")], check=True)
    subprocess.run([str(path / "dispatch")], check=True)
