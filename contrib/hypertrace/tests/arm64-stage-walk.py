#!/usr/bin/env python3.12
"""Run the production Arm64 stage-one walker against guarded 16K tables."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / "sys/arm64/vmm/vmm_arm64.c").read_text()
start = source.index("static void\nptp_release(")
end = source.index("\nint\nvmmops_run(", start)
fixture = Path(__file__).with_suffix(".c").read_text()
program = fixture.replace("/* FUNCTION */", source[start:end], 1)
with tempfile.TemporaryDirectory(prefix="hypertrace-arm64-walk-") as directory:
    path = Path(directory)
    (path / "walk.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "walk.c"),
                    "-o", str(path / "walk")], check=True)
    subprocess.run([str(path / "walk")], check=True)
