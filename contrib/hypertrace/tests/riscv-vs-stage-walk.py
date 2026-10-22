#!/usr/bin/env python3.12
"""Compile the production RISC-V page walk into a native fake-memory fixture."""
from pathlib import Path
import subprocess
import tempfile

source_root = Path(__file__).resolve().parents[3]
source = (source_root / "sys/riscv/vmm/vmm_riscv.c").read_text()
start = source.index("int\nvmmops_gla2gpa(")
end = source.index("\nvoid\nriscv_send_ipi(", start)
fixture = Path(__file__).with_suffix(".c").read_text()
program = fixture.replace("/* FUNCTION */", source[start:end], 1)
with tempfile.TemporaryDirectory(prefix="hypertrace-riscv-walk-") as directory:
    path = Path(directory)
    (path / "walk.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "walk.c"),
                    "-o", str(path / "walk")], check=True)
    subprocess.run([str(path / "walk")], check=True)
