#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production arm64 guest probe entry: the registers are read
into the handle before the stage 2 pmap is locked, and the probe reads only
that copy."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
header = (root / "sys/arm64/include/vmm.h").read_text()
vmm = (root / "sys/arm64/vmm/vmm.c").read_text()

def between(source, start, end):
    first = source.index(start)
    return source[first:source.index(end, first) + len(end)]

program = Path(__file__).with_suffix(".c").read_text()
for marker, text in (
    ("/* ENUM */", between(header, "enum vm_reg_name {", "\n};\n")),
    ("/* HANDLE */", between(header, "struct vm_hdl {", "\n};\n")),
    ("/* SNAPSHOT */", between(vmm,
        "static const int vm_hypertrace_regs[] = {",
        "\t*value = vhdl->regs[reg];\n\treturn (0);\n}\n")),
    ("/* ENTRY */", between(vmm, "static uint64_t\nvm_hypertrace_probe(",
        "\n}\n"))):
    if program.count(marker) != 1:
        raise SystemExit("fixture marker: " + marker)
    program = program.replace(marker, text, 1)
with tempfile.TemporaryDirectory(prefix="hypertrace-arm64-entry-") as work:
    source = Path(work) / "arm64-probe-entry.c"
    source.write_text(program)
    binary = source.with_suffix("")
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
        str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
