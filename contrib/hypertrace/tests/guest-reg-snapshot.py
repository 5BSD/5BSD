#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production guest register snapshot of the amd64 and arm64
VMMs against the registers dtrace_guest_reg_name() lets a D program name."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
dtrace = (root /
    "sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c").read_text()
fixture = Path(__file__).with_suffix(".c").read_text()

def between(source, start, end):
    first = source.index(start)
    return source[first:source.index(end, first) + len(end)]

name = between(dtrace, "static int\ndtrace_guest_reg_name(uint_t ndx)\n{",
    "\n}\n")
# (architecture, regset.h directory, registers a D program can name)
targets = (("amd64", "x86", 24), ("arm64", "aarch64", 33))
with tempfile.TemporaryDirectory(prefix="hypertrace-reg-snapshot-") as work:
    for arch, regset, named in targets:
        header = (root / "sys" / arch / "include/vmm.h").read_text()
        vmm = (root / "sys" / arch / "vmm/vmm.c").read_text()
        program = fixture
        for marker, text in (
            ("/* REGSET */", (root / "sys/cddl/dev/dtrace" / regset /
                "regset.h").read_text()),
            ("/* ENUM */", between(header, "enum vm_reg_name {", "\n};\n")),
            ("/* HANDLE */", between(header, "struct vm_hdl {", "\n};\n")),
            ("/* SNAPSHOT */", between(vmm,
                "static const int vm_hypertrace_regs[] = {",
                "\t*value = vhdl->regs[reg];\n\treturn (0);\n}\n")),
            ("/* NAME */", name)):
            if program.count(marker) != 1:
                raise SystemExit("fixture marker: " + marker)
            program = program.replace(marker, text, 1)
        source = Path(work) / (arch + ".c")
        source.write_text(program)
        binary = source.with_suffix("")
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
            "-DFIXTURE_" + arch.upper(), "-DNAMED_REGISTERS=" + str(named),
            '-DARCHITECTURE="' + arch + '"', str(source), "-o", str(binary)],
            check=True)
        subprocess.run([str(binary)], check=True)
