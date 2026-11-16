#!/usr/bin/env python3.12
"""Exercise the production amd64 HyperTrace hypercall handler."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / "sys/amd64/vmm/vmm.c").read_text()
header = (root / "sys/sys/hypertrace.h").read_text()
helper_start = header.index("static __inline int\nhypertrace_pcstack_valid(")
helper_end = header.index("\n}", helper_start) + 2
start = source.index("static int64_t\nhc_handle_dtrace_probe(")
end = source.index("\n/*", start)
regs_start = source.index("/* The registers dtrace_guest_reg_name() can name. */")
regs_end = source.index("\n}\n", source.index("\ndtrace_vmm_getreg(", regs_start)) + 3
fixture = Path(__file__).with_suffix(".c").read_text()
program = fixture.replace("/* HELPER */", header[helper_start:helper_end], 1)
program = program.replace("/* REGS */", source[regs_start:regs_end], 1)
program = program.replace("/* FUNCTION */", source[start:end], 1)
with tempfile.TemporaryDirectory(prefix="hypertrace-amd64-hypercall-") as directory:
    path = Path(directory)
    (path / "hypercall.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "hypercall.c"),
                    "-o", str(path / "hypercall")], check=True)
    subprocess.run([str(path / "hypercall")], check=True)
