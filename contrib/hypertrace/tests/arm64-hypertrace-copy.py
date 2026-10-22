#!/usr/bin/env python3.12
"""Exercise the production Arm64 HVC envelope copy with discontiguous pages."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / "sys/arm64/vmm/vmm.c").read_text()
wrapper_start = source.index("static int vm_hypertrace_copyin(struct vcpu *")
wrapper_end = source.index("\nstatic int\nvmm_unsupported_quirk(", wrapper_start)
start = source.index("static int\nvm_hypertrace_copyin(")
end = source.index("\nstatic int\nvm_handle_smccc_call(", start)
fixture = Path(__file__).with_suffix(".c").read_text()
program = fixture.replace("/* FUNCTION */",
    source[wrapper_start:wrapper_end] + "\n" + source[start:end], 1)
with tempfile.TemporaryDirectory(prefix="hypertrace-arm64-copy-") as directory:
    path = Path(directory)
    (path / "copy.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "copy.c"),
                    "-o", str(path / "copy")], check=True)
    subprocess.run([str(path / "copy")], check=True)
