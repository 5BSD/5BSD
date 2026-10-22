#!/usr/bin/env python3.12
"""Exercise the production execargs copy with an untrusted guest pointer."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / "sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c").read_text()
start = source.index("static uintptr_t\ndtrace_dif_varstrz(")
end = source.index("\n}\n", start) + len("\n}\n")
fixture = Path(__file__).with_suffix(".c").read_text()
program = fixture.replace("/* FUNCTION */", source[start:end], 1)
with tempfile.TemporaryDirectory(prefix="hypertrace-guest-execargs-") as directory:
    path = Path(directory)
    (path / "execargs.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-parameter",
                    "-fsanitize=address,undefined", str(path / "execargs.c"),
                    "-o", str(path / "execargs")], check=True)
    subprocess.run([str(path / "execargs")], check=True)
