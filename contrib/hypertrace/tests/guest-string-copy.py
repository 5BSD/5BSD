#!/usr/bin/env python3.12
"""Exercise the production guest string helper and pointer ownership."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / "sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c").read_text()
start = source.index("static uintptr_t\ndtrace_dif_guest_varstr(")
end = source.index("\n/*\n * Return a string from a memoy address", start)
fixture = Path(__file__).with_suffix(".c").read_text()
program = fixture.replace("/* FUNCTION */", source[start:end], 1)
with tempfile.TemporaryDirectory(prefix="hypertrace-guest-string-") as directory:
    path = Path(directory)
    (path / "string.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "string.c"),
                    "-o", str(path / "string")], check=True)
    subprocess.run([str(path / "string")], check=True)
