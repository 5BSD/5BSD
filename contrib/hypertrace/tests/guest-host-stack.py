#!/usr/bin/env python3.12
"""Execute the production host register and stack DIF variable arms."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / "sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c").read_text()
header = (root / "sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h").read_text()
registers = source[source.index("\tcase DIF_VAR_REGS:"):
                   source.index("\tcase DIF_VAR_HCURTHREAD:")]
stack = source[source.index("\tcase DIF_VAR_STACKDEPTH:"):
               source.index("\tcase DIF_VAR_PROBEPROV:")]
arms = registers + stack
names = set(re.findall(r"\bDIF_VAR_[A-Z0-9_]+", arms))
defines = "\n".join(line for line in header.splitlines()
                    if (match := re.match(r"#define\s+(DIF_VAR_[A-Z0-9_]+)\b", line))
                    and match[1] in names)
fixture = Path(__file__).with_suffix(".c").read_text()
with tempfile.TemporaryDirectory(prefix="hypertrace-host-stack-") as directory:
    path = Path(directory)
    (path / "arms.inc").write_text(arms)
    (path / "defines.inc").write_text(defines + "\n")
    (path / "test.c").write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-parameter", "-fsanitize=address,undefined",
                    "-I", str(path), str(path / "test.c"), "-o", str(path / "test")],
                   check=True)
    subprocess.run([str(path / "test")], check=True)
