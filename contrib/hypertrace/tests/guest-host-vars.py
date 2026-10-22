#!/usr/bin/env python3.12
"""Exercise the production guest/host DIF variable arms over distinct state."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = (root / "sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c").read_text()
identifiers = (root / "cddl/contrib/opensolaris/lib/libdtrace/common/dt_open.c").read_text()
assert re.search(r'\{ "hhostid",\s*DT_IDENT_SCALAR,\s*0,\s*DIF_VAR_HHOSTID\b',
                 identifiers), "hhostid must compile to the host-specific DIF variable"
start = source.index("\tcase DIF_VAR_PID:")
end = source.index("\n\tdefault:", start)
arms = source[start:end]
helper_start = source.index("static uintptr_t\ndtrace_dif_varstrz(")
helper_end = source.index("\n}\n", helper_start) + len("\n}\n")
helper = source[helper_start:helper_end]
header = (root / "sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h").read_text()
names = set(re.findall(r"\bDIF_VAR_[A-Z0-9_]+", arms))
defines = "\n".join(line for line in header.splitlines()
                    if (match := re.match(r"#define\s+(DIF_VAR_[A-Z0-9_]+)\b", line))
                    and match[1] in names)
fixture = Path(__file__).with_suffix(".c").read_text()
with tempfile.TemporaryDirectory(prefix="hypertrace-guest-host-vars-") as directory:
    path = Path(directory)
    (path / "arms.inc").write_text(arms)
    (path / "defines.inc").write_text(defines + "\n")
    (path / "vars.c").write_text(fixture.replace("/* HELPER */", helper, 1))
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-parameter",
                    "-fsanitize=address,undefined",
                    "-I", str(path), str(path / "vars.c"), "-o",
                    str(path / "vars")], check=True)
    subprocess.run([str(path / "vars")], check=True)
