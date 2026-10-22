#!/usr/bin/env python3.12
"""Test actual DTrace matched-list allocation with sparse probe IDs."""
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[3]
source = (root / "sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c").read_text()
a = source.index("static dtrace_probedesc_t *\ndtrace_enabling_list(")
b = source.index("\nstatic int\ndtrace_enabling_match(", a)
with tempfile.TemporaryDirectory(prefix="hypertrace-sparse-") as scratch:
    scratch = pathlib.Path(scratch)
    (scratch / "enable-sparse-list-impl.inc").write_text(source[a:b])
    binary = scratch / "enable-sparse-list"
    subprocess.run(
        ["cc", "-std=gnu17", "-fsanitize=address,undefined", "-Wall", "-Wextra",
         "-Werror", "-Wno-unused-variable", "-I", str(scratch),
         str(pathlib.Path(__file__).with_suffix(".c")), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)
