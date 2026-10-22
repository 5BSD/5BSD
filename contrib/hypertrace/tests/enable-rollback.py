#!/usr/bin/env python3.12
"""Compile and run the kernel ECB rollback body with sparse EPID slots."""
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[3]
source = (root / "sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c").read_text()
start = source.index("static void\ndtrace_enabling_rollback(")
end = source.index("\n/*\n * This subroutine is destructive.", start)
with tempfile.TemporaryDirectory(prefix="hypertrace-rollback-") as scratch:
    scratch = pathlib.Path(scratch)
    (scratch / "enable-rollback-impl.inc").write_text(source[start:end])
    binary = scratch / "enable-rollback"
    subprocess.run(
        ["cc", "-std=gnu17", "-fsanitize=address,undefined", "-Wall", "-Wextra",
         "-Werror", "-I", str(scratch),
         str(pathlib.Path(__file__).with_suffix(".c")), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)
