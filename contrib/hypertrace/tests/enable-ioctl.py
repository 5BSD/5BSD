#!/usr/bin/env python3.12
"""Run the actual kernel ENABLE ioctl case against matching-failure fixtures."""
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[3]
ioctl_source = (root / "sys/cddl/dev/dtrace/dtrace_ioctl.c").read_text()
rollback_source = (root / "sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c").read_text()
a = ioctl_source.index("\tcase DTRACEIOC_ENABLE: {")
b = ioctl_source.index("\tcase DTRACEIOC_EPROBE:", a)
case = "static int dispatch(void *addr, dtrace_state_t *state, thread_t *td)\n" \
    "{ switch (DTRACEIOC_ENABLE) {\n" + ioctl_source[a:b] + "\n} return EINVAL; }\n"
a = rollback_source.index("static void\ndtrace_enabling_rollback(")
b = rollback_source.index("\n/*\n * This subroutine is destructive.", a)
with tempfile.TemporaryDirectory(prefix="hypertrace-enable-ioctl-") as scratch:
    scratch = pathlib.Path(scratch)
    (scratch / "enable-ioctl-impl.inc").write_text(case)
    (scratch / "enable-rollback-impl.inc").write_text(rollback_source[a:b])
    binary = scratch / "enable-ioctl"
    subprocess.run(
        ["cc", "-std=gnu17", "-fsanitize=address,undefined", "-Wall", "-Wextra",
         "-Werror", "-Wno-unused-variable", "-I", str(scratch),
         str(pathlib.Path(__file__).with_suffix(".c")), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)
