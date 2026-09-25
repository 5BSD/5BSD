#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Fault injection for the small HardenedBSD defensive ports (FreeBSD host)."""

import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


def function(source, name):
    """Extract a function ending with a column-zero brace; fail on drift."""
    match = re.search(r"(?m)^(?:static )?(?:int|void \*)\n" +
                      re.escape(name) + r"\(.*?\n}\n", source, re.S)
    if match is None:
        raise ValueError("Cannot find function: " + name)
    return match.group()


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=here.parents[2])
    args = parser.parse_args()
    root = args.source_root.resolve()
    cc = shlex.split(os.environ.get("CC", "cc"))
    failures = []

    with tempfile.TemporaryDirectory(prefix="5bsd-defensive-tests-") as temp:
        work = Path(temp)
        logger = work / "logger"
        subprocess.run(cc + ["-O1", "-g", "-Wall", "-Wextra", "-Werror",
                            "-Dgethostname=test_gethostname",
                            "-Dsendto=test_sendto",
                            str(root / "usr.bin/logger/logger.c"),
                            str(here / "logger_faults.c"), "-o", str(logger)],
                       check=True)
        cases = {"failure": b"", "partial_failure": b"",
                 "host.example": b"host", "host": b"host", "": b"",
                 "full": b"x" * 256, "override": b"custom.example"}
        for case, expected in cases.items():
            env = dict(os.environ, LOGGER_HOSTNAME_CASE=case)
            command = [str(logger), "-h", "127.0.0.1", "-P", "514",
                       "-t", "hardening"]
            if case == "override":
                command += ["-H", "custom.example"]
            result = subprocess.run(command + ["probe"], env=env,
                                    capture_output=True, timeout=10)
            match = re.fullmatch(rb"<13>.{15} (.*?) hardening: probe",
                                 result.stdout, re.S)
            ok = (result.returncode == 0 and match is not None and
                  match[1] == expected and result.stderr == b"")
            label = "logger: " + repr(case)
            print(("PASS " if ok else "FAIL ") + label)
            if not ok:
                failures.append(label)

        # Compile the actual qlnx helper and the mrsas entry paths up to DMA
        # setup, with allocator/command stubs. No kernel or device is touched.
        qlnx = (root / "sys/dev/qlnx/qlnxe/qlnx_os.c").read_text()
        mrsas = (root / "sys/dev/mrsas/mrsas.c").read_text()
        paths = function(qlnx, "qlnx_zalloc")
        for kind in ("pd", "ld"):
            body = function(mrsas, "mrsas_get_" + kind + "_list")
            marker = "\t" + kind + "_list_size ="
            if body.count(marker) != 1:
                raise ValueError("DMA setup boundary changed")
            paths += body.split(marker)[0]
            paths += ("\t(void)dcmd;\n\ttest_stop_after_alloc(tcmd);\n"
                      "\treturn (0);\n}\n")
        (work / "allocation_paths.inc").write_text(paths)
        harness = work / "alloc_faults"
        subprocess.run(cc + ["-O1", "-g", "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-variable", "-I", str(work),
                            str(here / "alloc_faults.c"), "-o", str(harness)],
                       check=True)
        for case in ("qlnx", "pd", "ld"):
            result = subprocess.run([str(harness), case], cwd=work,
                                    capture_output=True, timeout=10)
            ok = result.returncode == 0
            print(("PASS " if ok else "FAIL ") + "allocation: " + case)
            if not ok:
                failures.append("allocation: " + case)
        if failures:
            raise SystemExit("Failed: " + ", ".join(failures))


if __name__ == "__main__":
    main()
