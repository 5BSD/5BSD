#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise maintained Make per-program override semantics without building."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--src", type=Path, required=True)
parser.add_argument("--make", default="/usr/bin/make")
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="bsd-program-overrides-") as directory:
    path = Path(directory)
    (path / "Makefile").write_text("""PROGS= demo
PROG= demo
SRCS=
_SKIP_BUILD= yes
NO_SHARED=
NO_SHARED.demo= no
BINDIR= /global
BINDIR.demo= /selected
WARNS= 6
WARNS.demo= 0
CFLAGS= -DGLOBAL
CFLAGS.demo= -DLOCAL
.include <bsd.progs.mk>
""")
    def query(expression, *settings):
        return subprocess.check_output([args.make, "-m", str(args.src / "share/mk"),
            "-C", directory, "SRCTOP=" + str(args.src), *settings,
            "-V", expression], text=True).strip()
    assert query("${NO_SHARED:Q}") == "no"
    assert query("${BINDIR:Q}") == "/selected"
    assert query("${WARNS:Q}") == "0"
    assert query("${CSTD:Q}") == "gnu17"
    assert "-static" not in query("${LDFLAGS}").split()
    assert "-static" in query("${LDFLAGS}", "NO_SHARED.demo=yes").split()
    flags = query("${CFLAGS}").split()
    assert flags.count("-DGLOBAL") == 1 and flags.count("-DLOCAL") == 1
    assert query("${NO_SHARED:Q}", "NO_SHARED=yes") == "yes"
print("passed: replacement, append, unset defaults, static/shared selection, command-line precedence")
