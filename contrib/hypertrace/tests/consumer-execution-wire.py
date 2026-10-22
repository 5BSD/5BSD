#!/usr/bin/env python3.12
"""Exercise the production execution-result sender and canonical daemon wire."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
source = (root / "cddl/contrib/opensolaris/cmd/dtrace/dtrace.c").read_text()
start = source.index("static int\nreport_identified_execution(")
end = source.index("\n}\n", start) + len("\n}\n")
fixture = Path(__file__).with_suffix(".c").read_text()
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to("/usr/obj"):
    raise SystemExit("Use the /usr/obj object root")
out.mkdir(parents=True, exist_ok=True)
program = out / "consumer-execution-wire.c"
program.write_text(fixture.replace("/* FUNCTION */", source[start:end], 1))
binary = out / "consumer-execution-wire"
subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-UNDEBUG", "-fsanitize=address,undefined",
                "-I" + str(root / "usr.sbin/dtraced"), str(program),
                "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=10)
