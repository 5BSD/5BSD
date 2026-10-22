#!/usr/bin/env python3.12
"""Exercise the production execution reporter queue with concurrent outcomes."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
source = (root / "cddl/contrib/opensolaris/cmd/dtrace/dtrace.c").read_text()
functions = []
for marker in ("static void\nexecution_identity_set(",
               "static int\nidentified_ingress_header_valid(",
               "static void\nqueue_identified_execution(",
               "static void *\nreport_identified_executions("):
    start = source.index(marker)
    end = source.index("\n}\n", start) + len("\n}\n")
    functions.append(source[start:end])
fixture = Path(__file__).with_suffix(".c").read_text()
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to("/usr/obj"):
    raise SystemExit("Use the /usr/obj object root")
out.mkdir(parents=True, exist_ok=True)
program = out / "consumer-execution-queue.c"
program.write_text(fixture.replace("/* FUNCTIONS */", "\n".join(functions), 1))
binary = out / "consumer-execution-queue"
subprocess.run(["cc", "-std=c11", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra",
                "-Werror", "-UNDEBUG", "-fsanitize=address,undefined",
                "-pthread", "-I" + str(root / "usr.sbin/dtraced"),
                str(program), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=10)
