#!/usr/bin/env python3.12
"""Exercise the production Arm64 HyperTrace guest copies: the frozen HVC
envelope copy, and the probe-context stage 2 walk behind the guest hooks."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
vmm = (root / "sys/arm64/vmm/vmm.c").read_text()
vmm_arm64 = (root / "sys/arm64/vmm/vmm_arm64.c").read_text()
pte = (root / "sys/arm64/include/pte.h").read_text()

def between(source, start, end):
    first = source.index(start)
    return source[first:source.index(end, first)]

envelope = between(vmm, "/* Copy a bounded guest envelope",
    "\n/*\n * Fire a guest probe")
hooks = between(vmm, "static int\ndtrace_vmm_guest_copyin(",
    "\nstatic int\nvmm_unsupported_quirk(")
walk = between(vmm_arm64, "/*\n * DTrace probe context can neither fault",
    "\n/* log2 of the number of bytes in a page table entry */")
copy = between(vmm_arm64, "/*\n * Copy len bytes to or from guest virtual",
    "\nint\nvmmops_run(")
# Descriptor and permission bits come from the header so that a change there
# is tested; the 4K granule geometry is fixed in the fixture.
names = ("ATTR_DESCR_MASK", "L0_TABLE", "L1_BLOCK", "L1_TABLE", "L3_PAGE",
    "ATTR_S2_S2AP", "ATTR_S2_S2AP_READ", "ATTR_S2_S2AP_WRITE")
defines = []
for name in names:
    match = re.search(r"^#define\s+" + re.escape(name) + r"\b.*$", pte, re.M)
    if match is None:
        raise SystemExit("Missing pte.h definition: " + name)
    defines.append(match.group(0))
fixture = Path(__file__).with_suffix(".c").read_text()
program = (fixture.replace("/* PTE */", "\n".join(defines), 1)
    .replace("/* ENVELOPE */", envelope, 1)
    .replace("/* WALK */", walk + "\n" + copy, 1)
    .replace("/* HOOKS */", hooks, 1))
with tempfile.TemporaryDirectory(prefix="hypertrace-arm64-copy-") as directory:
    path = Path(directory)
    (path / "copy.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "copy.c"),
                    "-o", str(path / "copy")], check=True)
    subprocess.run([str(path / "copy")], check=True)
