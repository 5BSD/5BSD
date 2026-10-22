#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check cross-host DTrace provider objects against the arm64 target ABI."""

from pathlib import Path
import struct
import subprocess
import sys


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True, capture_output=True)


def machine(path: Path) -> int:
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise SystemExit(f"not a little-endian ELF64 object: {path}")
    return struct.unpack_from("<H", data, 18)[0]


def main() -> None:
    if len(sys.argv) != 6:
        raise SystemExit("usage: arm64-provider-abi.py OUTDIR DTRACE DRTI CC LD")
    out = Path(sys.argv[1]).resolve()
    if not out.is_relative_to("/usr/obj"):
        raise SystemExit("Use the /usr/obj object root")
    dtrace, drti, cc, ld = sys.argv[2:]
    out.mkdir(parents=True, exist_ok=True)
    provider = out / "provider.d"
    source = out / "provider.c"
    header = out / "provider.h"
    guest = out / "provider-arm64.o"
    wrong = out / "provider-amd64.o"
    dof = out / "provider-dof.o"
    linked = out / "provider-linked.o"
    provider.write_text("provider abicheck { probe hit(); };\n")
    source.write_text('#include "provider.h"\nvoid hit(void) { ABICHECK_HIT(); }\n')
    opts = (dtrace, "-C", "-x", "nolibs", "-x", f"syslibdir={Path(drti).parent}")
    run(*opts, "-h", "-o", str(header), "-s", str(provider))
    run(cc, "-target", "aarch64-unknown-freebsd16.0", "-I", str(out),
        "-c", str(source), "-o", str(guest))
    run(cc, "-target", "x86_64-unknown-freebsd16.0", "-I", str(out),
        "-c", str(source), "-o", str(wrong))
    run(*opts, "-G", "-o", str(dof), "-s", str(provider), str(guest))
    for path in (guest, dof, Path(drti)):
        if machine(path) != 183:
            raise SystemExit(f"not an arm64 object: {path}")
    run(ld, "-m", "aarch64elf", "-r", "-o", str(linked),
        drti, str(guest), str(dof))
    if machine(linked) != 183:
        raise SystemExit("linked provider changed target architecture")
    sections = run("readelf", "-S", str(dof)).stdout
    if ".SUNW_dof" not in sections:
        raise SystemExit("generated provider has no DOF section")
    mixed = run(*opts, "-G", "-o", str(out / "mixed.o"), "-s",
                str(provider), str(guest), str(wrong), check=False)
    if mixed.returncode == 0 or "incorrect ELF machine type" not in mixed.stderr:
        raise SystemExit("mixed arm64/amd64 objects were accepted")
    print("PASS: arm64 provider object, drti and relocatable link agree; "
          "mixed architecture rejected")


if __name__ == "__main__":
    main()
