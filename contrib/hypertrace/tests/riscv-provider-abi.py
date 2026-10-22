#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check the real cross-host dtrace provider linker against RISC-V ABI flags."""

from pathlib import Path
import struct
import subprocess
import sys


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True, capture_output=True)


def flags(path: Path) -> int:
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 243:
        raise SystemExit(f"not a little-endian ELF64 RISC-V object: {path}")
    return struct.unpack_from("<I", data, 48)[0]


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: riscv-provider-abi.py OUTDIR DTRACE DRTI CC")
    out = Path(sys.argv[1]).resolve()
    if not out.is_relative_to("/usr/obj"):
        raise SystemExit("Use the /usr/obj object root")
    dtrace, drti, cc = sys.argv[2:]
    out.mkdir(parents=True, exist_ok=True)
    provider = out / "provider.d"
    source = out / "provider.c"
    header = out / "provider.h"
    double = out / "provider-double.o"
    no_rvc = out / "provider-no-rvc.o"
    soft = out / "provider-soft.o"
    generated = out / "provider-dof.o"
    combined = out / "provider-combined.o"
    provider.write_text("provider abicheck { probe hit(); };\n")
    source.write_text('#include "provider.h"\nvoid hit(void) { ABICHECK_HIT(); }\n')
    opts = (dtrace, "-C", "-x", "nolibs", "-x", f"syslibdir={Path(drti).parent}")
    run(*opts, "-h", "-o", str(header), "-s", str(provider))
    for abi, output in (("lp64d", double), ("lp64", soft)):
        run(cc, "-target", "riscv64-unknown-freebsd16.0", f"-mabi={abi}",
            "-I", str(out), "-c", str(source), "-o", str(output))
    run(cc, "-target", "riscv64-unknown-freebsd16.0", "-march=rv64imafd",
        "-mabi=lp64d", "-I", str(out), "-c", str(source), "-o", str(no_rvc))
    run(*opts, "-G", "-o", str(generated), "-s", str(provider), str(double))
    run(*opts, "-G", "-o", str(combined), "-s", str(provider),
        str(no_rvc), str(double))

    input_flags, generated_flags, drti_flags = (
        flags(double), flags(generated), flags(Path(drti)))
    if input_flags != generated_flags or generated_flags != drti_flags:
        raise SystemExit(f"ELF ABI flags differ: input={input_flags:#x}, "
                         f"generated={generated_flags:#x}, drti={drti_flags:#x}")
    if (input_flags ^ flags(soft)) & 0x6 != 0x4:
        raise SystemExit("the fixture did not create different floating-point ABIs")
    if flags(no_rvc) != (input_flags & ~0x1) or flags(combined) != input_flags:
        raise SystemExit("compatible RVC flags were not combined")

    mixed = run(*opts, "-G", "-o", str(out / "mixed.o"), "-s",
                str(provider), str(double), str(soft), check=False)
    if mixed.returncode == 0 or "mixed RISC-V ABI flags" not in mixed.stderr:
        raise SystemExit("mixed RISC-V floating-point ABIs were not rejected")
    print(f"PASS: generated provider, input and drti flags match ({generated_flags:#x}); "
          "compatible RVC flags combined; mixed ABI rejected")


if __name__ == "__main__":
    main()
