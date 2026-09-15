#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run hardware-independent tests against the production MMC power functions.

Usage: python3 tools/test/mmc/power_test.py
Requires a host C compiler. This exercises error/ordering contracts with fake
hardware; it does not replace kernel WITNESS or Raspberry Pi hardware tests.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
FUNCTIONS = [
    ("sys/dev/mmc/mmc_pwrseq.c", "static int", "mmv_pwrseq_set_power"),
    ("sys/arm/broadcom/bcm2835/bcm2835_sdhci.c", "static int", "bcm_sdhci_set_power"),
    ("sys/dev/sdhci/sdhci.c", "int", "sdhci_generic_update_ios"),
    ("sys/dev/sdhci/sdhci.c", "static int", "sdhci_cam_update_ios"),
    ("sys/dev/sdhci/sdhci.c", "static int", "sdhci_cam_settran_settings"),
    ("sys/dev/sdhci/sdhci.c", "static void", "sdhci_cam_ios_task"),
    ("sys/dev/sdhci/sdhci.c", "void", "sdhci_cam_action"),
]


def run_test(fixture, functions, flags=()):
    with tempfile.TemporaryDirectory(prefix="mmc-power-test-") as directory:
        build = Path(directory)
        bodies = []
        for path, result, name in functions:
            source = (ROOT / path).read_text()
            start = source.find(f"{result}\n{name}(")
            if start < 0:  # Imported Linux functions put the type on the same line.
                start = source.find(f"{result} {name}(")
            if start < 0 and result.endswith('*'):
                start = source.find(f"{result}{name}(")
            if start < 0:
                raise ValueError(f"Function {name} not found in {path}")
            end = source.index("\n}\n", start) + 3
            line = source[:start].count("\n") + 1
            bodies.append(f'#line {line} "{path}"\n' + source[start:end])
        (build / "power_functions.h").write_text("\n".join(bodies))
        compiler = shlex.split(os.environ.get("CC", "cc"))
        subprocess.run(compiler + list(flags) + ["-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(build), str(Path(__file__).with_name(fixture)),
            "-o", str(build / "power_test")], check=True)
        subprocess.run([str(build / "power_test")], check=True, timeout=30)


if __name__ == "__main__":
    run_test("power_test.c", FUNCTIONS)
    run_test("fdt_test.c", [
        ("sys/dev/mmc/mmc_fdt_helpers.c", "int", "mmc_fdt_parse"),
        ("sys/dev/sdhci/sdhci_xenon_fdt.c", "static int", "sdhci_xenon_fdt_parse"),
        ("sys/dev/sdhci/sdhci_xenon_fdt.c", "static int", "sdhci_xenon_fdt_attach"),
    ])
