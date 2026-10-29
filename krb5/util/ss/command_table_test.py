# SPDX-License-Identifier: BSD-2-Clause
"""Exercise command-table rejection using the actual declared vendor parsers."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sed", "awk", "vendor-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    vendor = args.vendor_dir.resolve(strict=True)
    driver = Path(__file__).with_name("command_table.py")
    with tempfile.TemporaryDirectory() as work:
        root = Path(work)
        source = root / "bad.ct"
        output = root / "bad.c"
        source.write_text('command_table bad;\ninvalid_keyword bogus;\nend;\n')
        command = [sys.executable, "-B", "-S", str(driver), "--sed", str(args.sed.resolve(strict=True)),
                   "--awk", str(args.awk.resolve(strict=True)), "--sed-script", str(vendor / "ct_c_sed.in"),
                   "--awk-script", str(vendor / "ct_c_awk.in"), "--source", str(source), "--output", str(output)]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0 or output.exists() or b"invalid command table" not in result.stderr:
            raise AssertionError((result.returncode, output.exists(), result.stdout, result.stderr))
        print(json.dumps({"malformed_table_rejected": True, "failed_output_removed": True}))


if __name__ == "__main__":
    main()
