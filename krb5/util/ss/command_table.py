# SPDX-License-Identifier: BSD-2-Clause
"""Run the vendor command-table parser with declared tools and inputs."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sed", "awk", "sed-script", "awk-script", "source", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    output = Path(args.output)
    parsed = subprocess.run([args.sed, "-f", args.sed_script, args.source],
                            check=True, stdout=subprocess.PIPE).stdout
    try:
        subprocess.run([args.awk, "-f", args.awk_script,
                        "rootname=" + str(Path(args.source).with_suffix("")),
                        "outfile=" + str(output), "-"], input=parsed, check=True)
        if any(line.startswith(b"#__ERROR_IN_FILE") for line in output.read_bytes().splitlines()):
            raise ValueError("invalid command table: " + args.source)
    except BaseException:
        output.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    main()
