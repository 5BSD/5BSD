# SPDX-License-Identifier: BSD-2-Clause
"""Generate the original anchored DEFINE_TEST registry from declared sources."""
import argparse
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exclude", action="append", default=[], help="original literal C test-name fragment excluded by Make")
    parser.add_argument("output", type=Path)
    parser.add_argument("sources", type=Path, nargs="+")
    args = parser.parse_args()
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) for name in args.exclude):
        parser.error("excluded test fragments must be C identifiers")
    excluded = {name.encode("ascii"): False for name in args.exclude}
    lines = []
    for source in args.sources:
        data = source.read_bytes()
        if b"\0" in data:
            parser.error("test source contains NUL: " + str(source))
        for line in data.split(b"\n"):
            if not line.startswith(b"DEFINE_TEST"):
                continue
            matches = [name for name in excluded if name in line]
            for name in matches:
                excluded[name] = True
            if not matches:
                lines.append(line + b"\n")
    if not lines:
        parser.error("empty libarchive test registry")
    if not all(excluded.values()):
        parser.error("excluded test fragment does not match the selected registry")
    args.output.write_bytes(b"".join(lines))


if __name__ == "__main__":
    main()
