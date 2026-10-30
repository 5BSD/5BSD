# SPDX-License-Identifier: BSD-2-Clause
"""Generate libfetch protocol tables from their maintained source inventory."""
import argparse
import json
from pathlib import Path
import re


def generate(source, protocol):
    rows = []
    codes = set()
    for number, line in enumerate(source.splitlines(), 1):
        if line.startswith("#"):
            continue
        fields = line.split(None, 2)
        if len(fields) != 3 or not fields[0].isdigit() or not re.fullmatch(r"[A-Z_]+", fields[1]):
            raise ValueError(f"invalid error table record at line {number}")
        code, category, message = fields
        if int(code) in codes:
            raise ValueError(f"duplicate error code: {code}")
        codes.add(int(code))
        rows.append((line, code, category, message.strip()))
    lines = [f"static struct fetcherr {protocol}_errlist[] = {{"]
    for _, code, category, message in sorted(rows):
        lines.append(f"    {{ {code}, FETCH_{category}, {json.dumps(message, ensure_ascii=True)} }},")
    lines += [f'    {{ -1, FETCH_UNKNOWN, "Unknown {protocol.upper()} error" }}', "};"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("protocol", choices=["ftp", "http"])
    args = parser.parse_args()
    args.output.write_text(generate(args.source.read_text(), args.protocol))
