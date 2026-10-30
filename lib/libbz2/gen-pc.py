# SPDX-License-Identifier: BSD-2-Clause
"""Generate bzip2 pkg-config metadata from its declared header and template."""
import argparse
from pathlib import Path
import re


def render(template, header, values):
    versions = re.findall(r"bzip2/libbzip2 version ([0-9]+(?:\.[0-9]+)+) of", header)
    if len(versions) != 1:
        raise ValueError("expected exactly one bzip2 header version")
    values = dict(values, VERSION=versions[0])
    if any(not value or any(c in value for c in "\r\n@") for value in values.values()):
        raise ValueError("invalid pkg-config substitution")
    tokens = set(re.findall(r"@([A-Za-z_]+)@", template))
    if tokens != set(values):
        raise ValueError("template substitutions differ from declared fields")
    return re.sub(r"@([A-Za-z_]+)@", lambda m: values[m[1]], template)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("template", "header", "output", "prefix", "exec_prefix", "libdir", "sharedlibdir", "includedir"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    values = {key: getattr(args, key) for key in ("prefix", "exec_prefix", "libdir", "sharedlibdir", "includedir")}
    result = render(Path(args.template).read_text(), Path(args.header).read_text(), values)
    Path(args.output).write_text(result)


if __name__ == "__main__":
    main()
