#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Enforce maintained rtld forbidden-dependency checks before exporting ELF."""
import hashlib
import json
from pathlib import Path
import shutil
import sys


def check(binary, linkmap, output, report):
    content = linkmap.read_text()
    forbidden = [name for name in ("__libsys_interposing", "__libc_interposing", "xlocale", "fprintf") if name in content]
    if forbidden:
        raise ValueError("rtld dependency leaked: " + ", ".join(forbidden))
    if not content.strip() or binary.read_bytes()[:4] != b"\x7fELF":
        raise ValueError("rtld link must produce ELF and a nonempty map")
    shutil.copyfile(binary, output)
    output.chmod(0o755)
    report.write_text(json.dumps({"status": "passed", "scope": "maintained Make forbidden link-map dependency checks",
        "binary_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "map_sha256": hashlib.sha256(linkmap.read_bytes()).hexdigest()}, indent=2) + "\n")


if __name__ == "__main__":
    check(*(Path(p) for p in sys.argv[1:]))
