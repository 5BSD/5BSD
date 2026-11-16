# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Hash exactly the declared execution paths, preserving repository aliases."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys


def inventory(names):
    files = {}
    for name in names:
        path = PurePosixPath(name)
        if (not name or path.is_absolute() or str(path) != name or
                any(part in (".", "..") for part in path.parts) or
                any(ord(c) < 32 or ord(c) == 127 for c in name)):
            raise ValueError("canonical relative payload execution path required")
        if name in files:
            raise ValueError("duplicate declared payload execution path: " + name)
        source = Path(name)
        if not source.is_file():
            raise ValueError("regular declared payload required: " + name)
        with source.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        files[name] = dict(sha256 = digest, size = source.stat().st_size)
    if not files:
        raise ValueError("nonempty declared payload inventory required")
    return dict(format = 1, scope = "declared-installation-payloads", files = files)


def main():
    if len(sys.argv) != 3 or not sys.argv[2].startswith("@"):
        raise ValueError("output and explicit Bazel multiline argument file required")
    names = Path(sys.argv[2][1:]).read_text().splitlines()
    Path(sys.argv[1]).write_text(json.dumps(inventory(names), sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
