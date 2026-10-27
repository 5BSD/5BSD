# SPDX-License-Identifier: BSD-2-Clause
"""Select and hash-check only declared package outputs; ignore stale neighbors."""
import hashlib
import json
from pathlib import Path


def packages(directory):
    index = json.loads((directory / "index.json").read_text())
    if index.get("format") != 1 or not index.get("packages"):
        raise ValueError("nonempty format-1 package index required")
    result = []
    seen = set()
    for entry in index["packages"]:
        name = entry["name"]
        if not isinstance(name, str) or Path(name).name != name or not name.endswith(".pkg") or name in seen:
            raise ValueError("invalid/duplicate indexed package filename")
        seen.add(name)
        path = directory / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("indexed package missing or changed: " + name)
        result.append(path)
    return sorted(result)
