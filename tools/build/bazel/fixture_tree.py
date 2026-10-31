# SPDX-License-Identifier: BSD-2-Clause
"""Copy explicitly declared fixture files; never discover inputs by walking."""
import json
from pathlib import Path
import shutil
import sys


def materialize(records, output):
    # Validate the complete namespace before writing. Checking each destination
    # against every earlier destination makes large source fixtures quadratic.
    destinations = set()
    for record in records:
        name = record["destination"]
        parts = name.split("/")
        if any(part in ("", ".", "..") for part in parts) or "\\" in name:
            raise ValueError("fixture destination must be normalized and relative")
        if name in destinations:
            raise ValueError("conflicting fixture destination")
        destinations.add(name)
    for name in destinations:
        parts = name.split("/")
        for index in range(1, len(parts)):
            if "/".join(parts[:index]) in destinations:
                raise ValueError("conflicting fixture destination")
    output.mkdir(exist_ok=True)
    for record in records:
        name = record["destination"]
        source = Path(record["source"])
        if not source.is_file():
            raise ValueError("fixture source must be a regular file")
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as src, destination.open("xb") as dst:
            shutil.copyfileobj(src, dst)
        destination.chmod(0o444)


if __name__ == "__main__":
    materialize(json.loads(Path(sys.argv[1]).read_text()), Path(sys.argv[2]))
