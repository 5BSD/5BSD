#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Enumerate a pinned Starnix snapshot and check module/feature review coverage.

This checks inventory coverage, not implementation correctness or test passes.
The input is the extracted src/starnix directory. Output is deterministic JSON.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def directories(path):
    return sorted(p.name for p in path.iterdir() if p.is_dir())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--revision", required=True,
                        help="upstream commit from the verified source provenance")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.revision) is None:
        parser.error("revision must be a full lowercase SHA-1 commit ID")
    root = args.snapshot
    enum_path = "lib/features/src/lib.rs"
    enum_source = (root / enum_path).read_text()
    enum = re.search(r"pub enum Feature \{(.*?)\n\}", enum_source, re.S)
    if enum is None:
        parser.error("Feature enum not found; review parser for this snapshot")
    features = re.findall(r"^\s{4}([A-Z]\w*),\s*$", enum.group(1), re.M)
    modules = directories(root / "modules")
    inventory = args.inventory.read_text()
    missing_modules = [m for m in modules if f"| `{m}` |" not in inventory]
    missing_features = [f for f in features if f"`{f}`" not in inventory]
    if missing_modules or missing_features:
        parser.error(f"unreviewed modules={missing_modules}; features={missing_features}")
    anchors = [
        "modules/BUILD.gn", "modules/lib.rs", enum_path,
        "kernel/runner/src/features.rs", "kernel/core/task/kernel.rs",
        "tests/BUILD.gn", "tests/syscalls/cpp/BUILD.gn",
    ]
    result = {
        "format": 1,
        "revision": args.revision,
        "source_root": "src/starnix",
        "scope": "source inventory; no claim of runtime support or passing tests",
        "modules": modules,
        "feature_enum": features,
        "core_directories": directories(root / "kernel/core"),
        "core_top_level_rust": sorted(p.name for p in (root / "kernel/core").glob("*.rs")),
        "libraries": directories(root / "lib"),
        "test_directories": directories(root / "tests"),
        "cpp_test_sources": sorted(str(p.relative_to(root)) for p in
                                   (root / "tests/syscalls/cpp").rglob("*.cc")),
        "expectation_files": sorted(str(p.relative_to(root)) for p in
                                    (root / "tests/syscalls/cpp/expectations").rglob("*")
                                    if p.is_file()),
        "review_anchor_sha256": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in anchors
        },
    }
    print(json.dumps(result, indent=2) + "\n", end="")


if __name__ == "__main__":
    main()
