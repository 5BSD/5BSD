#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inventory a pinned HardenedBSD tree delta without modifying any checkout.

The base must be the FreeBSD revision merged into the HardenedBSD snapshot.
Blob equality is a triage aid, not proof of equivalent security behavior.
"""

import argparse
import json
import subprocess
import sys


def git(repo, *args):
    return subprocess.check_output(["git", "-C", repo, *args])


def tree(repo, revision):
    entries = {}
    for entry in git(repo, "ls-tree", "-r", "-z", revision).split(b"\0"):
        if entry:
            metadata, path = entry.split(b"\t", 1)
            entries[path] = metadata
    return entries


def state(value, base, hardened):
    if value == hardened:
        return "matches-hardened"
    if value == base:
        return "matches-base"
    return "diverged"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", help="Git repository containing all revisions")
    for name in ("base", "hardened", "upstream", "target"):
        parser.add_argument("--" + name, required=True, help="Pinned revision")
    args = parser.parse_args()
    revisions = {}
    trees = {}
    for name in ("base", "hardened", "upstream", "target"):
        revision = git(args.repo, "rev-parse", "--verify", "--end-of-options",
                       getattr(args, name) + "^{commit}").decode().strip()
        revisions[name] = revision
        trees[name] = tree(args.repo, revision)

    for name, revision in revisions.items():
        print(f"# {name}\t{revision}")
    print("# Equality compares complete Git entries, including file mode.")
    print("# matches-base means the retained file delta is absent verbatim;")
    print("# diverged requires review. Neither is a semantic security verdict.")
    print("status\tpath\tupstream\ttarget")
    base, hardened = trees["base"], trees["hardened"]
    for path in sorted(base.keys() | hardened.keys()):
        before, after = base.get(path), hardened.get(path)
        if before == after:
            continue
        status = "A" if before is None else "D" if after is None else "M"
        upstream = state(trees["upstream"].get(path), before, after)
        target = state(trees["target"].get(path), before, after)
        # Keep unusual filenames on one TSV row using JSON quoting.
        display = path.decode("utf-8", errors="backslashreplace")
        if any(c in display for c in "\t\n\r\\\""):
            display = json.dumps(display, ensure_ascii=True)
        print(f"{status}\t{display}\t{upstream}\t{target}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
