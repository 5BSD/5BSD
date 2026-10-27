# SPDX-License-Identifier: BSD-2-Clause
"""Resolve archive ancestors and identities from declared base policy sources."""
from pathlib import Path, PurePosixPath
import subprocess
from directory_metadata import records, normalize, absolute


def accounts(path, fields):
    result = {}
    for line in Path(path).read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        row = line.split(":")
        if len(row) != fields or not row[0] or row[0] in result:
            raise ValueError("invalid or duplicate account entry")
        result[row[0]] = int(row[2])
        if result[row[0]] < 0:
            raise ValueError("negative account identity")
    return result


def resolve(request):
    specs = request.get("mtree_specs", [])
    if not specs:
        if request.get("directory_packages"):
            raise ValueError("package directory selection requires mtree sources")
        return request
    if request["users"] or request["groups"]:
        raise ValueError("account files and inline identities cannot be mixed")
    request = dict(request)
    request["users"] = accounts(request["passwd"], 10)
    request["groups"] = accounts(request["group"], 4)
    required = {"/"}
    for record in request["records"]:
        path = PurePosixPath(record["destination"]).parent
        required.add(str(path))
        required.update(str(parent) for parent in path.parents)
    # Components may declare directories created by their install rules. They
    # must agree with mtree wherever both sources describe the same object.
    explicit = {}
    for record in request["records"]:
        if record["type"] == "dir":
            path = absolute(record["destination"])
            if path in explicit:
                raise ValueError("duplicate explicit directory policy: " + path)
            explicit[path] = record
            required.add(path)
    # Select empty package-owned directories from source mtree tags as well as
    # payload ancestors. Keep selection separate from normalization: unrelated
    # mtree entries may describe object types this archive does not install.
    selected_packages = set(request.get("directory_packages", []))
    flattened = []
    for spec in specs:
        prefix = absolute(spec["prefix"])
        output = subprocess.run([request["mtree"], "-C", "-K", "all", "-f", spec["source"]],
                                check=True, capture_output=True, text=True).stdout
        for relative, attrs in records(output):
            path = absolute(prefix.rstrip("/") + ("/" + relative[2:] if relative != "." else "") or "/")
            flattened.append((path, attrs))
            packages = {tag[len("package="):] for tag in attrs.get("tags", "").split(",") if tag.startswith("package=")}
            if attrs.get("type") == "dir" and packages & selected_packages:
                required.add(path)
                required.update(str(parent) for parent in PurePosixPath(path).parents)
    policy = dict(explicit)
    for path, attrs in flattened:
        if path in required:
            meta = normalize(attrs)
            resolved = dict(destination=path, type="dir", owner=meta["uname"],
                group=meta["gname"], mode=format(meta["mode"], "04o"), tags=meta["tags"])
            if path in explicit:
                declared = explicit[path]
                if (declared["owner"] != resolved["owner"] or declared["group"] != resolved["group"] or
                        int(declared["mode"], 8) != int(resolved["mode"], 8) or
                        declared.get("flags", "")):
                    raise ValueError("explicit directory conflicts with mtree: " + path)
            else:
                if path in policy:
                    previous = policy[path]
                    if (previous["owner"] != resolved["owner"] or previous["group"] != resolved["group"] or
                            int(previous["mode"], 8) != int(resolved["mode"], 8)):
                        raise ValueError("conflicting mtree directory policy: " + path)
                policy[path] = resolved
    missing = required - set(policy)
    if missing:
        raise ValueError("missing source directory policy: " + str(sorted(missing)))
    request["records"] = request["records"] + [policy[path] for path in sorted(policy) if path not in explicit]
    return request
