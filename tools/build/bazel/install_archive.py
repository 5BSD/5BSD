# SPDX-License-Identifier: BSD-2-Clause
"""Serialize declared installation metadata and payloads as a deterministic tar."""
import argparse
import json
from pathlib import Path, PurePosixPath
import tarfile
from archive_policy import resolve


def normalized(path):
    if not path.startswith("/") or path.startswith("//") or str(PurePosixPath(path)) != path or ".." in path.split("/"):
        raise ValueError("non-normalized installation path: " + path)
    return path.lstrip("/") or "."


def write_archive(request, output):
    records = {}
    for record in request["records"]:
        path = record["destination"]
        normalized(path)
        if path in records:
            raise ValueError("duplicate destination: " + path)
        records[path] = record
    if "/" not in records or records["/"]["type"] != "dir":
        raise ValueError("explicit root directory policy required")
    for path, record in records.items():
        if path != "/":
            parent = str(PurePosixPath(path).parent)
            if parent not in records or records[parent]["type"] != "dir":
                raise ValueError("missing directory policy: " + parent)
        if record.get("flags", "") not in ("", "none", "schg", "uchg"):
            raise ValueError("unqualified filesystem flags: " + record["flags"])
    roots = {}
    def root(path):
        chain = []
        seen = set()
        while path not in roots:
            if path in seen:
                raise ValueError("hardlink cycle")
            seen.add(path)
            record = records.get(path)
            if record is None or record["type"] not in ("file", "hardlink"):
                raise ValueError("hardlink target is not a regular file")
            chain.append(path)
            if record["type"] == "file":
                roots[path] = path
                break
            path = record["link"]
        target = roots[path]
        for member in chain:
            for key in ("owner", "group", "mode", "flags"):
                if records[member].get(key, "") != records[target].get(key, ""):
                    raise ValueError("hardlink inode metadata differs")
            roots[member] = target
        return target
    for path, record in records.items():
        if record["type"] == "hardlink":
            root(path)
    epoch = request["epoch"]
    if type(epoch) is not int or epoch < 0:
        raise ValueError("nonnegative explicit epoch required")
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
        order = {"dir": 0, "file": 1, "hardlink": 2, "symlink": 3}
        for path, record in sorted(records.items(), key=lambda item: (order[item[1]["type"]], item[0])):
            entry = tarfile.TarInfo(normalized(path))
            entry.uname, entry.gname = record["owner"], record["group"]
            entry.uid = request["users"][entry.uname]
            entry.gid = request["groups"][entry.gname]
            if any(type(v) is not int or v < 0 for v in (entry.uid, entry.gid)):
                raise ValueError("invalid numeric account identity")
            entry.mode = int(record["mode"], 8)
            if not 0 <= entry.mode <= 0o7777:
                raise ValueError("invalid mode")
            entry.mtime = epoch
            if record.get("flags") not in (None, "", "none"):
                entry.pax_headers["SCHILY.fflags"] = record["flags"]
            kind = record["type"]
            if kind == "dir":
                entry.type = tarfile.DIRTYPE
            elif kind == "hardlink":
                entry.type = tarfile.LNKTYPE
                entry.linkname = normalized(roots[path])
            elif kind == "symlink":
                entry.type = tarfile.SYMTYPE
                entry.linkname = record["link"]
            if kind == "file":
                with Path(record["source"]).open("rb") as payload:
                    entry.size = payload.seek(0, 2)
                    payload.seek(0)
                    archive.addfile(entry, payload)
            else:
                archive.addfile(entry)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--directory-metadata", type=Path)
    args = parser.parse_args()
    request = resolve(json.loads(args.request.read_text()))
    write_archive(request, args.output)
    if args.directory_metadata:
        selected = set(request.get("directory_packages", []))
        directories = [r for r in request["records"] if r["type"] == "dir" and
                       any(t.startswith("package=") and t[len("package="):] in selected for t in r.get("tags", []))]
        args.directory_metadata.write_text(json.dumps(dict(format=1, directories=directories), sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
