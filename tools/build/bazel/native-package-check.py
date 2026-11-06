#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare native pkg archives with declared payloads and independent Make packages."""
from package_index import packages as indexed_packages
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import archive_headers


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "layout", "packages", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--directory-metadata", type=Path)
    parser.add_argument("--reference", type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() or not out.is_relative_to("/usr/obj"):
        raise ValueError("fresh inspection output under /usr/obj required")
    layout = json.loads(args.layout.read_text())
    expected = {record["destination"]: record for entries in layout["packages"].values() for record in entries}
    with tarfile.open(args.archive) as tar:
        members = {"/" if m.name == "." else "/" + m.name: m for m in tar.getmembers()}
    archives = indexed_packages(args.packages)
    if len(archives) != len(layout["packages"]):
        raise ValueError("package inventory differs")
    owned = {name: set() for name in layout["packages"]}
    if args.directory_metadata:
        directory_policy = json.loads(args.directory_metadata.read_text())
        if directory_policy.get("format") != 1:
            raise ValueError("unsupported directory metadata format")
        for entry in directory_policy["directories"]:
            bases = [t[8:] for t in entry["tags"] if t.startswith("package=")]
            if len(bases) != 1:
                raise ValueError("invalid directory ownership")
            name = bases[0] + "".join("-" + s for s in layout["suffix_tags"] if s in entry["tags"])
            owned[name].add(entry["destination"])
    out.mkdir()
    extracted = out / "extracted"
    extracted.mkdir()
    seen = set()
    results = []
    for archive in archives:
        reference = args.reference / archive.name if args.reference else None
        def manifest(path):
            return json.loads(subprocess.check_output(["/usr/bin/tar", "-xOf", str(path), "+MANIFEST"]))
        current = manifest(archive)
        previous = manifest(reference) if reference else None
        if previous is not None:
            keys = set(current) | set(previous)
            for key in keys - {"files", "flatsize"}:
                if current.get(key) != previous.get(key):
                    raise ValueError("Make package metadata differs: " + archive.name + ":" + key)
        names = set(current["files"])
        matches = [name for name, entries in layout["packages"].items() if {e["destination"] for e in entries if e["type"] != "dir"} == names]
        if len(matches) != 1 or matches[0] in seen:
            raise ValueError("package file partition differs")
        package_name = matches[0]
        configs = {e["destination"] for e in layout["packages"][package_name] if "config" in e["tags"]}
        if configs != set(current.get("config", {})):
            raise ValueError("package configuration inventory differs: " + package_name)
        required_dirs = set(owned[package_name])
        for path in names | owned[package_name]:
            required_dirs.update(str(p) for p in Path(path).parents if str(p) != "/")
        if required_dirs != set(current.get("directories", {})):
            raise ValueError("package directory inventory differs: " + package_name)
        seen.add(package_name)
        if previous is not None and names != set(previous["files"]):
            raise ValueError("Make package file inventory differs")
        headers = archive_headers.read(archive)
        got = set()
        for header in headers:
            raw = header["pathname"]
            if raw in ("+MANIFEST", "+COMPACT_MANIFEST"):
                continue
            path = "/" + raw.lstrip("/").rstrip("/")
            if path not in members or path in got:
                raise ValueError("unexpected/duplicate archive member: " + path)
            got.add(path)
            meta = members[path]
            if (header["uname"], header["gname"], stat.S_IMODE(header["mode"])) != (meta.uname, meta.gname, meta.mode):
                raise ValueError("archive metadata differs: " + path)
            archive_headers.check_flags(header, meta.pax_headers.get("SCHILY.fflags", "none"))
            if header["symlink"] is not None and (not meta.issym() or header["symlink"] != meta.linkname):
                raise ValueError("archive symlink differs")
        if got != names | set(current.get("directories", {})):
            raise ValueError("archive headers differ from pkg manifest")
        subprocess.run(["/usr/bin/tar", "-xpf", str(archive), "--no-same-owner", "--no-fflags", "-C", str(extracted)], check=True)
        results.append(dict(name=archive.name, sha256=digest(archive), reference_sha256=digest(reference) if reference else None))
    if seen != set(layout["packages"]):
        raise ValueError("missing package")
    with tarfile.open(args.archive) as tar:
        for path, record in expected.items():
            file = extracted / path.lstrip("/")
            if record["type"] == "symlink":
                if os.readlink(file) != record["link"]:
                    raise ValueError("extracted symlink differs")
            elif record["type"] == "hardlink":
                if not file.samefile(extracted / record["link"].lstrip("/")):
                    raise ValueError("extracted hardlink differs")
            elif record["type"] == "dir":
                if not file.is_dir() or file.is_symlink():
                    raise ValueError("extracted directory differs")
            elif file.read_bytes() != tar.extractfile(path.lstrip("/")).read():
                raise ValueError("extracted payload bytes differ: " + path)
            if record["type"] != "symlink" and stat.S_IMODE(file.stat().st_mode) != int(record["mode"], 8):
                raise ValueError("extracted mode differs")
    result = dict(status="passed", scope="native pkg payload/link extraction versus installation archive; not installation/solver/performance qualification", make_reference_compared=args.reference is not None, packages=results,
                  input_sha256={str(p):digest(p) for p in ([args.archive, args.layout, Path(__file__), Path(archive_headers.__file__)] + ([args.directory_metadata] if args.directory_metadata else []))})
    (out / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    print(out / "receipt.json")


if __name__ == "__main__":
    main()
