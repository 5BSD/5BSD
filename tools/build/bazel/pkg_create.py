# SPDX-License-Identifier: BSD-2-Clause
"""Create a declared pkgbase family from a serialized installation archive."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile


def directory_package(record, suffix_tags):
    tags = record["tags"]
    bases = [t[len("package="):] for t in tags if t.startswith("package=")]
    if len(bases) != 1 or not bases[0] or len(set(tags)) != len(tags):
        raise ValueError("invalid directory package tags")
    return bases[0] + "".join("-" + tag for tag in suffix_tags if tag in tags)


def create(request):
    versions = re.findall(r"^#define\s+__FreeBSD_version\s+(\d+)\s*$", Path(request["osversion_header"]).read_text(), re.M)
    if len(versions) != 1:
        raise ValueError("one target OS version definition required")
    outputs = {name: Path(path) for name, path in request["outputs"].items()}
    parent = next(iter(outputs.values())).parent
    with tempfile.TemporaryDirectory(prefix="pkg-create-", dir=parent) as temporary:
        work = Path(temporary)
        stage = work / "root"
        stage.mkdir()
        repos = work / "repos"
        repos.mkdir()
        config = work / "pkg.conf"
        config.write_text("{}\n")
        with tarfile.open(request["archive"]) as archive:
            members = archive.getmembers()
            names = {member.name for member in members}
            if len(names) != len(members):
                raise ValueError("duplicate installation archive members")
            for member in members:
                if member.name != "." and (member.name.startswith("/") or str(PurePosixPath(member.name)) != member.name or ".." in PurePosixPath(member.name).parts):
                    raise ValueError("invalid installation archive path")
                if not (member.isdir() or member.isfile() or member.islnk() or member.issym()):
                    raise ValueError("unsupported installation archive member")
            dirs = {"/" if m.name == "." else "/" + m.name: m for m in members if m.isdir()}
            indexed = {"/" if m.name == "." else "/" + m.name: m for m in members}
            expected = {}
            for entries in request["packages"].values():
                for record in entries:
                    if record["destination"] in expected:
                        raise ValueError("duplicate package layout path")
                    expected[record["destination"]] = record
            payload_paths = {path for path, record in expected.items() if record["type"] != "dir"}
            if set(indexed) - set(dirs) != payload_paths or not set(expected).issubset(indexed):
                raise ValueError("archive and package layout payload inventories differ")
            if "/" not in dirs:
                raise ValueError("archive root directory required")
            for path, member in indexed.items():
                if path != "/" and str(PurePosixPath(path).parent) not in dirs:
                    raise ValueError("archive member has a non-directory parent")
                if path not in expected:
                    continue
                record = expected[path]
                if (member.uname, member.gname, member.mode) != (record["owner"], record["group"], int(record["mode"], 8)):
                    raise ValueError("archive metadata differs from package layout")
                kind = record["type"]
                if kind not in ("file", "dir", "symlink", "hardlink"):
                    raise ValueError("unsupported package layout type")
                if kind == "dir" and not member.isdir():
                    raise ValueError("directory payload expected")
                if kind == "file" and not member.isfile():
                    raise ValueError("regular payload expected")
                if kind == "symlink" and (not member.issym() or member.linkname != record["link"]):
                    raise ValueError("symlink payload differs")
                if kind == "hardlink":
                    target = path
                    seen = set()
                    while expected[target]["type"] == "hardlink":
                        if target in seen:
                            raise ValueError("hardlink cycle")
                        seen.add(target)
                        target = expected[target]["link"]
                    if expected[target]["type"] != "file" or not member.islnk() or member.linkname != target.lstrip("/"):
                        raise ValueError("hardlink payload differs")
        owned_directories = {name: set() for name in request["packages"]}
        # Explicit layout records own their directories directly. The archive's
        # optional directory_packages sidecar supplements source mtree ownership;
        # it need not repeat directories already declared by the layout.
        for name, entries in request["packages"].items():
            for record in entries:
                if record["type"] != "dir":
                    continue
                if directory_package(record, request["suffix_tags"]) != name:
                    raise ValueError("directory package ownership differs from layout")
                path = record["destination"]
                owned_directories[name].add(path)
                owned_directories[name].update(str(p) for p in PurePosixPath(path).parents if str(p) != "/")
        policy = json.loads(Path(request["directory_metadata"]).read_text())
        if policy.get("format") != 1:
            raise ValueError("unsupported directory metadata format")
        seen_directories = set()
        for record in policy["directories"]:
            path = record["destination"]
            if path in seen_directories or path not in dirs or record["type"] != "dir":
                raise ValueError("invalid or duplicate package directory")
            seen_directories.add(path)
            meta = dirs[path]
            if (meta.uname, meta.gname, meta.mode) != (record["owner"], record["group"], int(record["mode"], 8)):
                raise ValueError("archive directory differs from package directory policy")
            declared = expected.get(path)
            if declared is not None and (declared["type"] != "dir" or
                    set(declared["tags"]) != set(record["tags"])):
                raise ValueError("directory package ownership differs from layout")
            name = directory_package(record, request["suffix_tags"])
            if name not in owned_directories:
                raise ValueError("directory belongs to undeclared package: " + name)
            owned_directories[name].add(path)
            owned_directories[name].update(str(p) for p in PurePosixPath(path).parents if str(p) != "/")
        subprocess.run([request["tar"], "-xpf", request["archive"], "--no-same-owner", "-C", str(stage)], check=True)
        common = [request["pkg"], "-C", str(config), "-R", str(repos), "-o", "PKG_DBDIR=" + str(work / "db")]
        abi = subprocess.run(common + ["-o", "ABI_FILE=" + request["abi_file"], "config", "ABI"], check=True, capture_output=True, text=True).stdout.strip()
        if not abi or any(c.isspace() for c in abi):
            raise ValueError("invalid target ABI")
        common += ["-o", "ABI=" + abi, "-o", "OSVERSION=" + versions[0], "-o", "ALLOW_BASE_SHLIBS=yes", "-o", "SHLIB_PROVIDE_PATHS_NATIVE=/lib,/usr/lib"]
        for name, records in request["packages"].items():
            lines = []
            parents = set(owned_directories[name])
            for record in records:
                path = record["destination"]
                if record.get("flags"):
                    raise ValueError("file flags not qualified")
                for value in (path, record["owner"], record["group"], record["mode"]):
                    if any(c in value for c in "\n\r(),"):
                        raise ValueError("unsupported plist field")
                if record["type"] == "dir":
                    # Directory ownership and ancestor closure are emitted once below.
                    parents.add(path)
                    continue
                kind = "config" if "config" in record["tags"] else ""
                lines.append("@" + kind + "(" + ",".join([record["owner"], record["group"], record["mode"], ""]) + ") " + path)
                parents.update(str(p) for p in PurePosixPath(path).parents if str(p) != "/")
            for path in sorted(parents):
                meta = dirs[path]
                lines.append("@dir(" + ",".join([meta.uname, meta.gname, format(meta.mode, "04o"), ""]) + ") " + path)
            plist = work / (name + ".plist")
            plist.write_text("\n".join(lines) + "\n")
            subprocess.run(common + ["create", "-f", request["format"], "-T", str(request["threads"]), "-t", str(request["epoch"]),
                "-r", str(stage), "-o", str(work), "-M", request["manifests"][name], "-p", str(plist)], check=True)
            produced = work / outputs[name].name
            if not produced.is_file():
                raise ValueError("pkg did not produce declared output: " + str(produced))
            os.replace(produced, outputs[name])
        index = {"format": 1, "packages": [dict(name=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in outputs.values()]}
        Path(request["index"]).write_text(json.dumps(index, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    args = parser.parse_args()
    create(json.loads(args.request.read_text()))


if __name__ == "__main__":
    main()
