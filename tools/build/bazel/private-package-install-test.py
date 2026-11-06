#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Root-shell qualification of package add/check/delete in a fresh /usr/obj root."""
from package_index import packages as indexed_packages
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess



def pkg_command(pkg, root, config, repositories):
    """Explicit pkg overrides are host paths, even with -r relocation."""
    return [str(pkg), "-r", str(root), "-C", str(config), "-R", str(repositories),
            "-o", "PKG_DBDIR=" + str(root / "var/db/pkg"),
            "-o", "PKG_CACHEDIR=" + str(root / "var/cache/pkg"),
            "-o", "RUN_SCRIPTS=no", "-o", "PKG_ENABLE_PLUGINS=no",
            "-o", "PKG_TRIGGERS_ENABLE=no", "-o", "REPO_AUTOUPDATE=no", "-o", "SYSLOG=no"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pkg", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("OS root privileges required for isolated package installation; no host installation is performed")
    source = args.packages.resolve(strict=True)
    out = args.output.resolve()
    if out.exists() or args.output.is_symlink() or out == Path("/usr/obj") or not out.is_relative_to("/usr/obj") or source.is_relative_to(out) or out.is_relative_to(source):
        raise ValueError("fresh nonoverlapping test output below /usr/obj required")
    pkg = args.pkg.resolve(strict=True)
    archives = indexed_packages(source)
    if not archives:
        raise ValueError("explicit package files required")
    manifests = []
    payload_paths = set()
    for archive in archives:
        manifest = json.loads(subprocess.check_output(["/usr/bin/tar", "-xOf", str(archive), "+MANIFEST"]))
        if manifest.get("scripts") or manifest.get("lua_scripts"):
            raise ValueError("this qualification does not permit package scripts")
        for path in manifest.get("files", {}):
            if not path.startswith("/") or ".." in Path(path).parts:
                raise ValueError("unsafe package payload path")
        if payload_paths.intersection(manifest.get("files", {})):
            raise ValueError("overlapping package payloads")
        payload_paths.update(manifest.get("files", {}))
        manifests.append(manifest)
    names = {manifest["name"] for manifest in manifests}
    if len(names) != len(manifests):
        raise ValueError("duplicate package names")
    out.mkdir()
    root = out / "root"
    root.mkdir()
    for directory in (root / "var/db/pkg", root / "var/cache/pkg"):
        directory.mkdir(parents=True)
    repo = out / "empty-repositories"
    repo.mkdir()
    inputs = out / "inputs"
    inputs.mkdir()
    config = out / "pkg.conf"
    config.write_text('RUN_SCRIPTS = false; PKG_ENABLE_PLUGINS = false;\n')
    copied = []
    hashes = {}
    for archive in archives:
        target = inputs / archive.name
        shutil.copyfile(archive, target)
        hashes[archive.name] = hashlib.sha256(target.read_bytes()).hexdigest()
        copied.append(target)
    # Every mutating invocation has an explicit alternate installation root.
    command = pkg_command(pkg, root, config, repo)
    commands = []
    def run(arguments, label):
        argv = command + arguments
        result = subprocess.run(argv, capture_output=True, text=True, env={"PATH":"/bin:/usr/bin:/sbin:/usr/sbin", "LC_ALL":"C"})
        (out / (label + ".stdout")).write_text(result.stdout)
        (out / (label + ".stderr")).write_text(result.stderr)
        commands.append(dict(argv=argv, status=result.returncode))
        (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(label + " failed; see private logs")
        return result.stdout
    # Check effective config before any mutating package command. -r relocates
    # defaults; explicit -o paths must already include the private root.
    for key, path in [("PKG_DBDIR", root / "var/db/pkg"), ("PKG_CACHEDIR", root / "var/cache/pkg")]:
        if run(["config", key], "config-" + key).strip() != str(path):
            raise ValueError("pkg path escaped private root: " + key)
    run(["add", "-I", *map(str, copied)], "add")
    if set(run(["query", "%n"], "query").splitlines()) != names:
        raise ValueError("installed package inventory differs")
    database = root / "var/db/pkg/local.sqlite"
    if not database.is_file():
        raise ValueError("private database missing")
    run(["check", "-s", "-a"], "checksums")
    for manifest in manifests:
        for name in manifest["files"]:
            path = root / name.lstrip("/")
            if not path.exists() and not path.is_symlink():
                raise ValueError("installed payload missing: " + name)
    run(["delete", "-a", "-y"], "delete")
    if run(["query", "-a", "%n"], "post-delete-inventory").strip():
        raise ValueError("private database still contains packages")
    for manifest in manifests:
        for name in manifest["files"]:
            path = root / name.lstrip("/")
            if path.exists() or path.is_symlink():
                raise ValueError("deleted package payload remains: " + name)
    (out / "receipt.json").write_text(json.dumps(dict(status="passed", scope="private-root add/check/delete; not booted runtime, upgrade, solver repository or host installation", package_sha256=hashes, root=str(root), commands=commands), indent=2) + "\n")
    print(out / "receipt.json")


if __name__ == "__main__":
    main()
