#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Audit Make-selected kernel module leaves against native Bazel descriptions."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def kernel_options(kernel_build_dir):
    options = set()
    for path in sorted(Path(kernel_build_dir).glob("opt*.h")):
        for line in path.read_text(errors="replace").splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "#define":
                options.add(fields[1])
    return sorted(options)


def parse_make_query(output):
    """Parse `make -V SUBDIR -V KMOD`, retaining the empty values."""
    lines = output.splitlines()
    if len(lines) != 2:
        raise ValueError("expected exactly SUBDIR and KMOD output lines")
    subdirs = [part for part in lines[0].split() if part != ".WAIT"]
    kmod = lines[1].strip()
    if kmod and len(kmod.split()) != 1:
        raise ValueError("expected one KMOD name")
    return subdirs, kmod


def resolve_subdir(modules_root, parent, child):
    candidate = (modules_root / parent / child).resolve(strict=False)
    root = Path(modules_root).resolve(strict=True)
    if not candidate.is_relative_to(root):
        raise ValueError("SUBDIR escapes sys/modules: " + child)
    return candidate.relative_to(root)


def module_description(src, relative, kmod):
    directory = Path(src) / "sys/modules" / relative
    build_file = directory / "BUILD.bazel"
    text = build_file.read_text(errors="replace") if build_file.is_file() else ""
    return {
        "dir": relative.as_posix() or ".",
        "kmod": kmod,
        "build_file": build_file.is_file(),
        "direct_module_macro": bool(re.search(r"\bamd64_generic_module\s*\(", text)),
    }


def audit(src, make, target, target_arch, kernel_build_dir, srconf, make_conf, env_conf):
    src = Path(src).resolve(strict=True)
    modules_root = src / "sys/modules"
    kernel_build_dir = Path(kernel_build_dir).resolve(strict=True)
    options = " ".join(kernel_options(kernel_build_dir))
    queue = [Path()]
    visited = set()
    records = []
    errors = []
    while queue:
        relative = queue.pop()
        if relative in visited:
            continue
        visited.add(relative)
        directory = modules_root / relative
        if not directory.is_relative_to(modules_root) or not (directory / "Makefile").is_file():
            errors.append({"dir": relative.as_posix(), "error": "selected SUBDIR has no Makefile"})
            continue
        command = [
            make, "-C", str(directory), "SRCTOP=" + str(src),
            "TARGET=" + target, "TARGET_ARCH=" + target_arch,
            "KERNBUILDDIR=" + str(kernel_build_dir), "KERN_OPTS=" + options,
            "SRCCONF=" + srconf, "__MAKE_CONF=" + make_conf,
            "SRC_ENV_CONF=" + env_conf, "-V", "SUBDIR", "-V", "KMOD",
        ]
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            errors.append({"dir": relative.as_posix(), "error": result.stderr.strip()[-1000:]})
            continue
        try:
            children, kmod = parse_make_query(result.stdout)
        except ValueError as error:
            errors.append({"dir": relative.as_posix(), "error": str(error)})
            continue
        if kmod:
            records.append(module_description(src, relative, kmod))
        for child in children:
            child_path = Path(child)
            if child_path.is_absolute():
                errors.append({"dir": relative.as_posix(), "error": "absolute SUBDIR entry: " + child})
                continue
            try:
                queue.append(resolve_subdir(modules_root, relative, child_path))
            except ValueError as error:
                errors.append({"dir": relative.as_posix(), "error": str(error)})
    records.sort(key=lambda record: (record["dir"], record["kmod"]))
    makefiles = [p for p in modules_root.rglob("Makefile") if p.is_file() and p.parent != modules_root]
    direct_targets = sum(record["direct_module_macro"] for record in records)
    build_files = sum(record["build_file"] for record in records)
    return {
        "format": 1,
        "status": "complete" if not errors else "incomplete",
        "scope": "recursive Make SUBDIR selection; direct Bazel module macro presence is a source inventory, not build or runtime qualification",
        "target": target,
        "target_arch": target_arch,
        "kernel_build_dir": str(kernel_build_dir),
        "source_config": srconf,
        "make_config": make_conf,
        "source_environment_config": env_conf,
        "module_makefile_directories": len(makefiles),
        "selected_leaf_kmods": len(records),
        "selected_with_build_file": build_files,
        "selected_with_direct_module_macro": direct_targets,
        "selected_without_direct_module_macro": len(records) - direct_targets,
        "errors": errors,
        "modules": records,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--src", required=True)
    parser.add_argument("--make", default="/usr/bin/make")
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-arch", required=True)
    parser.add_argument("--kernel-build-dir", required=True)
    parser.add_argument("--src-conf", default="/dev/null")
    parser.add_argument("--make-conf", default="/dev/null")
    parser.add_argument("--source-env-conf", default="/dev/null")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = audit(args.src, args.make, args.target, args.target_arch,
                   args.kernel_build_dir, args.src_conf, args.make_conf,
                   args.source_env_conf)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in (
        "status", "module_makefile_directories", "selected_leaf_kmods",
        "selected_with_build_file", "selected_with_direct_module_macro",
        "selected_without_direct_module_macro")}, sort_keys=True))
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
