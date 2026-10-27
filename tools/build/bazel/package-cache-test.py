#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build package outputs cold, restore from disk cache, then rebuild independently."""
from package_index import packages as indexed_packages
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


from execution_log import objects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("src", "commands", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--package-directory", type=Path, required=True)
    args = parser.parse_args()
    src = args.src.resolve(strict=True)
    out = args.output.resolve()
    if out.exists() or not out.is_relative_to("/usr/obj"):
        raise ValueError("fresh output below /usr/obj required")
    if args.package_directory.is_absolute() or ".." in args.package_directory.parts or not args.target.startswith("//"):
        raise ValueError("source target and relative output package directory required")
    seed = json.loads(args.commands.read_text())[0]["argv"]
    prefixes = ("--max_idle_secs=", "--output_user_root=", "--symlink_prefix=", "--build_event_json_file=", "--execution_log_json_file=", "--disk_cache=")
    java_homes = [v.split("=", 1)[1] for v in seed if v.startswith("--server_javabase=")]
    if len(java_homes) != 1 or not Path(java_homes[0]).is_dir():
        raise ValueError("one explicit recorded Java home required")
    base = [v for v in seed if not v.startswith(prefixes) and not v.startswith("//")]
    if "test" in base:
        base[base.index("test")] = "build"
    if "--batch" not in base:
        base.insert(1, "--batch")
    out.mkdir()
    results = []
    for name in ("cold", "restored", "independent"):
        run = out / name
        run.mkdir()
        cache = out / ("independent-cache" if name == "independent" else "shared-cache")
        argv = base[:]
        argv.insert(argv.index("build"), "--output_user_root=" + str(run / "user-root"))
        argv += ["--disk_cache=" + str(cache), "--symlink_prefix=" + str(run / "bazel-"),
                 "--execution_log_json_file=" + str(run / "execution.json"), args.target]
        start = time.monotonic()
        with (run / "build.log").open("w") as log:
            done = subprocess.run(["/usr/bin/time", "-l", *argv], cwd=src, stdout=log, stderr=subprocess.STDOUT,
                                  env=dict(os.environ, JAVA_HOME=java_homes[0], BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN="1"))
        if done.returncode:
            raise RuntimeError(name + " build failed; see " + str(run / "build.log"))
        spawns = [v for v in objects(run / "execution.json") if v.get("targetLabel") == args.target and any("pkg_create.py" in x for x in v.get("commandArgs", []))]
        if len(spawns) != 1:
            raise ValueError("expected one package creation spawn")
        spawn = spawns[0]
        hit = spawn.get("cacheHit", False)
        if hit != (name == "restored"):
            raise ValueError("package action execution/cache expectation failed: " + name)
        packages = run / "bazel-bin" / args.package_directory
        files = indexed_packages(packages)
        if not files:
            raise ValueError("no package outputs")
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        result = dict(name=name, argv=argv, cache_hit=hit, package_sha256=hashes,
                      elapsed_seconds=time.monotonic() - start, action_metrics=spawn.get("metrics", {}),
                      status="passed" if not results or results[0]["package_sha256"] == hashes else "failed")
        results.append(result)
        (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        if result["status"] != "passed":
            raise ValueError("package bytes differ: " + name)
    (out / "receipt.json").write_text(json.dumps(dict(status="passed", scope="selected package action cache restoration and independent-build byte reproducibility; not installation or performance comparison", results=results), indent=2) + "\n")
    print(out / "receipt.json")


if __name__ == "__main__":
    main()
