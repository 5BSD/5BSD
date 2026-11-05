#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build a component archive cold, restore from cache, and rebuild independently."""
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
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--tar", type=Path, required=True)
    args = parser.parse_args()
    src = args.src.resolve(strict=True)
    out = args.output.resolve()
    if out.exists() or not out.is_relative_to("/usr/obj"):
        raise ValueError("fresh output below /usr/obj required")
    if args.archive.is_absolute() or ".." in args.archive.parts or not args.target.startswith("//"):
        raise ValueError("source target and relative output archive required")
    recorded = json.loads(args.commands.read_text())
    seeds = [command["argv"] for command in recorded
             if any(value in ("build", "test") for value in command["argv"])]
    if not seeds:
        raise ValueError("recorded commands contain no native build or test invocation")
    seed = seeds[0]
    prefixes = ("--max_idle_secs=", "--output_user_root=", "--symlink_prefix=", "--build_event_json_file=", "--execution_log_json_file=", "--execution_log_compact_file=", "--execution_log_binary_file=", "--output_groups=", "--disk_cache=")
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
                 "--execution_log_json_file=" + str(run / "execution.json"),
                 "--output_groups=+metadata,+directory_metadata", args.target]
        start = time.monotonic()
        with (run / "build.log").open("w") as log:
            done = subprocess.run(["/usr/bin/time", "-l", *argv], cwd=src, stdout=log, stderr=subprocess.STDOUT,
                                  env=dict(os.environ, JAVA_HOME=java_homes[0], BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN="1"))
        if done.returncode:
            raise RuntimeError(name + " build failed; see " + str(run / "build.log"))
        spawns = [v for v in objects(run / "execution.json") if v.get("targetLabel") == args.target and v.get("mnemonic") in ("BSDInstallArchive", "BSDInstallTreeArchive")]
        if len(spawns) != 1:
            raise ValueError("expected one installation archive spawn")
        spawn = spawns[0]
        hit = spawn.get("cacheHit", False)
        if hit != (name == "restored"):
            raise ValueError("archive action execution/cache expectation failed: " + name)
        archive = run / "bazel-bin" / args.archive
        outputs = [archive, archive.with_suffix(".json"),
                   archive.with_name(archive.stem + ".directories.json")]
        hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in outputs}
        subprocess.run([os.sys.executable, str(Path(__file__).with_name("archive-extraction-check.py")),
                        "--archive", str(archive), "--output", str(run / "extraction"),
                        "--tar", str(args.tar)], check=True)
        result = dict(name=name, argv=argv, cache_hit=hit, archive_sha256={archive.name: hashes[archive.name]},
                      installation_outputs_sha256=hashes,
                      elapsed_seconds=time.monotonic() - start, action_metrics=spawn.get("metrics", {}),
                      status="passed" if not results or results[0]["installation_outputs_sha256"] == hashes else "failed")
        results.append(result)
        (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        if result["status"] != "passed":
            raise ValueError("installation archive or metadata bytes differ: " + name)
    (out / "receipt.json").write_text(json.dumps(dict(status="passed", scope="component archive/metadata cache restoration, independent-build byte reproducibility, and extraction; not package lifecycle or Make performance comparison", results=results), indent=2) + "\n")
    print(out / "receipt.json")


if __name__ == "__main__":
    main()
