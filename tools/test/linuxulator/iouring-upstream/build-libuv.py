#!/usr/bin/env python3
"""Build a pinned, unmodified libuv and its Linux application compatibility check."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

VERSION = "1.53.0"
URL = f"https://dist.libuv.org/dist/v{VERSION}/libuv-v{VERSION}.tar.gz"
SHA256 = "cb0d6dd2128d5a95bd242c6cc982a24fe608fa93da57b6b4ec763b0018c53e64"
# Linux static-library sources from this release's CMakeLists.txt.
COMMON = "fs-poll idna inet random strscpy strtok thread-common threadpool timer uv-common uv-data-getter-setters version".split()
UNIX = "async core dl fs getaddrinfo getnameinfo loop-watcher loop pipe poll process proctitle random-devurandom signal stream tcp thread tty udp linux procfs-exepath random-getrandom random-sysctl-linux".split()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"),
                    help="Linux C compiler or the linux-cc wrapper from build.py")
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"libuv-v{VERSION}.tar.gz"
    if not archive.exists():
        urllib.request.urlretrieve(URL, archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise RuntimeError("libuv archive checksum mismatch")
    with tarfile.open(archive) as tf:
        tf.extractall(out, filter="data")
    root = out / f"libuv-v{VERSION}"
    obj = out / "objects"
    obj.mkdir(exist_ok=True)
    flags = ["-O2", "-g", "-std=gnu11", "-fno-strict-aliasing", "-pthread",
             "-D_GNU_SOURCE", "-D_FILE_OFFSET_BITS=64", "-D_LARGEFILE_SOURCE",
             "-I" + str(root / "include"), "-I" + str(root / "src")]
    sources = [root / "src" / (n + ".c") for n in COMMON]
    sources += [root / "src/unix" / (n + ".c") for n in UNIX]
    sources += [Path(__file__).resolve().with_name("libuv-compat.c")]
    commands = []
    objects = []
    for i, source in enumerate(sources):
        target = obj / f"{i:02d}-{source.stem}.o"
        objects.append(str(target))
        commands.append([args.cc, *flags, "-c", str(source), "-o", str(target)])

    def compile_one(command):
        return subprocess.run(command, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(compile_one, commands))
    (out / "build.log").write_text("".join(r.stdout for r in results))
    if any(r.returncode for r in results):
        raise RuntimeError("Compilation failed; see build.log")
    binary = out / "libuv-compat"
    link = [args.cc, "-static", "-pthread", *objects, "-ldl", "-lrt", "-lm",
            "-o", str(binary)]
    with (out / "build.log").open("a") as log:
        subprocess.run(link, stdout=log, stderr=subprocess.STDOUT, check=True)
    manifest = {"libuv_version": VERSION, "source_url": URL,
                "source_sha256": SHA256, "commands": commands + [link],
                "test_sha256": hashlib.sha256(sources[-1].read_bytes()).hexdigest(),
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    (out / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(binary)


if __name__ == "__main__":
    main()
