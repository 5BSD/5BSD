#!/usr/bin/env python3
"""Build pinned upstream Linux test programs; never execute the test suite."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

SOURCES = {
    "liburing": ("liburing-2.12", "https://codeload.github.com/axboe/liburing/tar.gz/refs/tags/liburing-2.12", "f1d10cb058c97c953b4c0c446b11e9177e8c8b32a5a88b309f23fdd389e26370"),
    "fio": ("fio-3.41", "https://codeload.github.com/axboe/fio/tar.gz/refs/tags/fio-3.41", "38f2c723eda1d94fd25c91dbad30da7a551a58840b7a6368eaee3daa700fb088"),
}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--make", default="gmake", help="GNU make executable")
    ap.add_argument("--linux-sysroot", type=Path, help="Static x86_64 musl sysroot for FreeBSD builds")
    ap.add_argument("--clang-resource-dir", type=Path)
    a = ap.parse_args()
    b = a.output.resolve()
    b.mkdir(parents=True, exist_ok=True)
    make = shutil.which(a.make)
    if not make:
        ap.error("GNU make not found")
    cc = os.environ.get("CC", "cc")
    if a.linux_sysroot:
        root = str(a.linux_sysroot.resolve())
        resource = ["-resource-dir=" + str(a.clang_resource_dir.resolve())] if a.clang_resource_dir else []
        wrapper = b / "linux-cc"
        wrapper.write_text("#!/usr/bin/env python3\n" +
            "import os,sys,subprocess\n" +
            f"root={root!r}\nresource={resource!r}\n" +
            "args=sys.argv[1:]\n" +
            "cmd=['clang','--target=x86_64-linux-musl','--sysroot='+root]+resource\n" +
            "compile_only=any(x in args for x in ['-c','-E','-S','-M','-MM','--version','-dumpmachine','-dumpversion','-print-search-dirs','-print-libgcc-file-name'])\n" +
            "if not compile_only:cmd+=['-fuse-ld=lld','-static','-nostdlib',root+'/usr/lib/crt1.o',root+'/usr/lib/crti.o']\n" +
            "cmd+=args\n" +
            "if not compile_only:cmd+=['-L'+root+'/usr/lib','-lc','-lm','-lpthread',root+'/usr/lib/crtn.o']\n" +
            "ret=subprocess.run(cmd).returncode\n" +
            "if ret==0 and not compile_only and '-o' in args:subprocess.run(['brandelf','-t','Linux',args[args.index('-o')+1]],check=True)\n" +
            "sys.exit(ret)\n")
        wrapper.chmod(0o755)
        cc = str(wrapper)
    bindir = b / "bin"
    bindir.mkdir(exist_ok=True)
    link = bindir / "make"
    if link.is_symlink():
        link.unlink()
    link.symlink_to(make)
    env = dict(os.environ, CC=cc, PATH=str(bindir) + os.pathsep + os.environ["PATH"])
    trees = {}
    for name, (tag, url, digest) in SOURCES.items():
        archive = b / (tag + ".tar.gz")
        if not archive.exists():
            urllib.request.urlretrieve(url, archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise RuntimeError("Archive checksum mismatch: " + str(archive))
        with tarfile.open(archive) as tf:
            trees[name] = b / tf.getmembers()[0].name.split("/")[0]
            if not trees[name].exists():
                tf.extractall(b, filter="data")
    def run(cmd, cwd, log):
        with (b / log).open("w") as out:
            subprocess.run(cmd, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, check=True)
    lib = trees["liburing"]
    run(["./configure", "--cc=" + cc, "--cxx=false", "--use-libc"], lib, "liburing-configure.log")
    run([make, "-C", "src", "-j4", "ENABLE_SHARED=0"], lib, "liburing-build.log")
    result = subprocess.check_output([make, "-s", "-C", "test", "--eval=print-targets:;@echo $(test_targets)", "print-targets"], cwd=lib, env=env, text=True)
    targets = [t for t in result.split() if t.endswith(".t") and (lib / "test" / (t[:-2] + ".c")).is_file()]
    if not targets:
        raise RuntimeError("No C test targets found")
    run([make, "-C", "test", "-j4"] + targets, lib, "liburing-tests-build.log")
    fio = trees["fio"]
    # musl's fcntl.h does not expose all Linux fallocate flags.
    src = fio / "oslib/linux-blkzoned.c"
    original = src.read_text()
    if "#include <linux/falloc.h>" not in original:
        src.write_text(original.replace("#include <linux/blkzoned.h>", "#include <linux/blkzoned.h>\n#include <linux/falloc.h>"))
    run(["./configure", "--build-static", "--disable-native", "--disable-numa", "--disable-http", "--disable-rados", "--disable-libnfs", "--disable-libblkio", "--disable-libzbc"], fio, "fio-configure.log")
    run([make, "-j4", "fio"], fio, "fio-build.log")
    payload = b / "payload"
    (payload / "tests").mkdir(parents=True, exist_ok=True)
    for target in targets:
        shutil.copy2(lib / "test" / target, payload / "tests" / target)
    shutil.copy2(fio / "fio", payload / "fio")
    for name in ["guest.sh", "cases.txt"]:
        shutil.copy2(Path(__file__).parent / name, payload / name)
    record = {"sources": SOURCES, "excluded": ["C++ tests"], "fio_build_adjustment": "include linux/falloc.h", "binaries": {str(p.relative_to(payload)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(payload.rglob("*")) if p.is_file()}}
    (b / "build-manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    print(payload)

if __name__ == "__main__":
    main()
