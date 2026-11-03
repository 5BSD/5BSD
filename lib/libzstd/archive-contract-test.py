#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect actual archive selection and target architecture with native tools."""
import argparse
from pathlib import Path
import struct
import os
import tempfile
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ["consumer", "program", "shared", "archive", "pic-archive", "nm", "ar"]:
        p.add_argument("--" + key, type=Path, required=True)
    p.add_argument("--machine", type=int, choices=[62, 183, 243], required=True)
    a = p.parse_args()
    for path, kinds in [(a.consumer, [2, 3]), (a.shared, [3])]:
        data = path.read_bytes()
        if data[:6] != b"\x7fELF\x02\x01":
            raise ValueError("ELF64 little endian target required")
        kind, machine = struct.unpack_from("<HH", data, 16)
        if kind not in kinds or machine != a.machine:
            raise ValueError("target architecture/type mismatch")
    names = ['entropy_common.o', 'error_private.o', 'fse_decompress.o', 'pool.o', 'threading.o', 'xxhash.o', 'zstd_common.o', 'fse_compress.o', 'huf_compress.o', 'zstd_compress.o', 'zstd_compress_literals.o', 'zstd_compress_sequences.o', 'zstd_compress_superblock.o', 'zstd_preSplit.o', 'zstdmt_compress.o', 'huf_decompress.o', 'zstd_ddict.o', 'zstd_decompress.o', 'zstd_decompress_block.o', 'zbuff_common.o', 'zbuff_compress.o', 'zbuff_decompress.o', 'cover.o', 'divsufsort.o', 'zdict.o', 'zstd_fast.o', 'zstd_lazy.o', 'zstd_ldm.o', 'zstd_opt.o', 'zstd_double_fast.o', 'debug.o', 'hist.o', 'fastcover.o']
    if a.machine == 243:
        names.append("zstd_kfreebsd.o")
    for archive, expected in [(a.archive, names), (a.pic_archive, [x[:-2] + ".pic.o" for x in names])]:
        actual = subprocess.check_output([a.ar, "t", archive], text=True).splitlines()
        if actual != expected:
            raise ValueError("original member order mismatch")
    symbols = {line.split()[-1] for line in subprocess.check_output([a.nm, "--defined-only", a.consumer], text=True).splitlines() if line.split()}
    if "ZSTD_versionNumber" not in symbols or "ZSTD_compress" in symbols or "POOL_create" in symbols:
        raise ValueError("default archive extraction contract mismatch")
    if a.machine == 62:
        # Native ABI only; foreign artifacts are never executed.
        env = dict(os.environ, LD_LIBRARY_PATH=str(a.shared.resolve().parent))
        sample = bytes(range(256)) * 1024
        with tempfile.TemporaryDirectory(prefix="zstd-family-") as temp:
            for alias in ["zstd", "zstdmt", "unzstd", "zstdcat"]:
                program = Path(temp) / alias
                program.symlink_to(a.program.resolve())
                encoded = subprocess.check_output([a.program, "-q", "-c", "--check"], input=sample, env=env)
                args = [program, "-q", "-c"] + ([] if alias in ["unzstd", "zstdcat"] else ["-d"])
                decoded = subprocess.check_output(args, input=encoded, env=env)
                if decoded != sample:
                    raise ValueError("native command alias roundtrip differs")
                rejected = subprocess.run(args, input=encoded[:-3], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if rejected.returncode == 0:
                    raise ValueError("truncated native command input accepted")
    print("PASS target ABI, original member order and selective static extraction; native-only command checks")


if __name__ == "__main__":
    main()
