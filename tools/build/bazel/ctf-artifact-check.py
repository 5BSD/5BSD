#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare a captured ELF64 object's CTF metadata with an explicit Make object."""
import argparse
import hashlib
import json
from pathlib import Path
import ctf_semantics
import qualification_artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--output-suffix', required=True)
    parser.add_argument('--make-binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    native_path, binding = qualification_artifacts.resolve(args.qualification, args.target, args.output_suffix)
    native = ctf_semantics.read_elf(native_path)
    reference = ctf_semantics.read_elf(args.make_binary)
    if native.sha256 != binding['sha256']:
        raise ValueError('captured artifact changed during inspection')
    result = ctf_semantics.compare(reference, native)
    with args.make_binary.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != reference.sha256:
            raise ValueError('Make reference changed during inspection')
    implementation = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in [Path(__file__), Path(ctf_semantics.__file__), Path(qualification_artifacts.__file__)]}
    result.update({'format': 1, 'implementation_sha256': implementation, 'scope': 'CTF type layouts, reference graphs and ELF symbol associations; not whole ELF, calling convention, runtime or complete ABI qualification',
                   'native': binding, 'make': str(args.make_binary), 'make_sha256': reference.sha256,
                   'make_ctf_sha256': reference.ctf_sha256, 'native_ctf_sha256': native.ctf_sha256,
                   'ctf_bytes_equal': reference.ctf_sha256 == native.ctf_sha256})
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
