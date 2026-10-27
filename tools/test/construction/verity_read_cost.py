# SPDX-License-Identifier: BSD-2-Clause
"""Count actual verifier callback traffic; not disk IOPS or a throughput benchmark."""
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[3]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--scratch-directory', type=Path, required=True)
    parser.add_argument('--data-bytes', type=int, required=True)
    parser.add_argument('--block-size', type=int, required=True)
    parser.add_argument('--request-bytes', type=int, required=True)
    parser.add_argument('--offset', type=int, default=0)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('tree', ROOT/'tools/build/capimage/verity_tree.py')
    tree = importlib.util.module_from_spec(spec); spec.loader.exec_module(tree)
    counts, _, tree_bytes = tree.geometry(args.data_bytes, args.block_size)
    if not (0 <= args.offset < args.data_bytes and 0 < args.request_bytes <= args.data_bytes - args.offset):
        parser.error('request must be a nonempty range inside data')
    library = args.library.resolve(strict=True)
    lib = C.CDLL(str(library))
    Reader = C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_int,C.c_uint64,C.c_void_p,C.c_size_t)
    lib.g_verity_read_range.argtypes = [C.c_uint64,C.c_uint32,C.c_void_p,C.c_size_t,
        C.c_void_p,C.c_uint64,C.c_size_t,Reader,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p]
    lib.g_verity_read_range.restype = C.c_int
    calls = [0, 0]; read_bytes = [0, 0]; unique = [set(), set()]
    with tempfile.TemporaryDirectory(prefix='verity-cost-', dir=args.scratch_directory) as scratch:
        with open(Path(scratch)/'data','w+b') as data, open(Path(scratch)/'tree','w+b') as hashes:
            data.truncate(args.data_bytes)
            salt = b'cost-probe'
            root = tree.build_tree(data.fileno(), hashes.fileno(), args.data_bytes,args.block_size,salt)
            @Reader
            def reader(arg, is_hash, offset, destination, length):
                calls[is_hash] += 1; read_bytes[is_hash] += length
                unique[is_hash].add((offset,length))
                content = os.pread((hashes if is_hash else data).fileno(),length,offset)
                if len(content) != length:
                    return 5
                C.memmove(destination,content,length)
                return 0
            scratch_buffers = [C.create_string_buffer(args.block_size) for _ in range(3)]
            output = C.create_string_buffer(args.request_bytes)
            result = lib.g_verity_read_range(args.data_bytes,args.block_size,salt,len(salt),root,
                args.offset,args.request_bytes,reader,None,*scratch_buffers,output)
            if result or any(output.raw):
                raise RuntimeError(f'verifier failed: {result}')
    sources = ['sys/geom/verity/g_verity_verify.c','tools/build/capimage/verity_tree.py']
    report = dict(scope='native-verifier-callback-cost', data_bytes=args.data_bytes,
        block_size=args.block_size, tree_levels=len(counts), tree_bytes=tree_bytes,
        offset=args.offset, request_bytes=args.request_bytes,
        data_read_calls=calls[0], hash_read_calls=calls[1],
        data_read_bytes=read_bytes[0], hash_read_bytes=read_bytes[1],
        unique_data_blocks=len(unique[0]), unique_hash_blocks=len(unique[1]),
        requested_byte_amplification=sum(read_bytes)/args.request_bytes,
        library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        source_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},
        physical_io_measured=False, throughput_measured=False, vm_run=False,
        caveats=['Zero-filled synthetic fixture; no application workload',
                 'Callbacks may be served from filesystem or ZFS caches',
                 'Python callbacks unsuitable for kernel performance estimates',
                 'Counts include request-local authenticated leaf reuse; no inter-request cache'])
    print(json.dumps(report,indent=2))

if __name__ == '__main__':
    main()
