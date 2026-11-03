#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect actual OpenSSL core target outputs without executing foreign programs."""
import argparse
import json
from pathlib import Path
import struct
import subprocess


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'pic-archive', 'shared', 'static-consumer', 'shared-consumer', 'ar', 'nm'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--machine', type=int, choices=[62, 183, 243], required=True)
    parser.add_argument("--member-order", type=Path, required=True)
    args = parser.parse_args()
    for path, kinds in [(args.shared, [3]), (args.static_consumer, [2, 3]), (args.shared_consumer, [2, 3])]:
        data = path.read_bytes()
        require(data[:6] == b'\x7fELF\x02\x01' and len(data) >= 64, 'ELF64 little endian required')
        kind, machine = struct.unpack_from('<HH', data, 16)
        require(kind in kinds and machine == args.machine, 'target machine/type differs')
    ordinary = subprocess.check_output([args.ar, 't', args.archive], text=True).splitlines()
    pic = subprocess.check_output([args.ar, 't', args.pic_archive], text=True).splitlines()
    expected = json.loads(args.member_order.read_text())
    require(isinstance(expected, list) and expected and len(set(expected)) == len(expected),
            'selected source-owned member order is empty or ambiguous')
    require(ordinary == expected, 'selected original core member count/order differs')
    require(all(name.endswith('.o') for name in ordinary), 'ordinary object suffix differs')
    require(pic == [name.removesuffix('.o') + '.pic.o' for name in ordinary],
            'PIC/ordinary member order or variant differs')
    symbols = subprocess.check_output([args.nm, '--format=posix', '--extern-only', '--defined-only', args.static_consumer], text=True)
    defined = {line.split()[0] for line in symbols.splitlines() if line.split()}
    require({'EVP_Digest', 'EVP_EncryptInit_ex', 'EVP_DigestSign', 'RAND_bytes', 'BN_mod_exp'} <= defined,
            'real core API consumer did not extract the default archive API')
    dynamic = subprocess.check_output([args.nm, '--dynamic', '--format=posix', '--extern-only', '--defined-only', args.shared], text=True)
    exported = {line.split()[0].split('@', 1)[0] for line in dynamic.splitlines() if line.split()}
    require({'X509_new', 'X509_STORE_CTX_init', 'PEM_read_bio_PrivateKey', 'OSSL_CMP_CTX_new'} <= exported,
            'shared archive lost exported APIs not used by the smoke consumer')
    print('OpenSSL core target ABI, paired archive variants and default static extraction: passed')


if __name__ == '__main__':
    main()
