# SPDX-License-Identifier: BSD-2-Clause
"""Actual buffer verifier and digest comparison with real BearSSL hashes.

Manifest lookup is stubbed; signature trust and boot handoff are separate gates.
"""
from pathlib import Path
import argparse
import hashlib
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
PREAMBLE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bearssl.h>
#define VE_SHA1_SUPPORT 1
#define VE_SHA384_SUPPORT 1
#define VE_SHA512_SUPPORT 1
#define VE_FINGERPRINT_OK 1
#define VE_FINGERPRINT_IGNORE 2
#define VE_FINGERPRINT_NONE -2
#define VE_FINGERPRINT_WRONG -3
#define VE_FINGERPRINT_UNKNOWN -4
static const char *entry;
static const char *fingerprint_info_lookup(int fd,const char *path) {
 assert(fd==42 && strcmp(path,"payload")==0);return entry;
}
static void ve_error_set(const char *fmt,...) { (void)fmt; }
'''
MAIN = r'''
int main(int argc,char **argv) {
 assert(argc==3);entry=strcmp(argv[1],"missing")==0 ? NULL : argv[1];
 size_t size=strlen(argv[2]);
 const char *data=strcmp(argv[2],"null")==0 ? NULL : argv[2];
 printf("%d\n",verify_buf(42,"payload",data,size));return 0;
}
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bearssl-library', type=Path, required=True)
    args = parser.parse_args()
    functions = []
    for filename, signatures in (
        ('vets.c', ('char *\nhexdigest(', 'int\nve_check_hash(')),
        ('veopen.c', ('static int\nfingerprint_hash(', 'int\nverify_buf('))):
        source = (ROOT / 'lib/libsecureboot' / filename).read_text()
        for signature in signatures:
            start = source.index(signature)
            functions.append(source[start:source.index('\n}\n', start) + 3])
    count = 0
    with tempfile.TemporaryDirectory(prefix='verify-buffer-') as directory:
        cfile, binary = Path(directory) / 'test.c', Path(directory) / 'test'
        cfile.write_text(PREAMBLE + '\n'.join(functions) + MAIN)
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(ROOT / 'contrib/bearssl/inc'), str(cfile),
                        str(args.bearssl_library.resolve(strict=True)),
                        '-o', str(binary)], check=True)
        def check(entry, payload, expected):
            nonlocal count
            result = subprocess.run([str(binary), entry, payload],
                                    check=True, capture_output=True, text=True, timeout=10)
            assert int(result.stdout.strip()) == expected, (entry, payload, result.stdout)
            count += 1
        for algorithm in ('sha1', 'sha256', 'sha384', 'sha512'):
            for payload in ('', 'abc', 'a' * 384, 'x' * 4097):
                entry = algorithm + '=' + hashlib.new(algorithm, payload.encode()).hexdigest() + '\n'
                check(entry, payload, 1)
                check(entry, payload + '!', -3)
                if payload:
                    check(entry, payload[:-1], -3)
                    check(entry, '!' + payload[1:], -3)
        check('missing', 'abc', -2)
        check('no_hash', 'abc', 2)
        check('unsupported=abc', 'abc', -4)
        check('sha256=' + hashlib.sha256(b'null').hexdigest() + '\n', 'null', -3)
    print(f'PASS: {count} native buffer/hash checks; manifest authentication not tested')

if __name__ == '__main__':
    main()
