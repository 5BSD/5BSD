#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect actual amd64 make configuration for EFI/BIOS object isolation.

This is a build-graph regression, not firmware or packaged-loader qualification.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import os
import re


def probe(source, directory, options=()):
    names = ('MACHINE', 'MK_LOADER_EFI_SECUREBOOT', 'MK_LOADER_EFI_TRUST_DB', 'MK_LOADER_VERIEXEC', 'MK_BEARSSL',
             'LIBSA', 'LIBSA32', 'LIBLUA', 'LIBLUA32', 'LIBFICL', 'LIBFICL32', 'CFLAGS', 'SRCS')
    argv = ['make', '-C', str(source / directory), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null', *options]
    for name in names:
        argv += ['-V', '__probe_' + name + '=${' + name + '}']
    output = subprocess.check_output(argv, text=True)
    values = {}
    for line in output.splitlines():
        if line.startswith('__probe_'):
            key, value = line[len('__probe_'):].split('=', 1)
            if key in values:
                raise ValueError('duplicate make probe result')
            values[key] = value
    if set(values) != set(names) or values['MACHINE'] != 'amd64':
        raise ValueError('this probe requires a complete native amd64 configuration')
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, required=True)
    args = parser.parse_args()
    source = args.src.resolve(strict=True)
    variants = {}
    for directory in ('stand/efi/loader_lua', 'stand/efi/loader_ia32',
                      'stand/efi/libsaefi', 'stand/efi/libluaefi', 'stand/efi/ficlefi'):
        value = probe(source, directory); variants[directory] = value
        assert value['MK_LOADER_EFI_SECUREBOOT'] == value['MK_LOADER_VERIEXEC'] == value['MK_BEARSSL'] == 'yes'
        assert '/stand/efi/libsaefi/' in value['LIBSA']
        assert '/stand/efi/libsa32efi/' in value['LIBSA32']
        assert '-DLOADER_VERIEXEC' in value['CFLAGS'].split()
    lua = variants['stand/efi/loader_lua']
    assert '/stand/efi/libluaefi/' in lua['LIBLUA']
    assert '/stand/efi/liblua32efi/' in variants['stand/efi/loader_ia32']['LIBLUA32']
    assert '-DEFI_SECUREBOOT' in lua['CFLAGS'].split()
    for directory in ('stand/efi/loader_lua', 'stand/efi/loader_ia32'):
        value = variants[directory]
        assert '-DLOADER_VERITY_SUPPORT' in value['CFLAGS'].split()
        assert {'veritydev.c', 'verity_attach.c', 'verity_read.c', 'g_verity_verify.c',
                'verified_root.c', 'verity_commands.c'} <= set(value['SRCS'].split())
    for directory in ('stand/i386/loader_lua', 'stand/libsa', 'stand/libsa32', 'stand/liblua'):
        value = probe(source, directory); variants[directory] = value
        assert value['MK_LOADER_VERIEXEC'] == value['MK_BEARSSL'] == 'no'
        assert '/stand/efi/' not in value['LIBSA'] + value['LIBSA32']
        assert '-DLOADER_VERIEXEC' not in value['CFLAGS'].split()
    disabled = probe(source, 'stand/efi/loader_lua', ('WITHOUT_LOADER_EFI_SECUREBOOT=yes',))
    assert disabled['MK_LOADER_EFI_SECUREBOOT'] == disabled['MK_LOADER_VERIEXEC'] == disabled['MK_BEARSSL'] == 'no'
    assert '-DEFI_SECUREBOOT' not in disabled['CFLAGS'].split()
    assert '-DLOADER_VERITY_SUPPORT' not in disabled['CFLAGS'].split()
    assert 'veritydev.c' not in disabled['SRCS'].split()
    assert '/stand/efi/libsaefi/' in disabled['LIBSA']
    variants['explicitly-disabled'] = disabled
    # Probe the real make graph; contents are deliberately not a certificate
    # because this test must not claim cryptographic or firmware validation.
    rejected = subprocess.run(['make', '-C', str(source / 'stand/efi/libsaefi'),
        'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
        'WITHOUT_LOADER_EFI_TRUST_DB=yes', '-V', 'CFLAGS'], capture_output=True, text=True)
    assert rejected.returncode != 0 and 'requires explicit public TRUST_ANCHORS' in rejected.stderr
    with tempfile.TemporaryDirectory() as temporary:
        anchor = Path(temporary) / 'owner-public-anchor.crt'
        anchor.write_text('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n')
        restricted = probe(source, 'stand/efi/libsaefi',
            ('WITHOUT_LOADER_EFI_TRUST_DB=yes', 'TRUST_ANCHORS=' + str(anchor)))
        assert restricted['MK_LOADER_EFI_TRUST_DB'] == 'no'
        assert '-DVE_EFI_COMPILED_TRUST_ONLY' in restricted['CFLAGS'].split()
        payload = subprocess.check_output(['make', '-C', str(source / 'stand/efi/libsaefi'),
            'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null', 'WITHOUT_LOADER_EFI_TRUST_DB=yes',
            'TRUST_ANCHORS=' + str(anchor), '-V', '${TA_PEM_LIST}'], text=True).strip()
        assert payload == str(anchor)
        # Reuse one object directory while selecting an older replacement
        # input. Changed trust membership must not reuse the previous ta.h.
        obj = Path(temporary) / 'obj'; obj.mkdir()
        replacement = Path(temporary) / 'replacement.crt'
        replacement.write_bytes(b'-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n')
        os.utime(replacement, (1, 1))
        for selected in (anchor, replacement):
            subprocess.run(['make', '-C', str(source / 'stand/efi/libsaefi'),
                'MAKEOBJDIR=' + str(obj), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
                'WITHOUT_LOADER_EFI_TRUST_DB=yes', 'TRUST_ANCHORS=' + str(selected),
                'BUILD_UTC=1', 'ta.h'], check=True, capture_output=True)
            header = (obj / 'ta.h').read_text()
            data = header.split('static const char ta_PEM[] = {', 1)[1].split('};', 1)[0]
            decoded = bytes(int(value, 16) for value in re.findall(r'0x([0-9a-f]{2})', data))
            assert decoded == selected.read_bytes() + b'\0'
        # Framing fixtures are not valid X.509 certificates. Check that private
        # material is rejected before replacing the existing generated header.
        previous = (obj / 'ta.h').read_bytes()
        replacement.write_text(anchor.read_text() + '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n')
        rejected = subprocess.run(['make', '-C', str(source / 'stand/efi/libsaefi'),
            'MAKEOBJDIR=' + str(obj), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
            'WITHOUT_LOADER_EFI_TRUST_DB=yes', 'TRUST_ANCHORS=' + str(replacement),
            'BUILD_UTC=1', 'ta.h'], capture_output=True, text=True)
        assert rejected.returncode != 0 and 'invalid public trust input' in rejected.stderr
        assert (obj / 'ta.h').read_bytes() == previous
        variants['compiled-manifest-trust'] = restricted
    assert variants['stand/efi/libsaefi']['MK_LOADER_EFI_TRUST_DB'] == 'yes'
    assert '-DVE_EFI_COMPILED_TRUST_ONLY' not in variants['stand/efi/libsaefi']['CFLAGS'].split()
    print(json.dumps({'result': 'PASS', 'scope': 'amd64 EFI/BIOS build configuration',
        'packaged_loader_qualified': False, 'firmware_qualified': False, 'variants': variants}, sort_keys=True))


if __name__ == '__main__':
    main()
