# SPDX-License-Identifier: BSD-2-Clause
"""Build an unsigned EFI loader with explicit generation trust in a trusted builder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from generation_boot import certificate_pem_blocks, opened

SOURCE = Path('/usr/src')
# Protocol implemented by this maintained source/build profile, not a user claim.
ROOT_TRANSITION_VERSION = 1


def digest(path):
    with opened(path) as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build_plan(output, jobs):
    output = Path(output)
    if (not output.is_absolute() or output == Path('/usr/obj') or
            not output.is_relative_to('/usr/obj') or
            re.fullmatch(r'/[A-Za-z0-9_./-]+', str(output)) is None or
            '..' in output.parts):
        raise ValueError('loader output must be a literal path below /usr/obj')
    if type(jobs) is not int or not 1 <= jobs <= 104857:
        raise ValueError('invalid compilation CPU count')
    # A fresh isolated tree makes changes of trust/configuration independent
    # of previous builds. No ambient make environment or configuration files.
    argv = ['/usr/bin/make', '-C', str(SOURCE / 'stand'), '-j', str(jobs),
            'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
            'WITH_BEARSSL=yes', 'WITH_LOADER_VERIEXEC=yes',
            'WITH_LOADER_EFI_SECUREBOOT=yes', 'WITHOUT_LOADER_EFI_TRUST_DB=yes',
            'WITHOUT_LOADER_VERIEXEC_VECTX=yes', 'WITHOUT_FORTH=yes',
            'WITHOUT_LOADER_IA32=yes', 'VE_HASH_LIST=SHA256 SHA384',
            'VE_SIGNATURE_LIST=RSA', 'VE_SIGNATURE_EXT_LIST=sig', 'TRUST_ANCHORS=' + str(output / 'anchors.pem'),
            'efi-loader']
    environment = dict(PATH='/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin', LC_ALL='C',
                       OPENSSL_CONF='/dev/null', MAKEOBJDIRPREFIX=str(output / 'obj'))
    return argv, environment


def build(anchors, output, jobs):
    if os.uname().machine != 'amd64':
        raise ValueError('production EFI loader build currently supports native amd64')
    output = Path(output)
    argv, environment = build_plan(output, jobs)
    if output.exists() or output.is_symlink():
        raise ValueError('loader output must be new')
    resolved = output.resolve()
    if resolved != output:
        raise ValueError('loader output must use its canonical path')
    with opened(anchors) as stream:
        if os.fstat(stream.fileno()).st_size > 4 * 1048576:
            raise ValueError('public anchors exceed size limit')
        data = stream.read(4 * 1048576 + 1)
    if len(data) > 4 * 1048576:
        raise ValueError('public anchors grew past size limit')
    # Parse every certificate and never copy a private or mixed PEM input.
    blocks = certificate_pem_blocks(data)
    openssl_hash = digest('/usr/bin/openssl')
    canonical = b''.join(subprocess.run(
        ['/usr/bin/openssl', 'x509', '-inform', 'PEM', '-outform', 'PEM'],
        input=block, capture_output=True, check=True, timeout=60,
        env=environment).stdout for block in blocks)
    if digest('/usr/bin/openssl') != openssl_hash:
        raise ValueError('certificate parser changed')
    output.mkdir(parents=True, mode=0o700)
    anchor_copy = output / 'anchors.pem'
    with anchor_copy.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o444)
        stream.write(canonical)
    anchor_hash = hashlib.sha256(canonical).hexdigest()
    make_hash = digest(argv[0])
    native = list(argv)
    native[2] = str(SOURCE / 'usr.sbin/bsd-build/loader-manifest-verify')
    native_commands = [native[:-1] + [target] for target in ('obj', 'all')]
    inputs = dict(schema='org.5bsd.loader-build-inputs.v1', argv=argv,
                  environment=environment, manifest_verifier_commands=native_commands,
                  root_transition_version=ROOT_TRANSITION_VERSION, jobs=jobs, target='amd64',
                  target_arch='amd64', anchor_input_sha256=hashlib.sha256(data).hexdigest(),
                  anchor_snapshot_sha256=anchor_hash, certificate_count=len(blocks),
                  openssl_sha256=openssl_hash, make_sha256=make_hash)
    (output / 'inputs.json').write_text(json.dumps(inputs, indent=2, sort_keys=True) + '\n')
    with (output / 'build.log').open('xb') as log:
        subprocess.run(argv, env=environment, stdin=subprocess.DEVNULL,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    with (output / 'manifest-verifier-build.log').open('xb') as log:
        for command in native_commands:
            subprocess.run(command, env=environment, stdin=subprocess.DEVNULL,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
    if digest(anchor_copy) != anchor_hash or digest(argv[0]) != make_hash:
        raise ValueError('loader build input/tool changed')
    objtop = output / 'obj/usr/src/amd64.amd64'
    loader = objtop / 'stand/efi/loader_lua/loader_lua.efi'
    trust = objtop / 'stand/efi/libsaefi/ta.h'
    # Bind the generated header's PEM bytes to the selected snapshot too.
    header = trust.read_text()
    encoded = header.split('static const char ta_PEM[] = {', 1)[1].split('};', 1)[0]
    embedded = bytes(int(value, 16) for value in re.findall(r'0x([0-9a-fA-F]{2})', encoded))
    if embedded != canonical + b'\0':
        raise ValueError('generated trust header differs from selected public anchors')
    native_dir = objtop / 'usr.sbin/bsd-build/loader-manifest-verify'
    native_header = (native_dir / 'ta.h').read_text()
    encoded = native_header.split('static const char ta_PEM[] = {', 1)[1].split('};', 1)[0]
    if bytes(int(value, 16) for value in re.findall(r'0x([0-9a-fA-F]{2})', encoded)) != canonical + b'\0':
        raise ValueError('native manifest verifier trust differs from loader anchors')
    verifier = native_dir / 'loader-manifest-verify'
    with opened(loader) as stream:
        if stream.read(2) != b'MZ':
            raise ValueError('build did not produce an EFI executable')
        size = os.fstat(stream.fileno()).st_size
    report = dict(schema='org.5bsd.loader-build.v1', result='PASS',
                  scope='trusted-builder-loader-compilation',
                  root_transition_version=ROOT_TRANSITION_VERSION,
                  inputs_sha256=digest(output / 'inputs.json'),
                  loader=dict(path=str(loader), size=size, sha256=digest(loader)),
                  anchors=dict(path=str(anchor_copy), sha256=anchor_hash),
                  generated_trust_header_sha256=digest(trust),
                  manifest_verifier=dict(path=str(verifier), sha256=digest(verifier),
                      trust_header_sha256=digest(native_dir / 'ta.h')),
                  firmware_db_manifest_fallback=False, signature_verified=False,
                  firmware_verified=False, source_attestation_verified=False,
                  staging_binding_verified=False, activation_authorized=False)
    (output / 'loader-build.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--anchors', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.anchors, args.output, args.jobs), sort_keys=True))


if __name__ == '__main__':
    main()
