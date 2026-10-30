#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify UEFI and loader verification in disposable, networkless QEMU guests.

This qualifies boot authentication and a read-only preloaded root image.
It is not complete runtime integrity, anti-rollback, or production qualification.
Private test keys remain on the host. No host firmware variables are accessed.
"""
from assemble_capsule import assemble, write_metalog
from program_report import crypto_completed, program_results, provider_completed, provider_continuity, provider_exits_ok, hostid_completed, utility_results, write_program_report

import argparse
import importlib.util
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
import shutil
import struct
import ssl
import uuid
import subprocess
import time


GENERATION_TRUST_CASES = ('firmware-signed-manifest', 'revoked-generation-manifest')


def generation_trust_rejected(text, name):
    reasons = {'firmware-signed-manifest': 'BR_ERR_X509_NOT_TRUSTED',
               'revoked-generation-manifest': 'Certificate is on forbidden list'}
    reason = reasons.get(name)
    return (reason is not None and
        any('cannot verify:' in line and '/manifest.certs:' in line and
            reason in line for line in text.splitlines()) and
        'Secure Boot: verification failed:' in text and
        not any(marker in text for marker in ('SECUREBOOT_GUEST_STARTED',
            'SECUREBOOT_VM_PASS', 'startup: running /etc/rc',
            'Fatal trap', 'lock order reversal')))


def process_control_completed(text):
    return (text.count('PROTECTED_SPAWN_PASS') == 1 and
            text.splitlines().count('SIGIO_CLEANUP_PASS') == 1 and
            text.splitlines().count('PROTECTED_SIGIO_PASS direct and group denial; live and exited origins; ordinary and self delivery controls') == 1 and
            text.count('BIP_EXEC_GUARD_PASS before-exec-denied ordinary-exec-debug-signal-schedule') == 1 and
            'PROTECTED_SPAWN_FAIL' not in text and 'BIP_EXEC_GUARD_FAIL' not in text and
            'SIGIO_CLEANUP_FAIL' not in text and
            'PROTECTED_SIGIO_CASE_FAIL' not in text)


def rtld_completed(text):
    markers = ['authenticated-root', 'fifo', 'hints-writable',
               'hints-foreign-readonly', 'hints-fifo', 'ordinary-libmap-independent', 'ordinary-hints-independent'] + [
        f'{kind}-{i}' for i in range(3)
        for kind in ('writable', 'foreign-readonly')]
    markers += [f'object-{source}-{mode}' for source in ('approved', 'writable', 'readonly', 'fifo')
                for mode in ('name', 'path', 'fd')]
    markers += [f'ordinary-{source}-{mode}' for source in ('approved', 'writable', 'readonly')
                for mode in ('name', 'path', 'fd')]
    lines = text.splitlines()
    return (all(lines.count('RTLD_POLICY_CHECK ' + marker) == 1 for marker in markers)
        and lines.count('RTLD_POLICY_PASS') == 1
        and not any(error in text for error in
            ('RTLD_POLICY_FAIL', 'panic:', 'Fatal trap', 'lock order reversal')))




# Deliberately valid but non-granting authenticated boot policy fixtures.
CRYPTO_REJECTIONS = {
    'capsule-native-crypto-absent': '',
    'capsule-native-crypto-wrong': 'test.NotCrypto/provider',
}


def crypto_rejected(text):
    marker = 'CRYPTO_BOOTSTRAP_DENIED provider unavailable, independent provider operational, direct control denied'
    return (text.splitlines().count(marker) == 1
        and 'service system.Crypto/bsdcrypto: exited status 13 ' in text
        and not any(error in text for error in
            ('CRYPTO_BOOTSTRAP_PASS', 'NATIVE_SERVICE_FAIL', 'panic:', 'Fatal trap',
             'lock order reversal', 'service system.Crypto/bsdcrypto: application reported ready',
             "naming: 'system.Crypto' registered")))


def isolation_io_completed(text):
    return (text.splitlines().count('ISOLATION_IO_PASS inherited denial, bounded read grant, ceiling and release') == 1
            and 'ISOLATION_IO_FAIL' not in text)


def capsule_case_completed(text, name):
    return (capsule_completed(text, name == 'capsule-native')
        and (name not in CRYPTO_REJECTIONS or crypto_rejected(text)))


PROVIDER_CASES = ('capsule-storage', 'capsule-storage-reboot')


def storage_case_completed(text, name, phase, challenge, restart=False):
    return provider_completed(text, phase, challenge, restart)

# Deliberately invalid authenticated boot inputs, never host paths.
BOOT_PREPARATION_FAILURES = {
    'capsule-rc-authority-missing': 'refusing protected launch',
    'capsule-tmp-missing': 'protected temporary storage rejected:',
    'capsule-tmp-nonempty': 'protected temporary storage rejected:',
    'capsule-run-nonempty': 'bootstrap: delegate protected runtime/console: Directory not empty',
    'capsule-run-owner': 'bootstrap: delegate protected runtime/console: Invalid argument',
}

def boot_preparation_rejected(text, name):
    if name == 'capsule-rc-authority-missing':
        return ('rc bootstrap authority unavailable:' in text
            and 'refusing protected launch' in text
            and 'startup: cannot launch /etc/rc' in text
            and not any(marker in text for marker in (
                'CAPSULE_BOOTSTRAP_PASS', 'CAPSULE_TEST_COMPLETE', 'PROGRAM_PASS',
                'going to single user mode', 'Enter full pathname of shell')))
    return (BOOT_PREPARATION_FAILURES[name] in text
        and 'BIP: legacy single-user recovery denied; authenticated recovery required' in text
        and 'going to single user mode' not in text
        and 'Enter full pathname of shell' not in text
        and 'startup: running /etc/rc' not in text
        and 'capsule_proto: switchboard ready' not in text
        and 'PROGRAM_PASS' not in text)


def capsule_completed(text, native=False):
    """Require guest evidence before host cleanup; no guest shutdown claim."""
    complete = ('CAPSULE_BOOTSTRAP_PASS' in text and 'CAPSULE_BOOTSTRAP_FAIL' not in text
                and 'SYSTEM_GATE_DENY_PASS' in text and 'SYSTEM_GATE_FAIL' not in text
                and text.splitlines().count('AUDIT_CONDITION_PASS status readable, administration denied, condition unchanged') == 1
                and text.splitlines().count('AUDIT_TRAIL_DENIAL_PASS repeated refusal, pathname cleanup, file and condition unchanged') == 1
                and 'CONSOLE_OUTPUT_ONLY_PASS' in text
                and 'default service identity validated' in text
                and 'capprotect shield active' in text and 'startup: running /etc/rc' in text
                and 'capsule_proto: switchboard ready' in text
                and 'protected runtime storage ready' in text and 'PROTECTED_RUNTIME_PASS' in text
                and 'protected temporary storage ready:' in text and 'STORAGE_PASS' in text
                and 'STORAGE_FAIL' not in text
                and all(row['status'] == 'tested-pass' for row in utility_results(text))
                and 'reclaim: mkdir' not in text and 'reclaim: open' not in text
                and 'CAPSULE_ROOT_POWEROFF_DENIED' in text and 'CAPSULE_TEST_COMPLETE' in text)
    if native:
        complete = complete and crypto_completed(text) and 'NATIVE_SOFTWARE_SERVICE_PASS' in text and 'NATIVE_SERVICE_FAIL' not in text
    return complete and not any(marker in text for marker in
        ('panic:', 'Fatal trap', 'lock order reversal', 'SECUREBOOT_VM_FAIL'))


# These images are correctly signed; PID 1 must still reject invalid policy.
INVALID_CAPSULE_POLICIES = {
    'capsule-policy-duplicate': 'capsule-duplicate.ucl',
    'capsule-policy-nul-key': 'capsule-nul-key.ucl',
    'capsule-policy-unknown-field': 'capsule-unknown-field.ucl',
    'capsule-policy-wrong-type': 'capsule-wrong-type.ucl',
    'capsule-policy-include': 'capsule-include.ucl',
    'capsule-policy-missing': None,
}


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def run(*args, **kwargs):
    return subprocess.run([str(v) for v in args], check=True, **kwargs)


def certificate(keys, name):
    key, cert = keys / (name + '.key'), keys / (name + '.pem')
    run('openssl', 'req', '-new', '-x509', '-newkey', 'rsa:3072', '-noenc',
        '-keyout', key, '-out', cert, '-days', '7', '-sha256',
        '-subj', '/CN=5BSD DISPOSABLE TEST ' + name.ljust(16, '_'),
        '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign',
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    return key, cert


def generation_backend():
    spec = importlib.util.spec_from_file_location('generation_boot',
        Path(__file__).resolve().parents[2] / 'build/capimage/generation_boot.py')
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    return backend


def sign_manifest(boot, key, cert):
    # Exercise the same public-only, key-matching signing path as boot-stage.
    # Complete validation before replacing any staged signature artifacts.
    backend = generation_backend()
    openssl = shutil.which('openssl')
    if openssl is None:
        raise ValueError('openssl is required for manifest signing')
    artifacts, _ = backend.sign_loader_manifest((boot / 'manifest').read_bytes(),
        dict(key=key, certificate=cert, openssl=openssl), boot.parent)
    for name in ('manifest.sig', 'manifest.certs'):
        (boot / name).write_bytes(artifacts[name])


def damage_pe(path):
    data = bytearray(path.read_bytes())
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe+4] == b'PE\0\0'
    sections = struct.unpack_from('<H', data, pe + 6)[0]
    optional = struct.unpack_from('<H', data, pe + 20)[0]
    for n in range(sections):
        section = pe + 24 + optional + n * 40
        if data[section:section+8].rstrip(b'\0') == b'.text':
            offset = struct.unpack_from('<I', data, section + 20)[0]
            data[offset + 32] ^= 1
            path.write_bytes(data)
            return
    raise RuntimeError('PE image has no .text section')


def signature_list(kind, owner, payloads):
    assert payloads and len({len(p) for p in payloads}) == 1
    size = 16 + len(payloads[0])
    return (uuid.UUID(kind).bytes_le + struct.pack('<III', 28 + size * len(payloads), 0, size)
        + b''.join(uuid.UUID(owner).bytes_le + p for p in payloads))


def cert_der(path):
    return ssl.PEM_cert_to_DER_cert(path.read_text())


def cert_tbs(der):
    # Read the first SEQUENCE within our generated DER certificate.
    def tlv(offset):
        assert der[offset] == 0x30
        length = der[offset + 1]
        start = offset + 2
        if length & 0x80:
            count = length & 0x7f
            length = int.from_bytes(der[start:start+count], 'big')
            start += count
        assert start + length <= len(der)
        return start, start + length
    start, _ = tlv(0)
    _, end = tlv(start)
    return der[start:end]


def set_database(tool, variables, name, data, directory, log):
    path = directory / (name + '.json')
    path.write_text(json.dumps({'version': 2, 'variables': [{'name': name,
        'guid': 'd719b2cb-3d3a-4596-a3bc-dad00e67656f', 'attr': 39, 'data': data.hex()}]}))
    run(tool, '--inplace', variables, '--set-json', path, stdout=log, stderr=log)


def full_case_names(integrity, storage='none'):
    """Canonical complete plan, shared by execution and evidence checking."""
    if type(integrity) is not bool or storage not in ('none', 'provider'):
        raise ValueError('invalid suite profile')
    cases = ['approved', 'unsigned-loader', 'altered-loader', 'untrusted-loader',
        'revoked-loader', 'missing-manifest', 'altered-manifest', 'untrusted-manifest',
        'altered-kernel', 'altered-config', 'unsigned-config', 'unsigned-esp-env',
        'no-hash-kernel', 'boot-options', 'unsigned-kernel', 'altered-module',
        'verification-off', 'second-db-cert', 'second-dbx-cert', 'second-dbx-hash', 'missing-policy', 'altered-policy', 'invalid-policy', 'returned-policy',
        'missing-config', 'missing-defaults', 'missing-module', 'nextboot-config', 'console-input', 'altered-root-image', 'unsigned-root-image', 'missing-root-image', 'unsigned-hardlink']
    if integrity:
        cases += ['mutable-root', 'root-override', 'firmware-disabled', 'capsule-bootstrap', 'capsule-isolation-off', 'capsule-native', 'capsule-native-tampered', *CRYPTO_REJECTIONS, *INVALID_CAPSULE_POLICIES, *BOOT_PREPARATION_FAILURES]
    if storage != 'none':
        cases += ['capsule-storage']
    cases = [boot for case_name in cases for boot in
             ([case_name, 'capsule-storage-reboot'] if case_name == 'capsule-storage' else [case_name])]
    return cases


BOOT_CASES = frozenset(('approved', 'boot-options', 'second-db-cert',
    'unsigned-config', 'unsigned-esp-env', 'nextboot-config', 'console-input',
    'root-override'))


def boot_completed(text, fw, forced, returncode, integrity, name):
    """Recheck accepted bootstrap execution; this is not installed-system proof."""
    if type(integrity) is not bool or name not in BOOT_CASES:
        return False
    evidence = ('SECUREBOOT_VM_PASS' in text and 'SECUREBOOT_VM_FAIL' not in text
        and 'RUNTIME_PROCESS_PASS' in text and 'RUNTIME_PROCESS_FAIL' not in text
        and 'RUNTIME_PROCESS_NAMESPACE_PASS' in text
        and 'RUNTIME_PROCESS_NAMESPACE_SHARING_PASS' in text
        and 'RUNTIME_PROCESS_NAMESPACE_FAIL' not in text
        and 'INVOCATION_PASS' in text and text.splitlines().count('INVOCATION_CURRENT_PASS') == 1
        and 'INVOCATION_FAIL' not in text
        and 'LEASE_PASS' in text and 'LEASE_FAIL' not in text
        and text.count('SECUREBOOT_DENIED ') == 20 and text.count('AUTHROOT_CHECK ') == 8
        and 'ResetType Shutdown' in fw
        and not forced and returncode == 0)
    evidence = evidence and ('SYSTEM_INTEGRITY_PASS' in text and 'SYSTEM_INTEGRITY_FAIL' not in text
        and rtld_completed(text)
        and text.splitlines().count('BIP_HOSTNAME_PASS root change and restore; nonroot denied') == 1
        and 'INIT_LIFETIME_PASS' in text
        and 'SYSTEM_GATE_PASS' in text and 'SYSTEM_GATE_AUTHORITY_PASS' in text
        and 'SYSTEM_ACCOUNTING_PASS' in text
        and text.splitlines().count('SYSTEM_ENTROPY_CONTROL_PASS ordinary harvest write; hardware sources preserved; unprivileged and seed-bypass writes denied') == 1
        and 'SYSTEM_GATE_REAUTHORIZE_PASS' in text
        and 'SYSTEM_GATE_FAIL' not in text
        and isolation_io_completed(text)
        and process_control_completed(text)
        if integrity else 'SYSTEM_INTEGRITY_ABSENT' in text)
    if name == 'boot-options':
        evidence = evidence and '"file BOOTX64.EFI"' in text
    return (evidence and not any(marker in text for marker in
        ('panic:', 'Fatal trap', 'lock order reversal')) and
        ('SYSTEM_INTEGRITY_ABSENT' not in text if integrity else
         'SYSTEM_INTEGRITY_PASS' not in text))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--objtop', type=Path, default=Path('/usr/obj/usr/src/amd64.amd64'))
    p.add_argument('--loader', type=Path, help='EFI loader from an independently configured object tree')
    p.add_argument('--generation-key', type=Path, help='host-only disposable generation signing key')
    p.add_argument('--generation-certificate', type=Path, help='public generation certificate compiled into the supplied loader')
    p.add_argument('--kernel', default='GENERIC-NODEBUG')
    p.add_argument('--startup-policy', type=Path, default=Path('/usr/src/stand/lua/secureboot.lua'))
    p.add_argument('--qemu', default='/usr/local/bin/qemu-system-x86_64')
    p.add_argument('--qemu-data', type=Path, default=Path('/usr/local/share/qemu'))
    p.add_argument('--vars-tool', required=True)
    p.add_argument('--capsign', type=Path, help='native host signer for the populated service fixture')
    p.add_argument('--storage-disk', type=Path, help='explicit exported test-pool disk image; copied privately')
    p.add_argument('--filesystem-policy', type=Path, help='explicit BSDFilesystem policy; selects the actual provider case')
    p.add_argument('--provider-crash', action='store_true', help='explicit controlled-crash provider fixture; requires the provider case')
    p.add_argument('--filesystem-policy-destination', default='/Capabilities/Config/bsdfilesystem.ucl',
                   help='policy destination inside the authenticated fixture; must match the Capsule assignment')
    p.add_argument('--storage-policy', type=Path, help='explicit Capsule storage policy authenticated in the fixture root')
    p.add_argument('--timeout', type=int, default=180)
    p.add_argument('--case', action='append', choices=['capsule-storage', 'approved', 'unsigned-loader', 'altered-loader',
        'untrusted-loader', 'revoked-loader', 'missing-manifest', 'altered-manifest',
        'untrusted-manifest', *GENERATION_TRUST_CASES, 'altered-kernel', 'altered-config', 'unsigned-config',
        'unsigned-esp-env', 'no-hash-kernel', 'boot-options', 'unsigned-kernel', 'altered-module',
        'verification-off', 'second-db-cert', 'second-dbx-cert', 'second-dbx-hash', 'missing-policy', 'altered-policy', 'invalid-policy', 'returned-policy',
        'missing-config', 'missing-defaults', 'missing-module', 'nextboot-config', 'console-input', 'altered-root-image', 'unsigned-root-image', 'missing-root-image', 'unsigned-hardlink', 'mutable-root', 'root-override', 'firmware-disabled', 'capsule-bootstrap', 'capsule-isolation-off', 'capsule-native', 'capsule-native-tampered', *CRYPTO_REJECTIONS, *INVALID_CAPSULE_POLICIES, *BOOT_PREPARATION_FAILURES])
    a = p.parse_args()
    if (a.generation_key is None) != (a.generation_certificate is None):
        p.error('generation signing requires both key and certificate')
    if a.generation_key is not None:
        if not a.case or any(c in ('second-db-cert', 'second-dbx-cert', 'second-dbx-hash') for c in a.case):
            p.error('generation signing requires explicit cases independent of secondary firmware db trust')
    if a.generation_key is None and a.case and any(c in GENERATION_TRUST_CASES for c in a.case):
        p.error('generation trust cases require explicit generation key and certificate')
    provider_requested = (a.case is not None and any(c in PROVIDER_CASES for c in a.case)) or (a.case is None and a.filesystem_policy is not None)
    if a.provider_crash and not provider_requested:
        p.error('--provider-crash requires capsule-storage and its policy inputs')
    storage_requested = provider_requested
    if provider_requested != (a.filesystem_policy is not None):
        p.error('capsule-storage requires --filesystem-policy; unused filesystem policy is rejected')
    if provider_requested:
        for name in ('etc/hostid', 'etc/machine-id'):
            identity_file = a.root / name
            if not identity_file.is_file() or identity_file.is_symlink():
                p.error('provider qualification requires a regular staged ' + name)
    if (a.storage_disk is None) != (a.storage_policy is None):
        p.error('--storage-disk and --storage-policy are required together')
    if storage_requested and a.storage_disk is None:
        p.error('capsule-storage requires explicit --storage-disk and --storage-policy')
    if a.storage_disk is not None and not storage_requested:
        p.error('storage inputs supplied without a storage case')
    if a.timeout < 15:
        p.error('timeout must be at least 15 seconds')
    root, obj, work = a.root.resolve(), a.objtop.resolve(), a.work.resolve()
    if not work.is_relative_to('/usr/obj/usr/src') or work == Path('/usr/obj/usr/src'):
        p.error('VM staging must be a new directory below /usr/obj/usr/src')
    if not obj.is_relative_to('/usr/obj/usr/src'):
        p.error('objects must use the standard /usr/obj/usr/src tree')
    if any(c in str(work) + str(a.qemu_data) for c in ',\n\r'):
        p.error('QEMU paths must not contain commas or newlines')
    kernel = obj / 'sys' / a.kernel / 'kernel'
    loader = a.loader.resolve() if a.loader else obj / 'stand/efi/loader_lua/loader_lua.efi'
    fixture = obj / 'tools/test/secureboot/secureboot_init'
    code = a.qemu_data / 'edk2-x86_64-secure-code.fd'
    template = a.qemu_data / 'edk2-i386-vars.fd'
    module = obj / 'sys' / a.kernel / 'modules/usr/src/sys/modules/geom/geom_nop/geom_nop.ko'
    runtime_module = module.parent.parent / 'geom_gate/geom_gate.ko'
    inputs = [kernel, loader, fixture, module, runtime_module, code, template, a.startup_policy.resolve(), Path(__file__).resolve(),
        Path(__file__).with_name("assemble_capsule.py").resolve(),
        Path(__file__).with_name("secureboot_init.c").resolve(),
        Path(__file__).resolve().parents[3] / "sys/sys/cap_authority.h",
        Path(__file__).resolve().parents[3] / "sys/sys/proc.h",
        Path(__file__).resolve().parents[3] / "sys/kern/kern_exit.c",
        Path(__file__).resolve().parents[3] / "sys/kern/kern_descrip.c",
        Path(__file__).resolve().parents[3] / "sys/kern/kern_sig.c",
        Path(__file__).resolve().parents[3] / "sys/sys/sigio.h",
        Path(__file__).resolve().parents[3] / "sys/security/mac/mac_process.c",
        Path(__file__).resolve().parents[3] / "sys/dev/mac_capability/mac_capability_capprotect.c",
        Path(__file__).resolve().parents[3] / "sys/dev/random/random_harvestq.c",
        Path(__file__).resolve().parents[3] / "sys/dev/random/random_infra.c",
        Path(__file__).resolve().parents[3] / "sys/kern/kern_fork.c",
        Path(__file__).resolve().parents[3] / "sys/kern/vfs_syscalls.c",
        Path(__file__).resolve().parents[3] / "sys/sys/filedesc.h",
        Path(__file__).resolve().parents[3] / "sys/dev/mac_capability/mac_capability_authority.c",
        Path(__file__).resolve().parents[3] / "sys/dev/mac_capability/mac_capability_process.c",
        Path(__file__).with_name("invocation_test.c").resolve(),
        Path(__file__).with_name("invocation_test.h").resolve(),
        Path(__file__).with_name("lease_test.c").resolve(),
        Path(__file__).with_name("lease_test.h").resolve(),
        Path(__file__).with_name("storage_test.c").resolve(),
        Path(__file__).with_name("storage_test.h").resolve(),
        Path(__file__).with_name("capsule_policy_test.c").resolve(),
        Path(__file__).with_name("capsule_policy_test.h").resolve(),
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/naming.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/BSDNotify/bsdnotify.c",
        Path(__file__).resolve().parents[3] / "lib/libcapsulert/storage_namespace.c",
        Path(__file__).resolve().parents[3] / "lib/libcapsulert/storage_namespace.h",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/authority.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/storage_namespace_admission.h",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/authority.h",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/switchboard.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/svc_proto.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/capsule_client.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/capsule/capsule_proto.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/capsule/req_validate.h",
        Path(__file__).resolve().parents[3] / "usr.sbin/capsule/config.h",
        Path(__file__).resolve().parents[3] / "usr.sbin/capsule/capsule.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/capsule/main.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/capsule/Makefile",
        Path(__file__).resolve().parents[3] / "usr.sbin/capsule/protected_storage.h",
        Path(__file__).resolve().parents[3] / "usr.sbin/capsule/protected_runtime.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/capsule/protected_runtime.h",
        Path(__file__).resolve().parents[3] / "lib/libcapsulert/capsule_svc_proto.h",
        Path(__file__).resolve().parents[3] / "lib/libcapsulert/switchboard_svc_proto.h",
        Path(__file__).resolve().parents[3] / "lib/libservice/libservice.c",
        Path(__file__).resolve().parents[3] / "lib/libservice/libservice.h",
        Path(__file__).resolve().parents[3] / "lib/libservice/service_client.c",
        Path(__file__).resolve().parents[3] / "lib/libservice/lookup_identity.h",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/domain.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/on_demand.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/session.h",

        Path(__file__).resolve().parents[3] / "tools/test/secureboot/build-bootstrap.sh",
        Path(__file__).resolve().parents[3] / "lib/libsecureboot/readfile.c",
        Path(__file__).resolve().parents[3] / "lib/libsecureboot/veopen.c",
        Path(__file__).resolve().parents[3] / "lib/libsecureboot/vectx.c",
        Path(__file__).resolve().parents[3] / "lib/libsecureboot/verify_file.c",
        Path(__file__).resolve().parents[3] / "lib/libsecureboot/h/libsecureboot.h",
        Path(__file__).resolve().parents[3] / "lib/libsecureboot/vets.c",

        Path(__file__).with_name("system_gate_test.c").resolve(),
        Path(__file__).with_name("sigio_cleanup_test.c").resolve(),
        Path(__file__).with_name("sigio_cleanup_test.h").resolve(),
        Path(__file__).with_name("system_gate_test.h").resolve(),
        Path(__file__).resolve().parents[3] / "lib/libcapsulert/filesystem_policy.c",
        Path(__file__).resolve().parents[3] / "lib/libcapsulert/filesystem_policy.h",
        Path(__file__).resolve().parents[3] / "usr.sbin/BSDFilesystem/bsdfilesystem.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/BSDFilesystem/bsdfilesystem.h",
        Path(__file__).resolve().parents[3] / "usr.sbin/BSDFilesystem/request.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/capsule/config.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/boot_authority.c",
        Path(__file__).resolve().parents[3] / "usr.sbin/switchboard/authority_policy.c",
        Path(__file__).resolve().parents[3] / "lib/libcapsulert/claim_parse.c",
        Path(__file__).with_name("program_report.py").resolve()]
    if storage_requested:
        if not a.storage_disk.is_file() or a.storage_disk.stat().st_size < 128 * 1024 * 1024:
            p.error('storage disk must be a regular virtual disk image of at least 128 MiB')
        if not a.storage_policy.is_file() or a.storage_policy.stat().st_size > 1024 * 1024:
            p.error('storage policy must be a regular file no larger than 1 MiB')
        storage_module = obj / 'sys' / a.kernel / 'modules/usr/src/sys/modules/zfs/zfs.ko'
        if provider_requested:
            if not a.filesystem_policy.is_file() or a.filesystem_policy.stat().st_size > 1024 * 1024:
                p.error('filesystem policy must be a regular file no larger than 1 MiB')
            inputs.append(a.filesystem_policy.resolve())
        inputs += [a.storage_disk.resolve(), a.storage_policy.resolve(), storage_module,
            Path(__file__).resolve().parents[3] / 'usr.sbin/capsule/protected_storage.c']
        inputs += [Path(__file__).resolve().parents[3] / name for name in (
            'sys/security/mac/mac_framework.h', 'sys/security/mac/mac_policy.h',
            'sys/sys/zfshandle.h',
            'sys/security/mac/mac_system.c', 'sys/security/mac/mac_vfs.c',
            'sys/security/mac/mac_trace_args.h',
            'sys/kern/vfs_lookup.c', 'sys/sys/namei.h',
            'sys/fs/nfs/nfs_var.h',
            'sys/fs/nfsserver/nfs_nfsdport.c',
            'sys/fs/nfsserver/nfs_nfsdserv.c',
            'sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c',
            'sys/contrib/openzfs/module/os/freebsd/zfs/zfs_vfsops.c',
            'sys/contrib/openzfs/include/sys/dmu_recv.h',
            'sys/contrib/openzfs/include/sys/zfs_ioctl_impl.h',
            'sys/contrib/openzfs/module/zfs/dmu_recv.c',
            'sys/contrib/openzfs/module/zfs/dsl_destroy.c',
            'sys/contrib/openzfs/module/zfs/dsl_dir.c',
            'sys/contrib/openzfs/module/zfs/dsl_dataset.c',
            'sys/contrib/openzfs/module/zfs/zfs_ioctl.c',
            'tools/test/system-tracing/mac-hook-arguments.json')]
    # Bind the ordinary-state classification and its unchanged privilege checks
    # to this run alongside the actual kernel and fixture binaries.
    inputs += [Path(__file__).resolve().parents[3] / name for name in (
        'sys/sys/sysctl.h', 'sys/kern/kern_sysctl.c',
        'sys/dev/mac_capability/mac_capability_system.c',
        'sys/security/mac_system_integrity/mac_system_integrity.c',
        'sys/opencrypto/crypto.c', 'sys/kern/kern_devctl.c',
        'sys/kern/kern_proc.c',
        'sys/netinet/tcp_input.c', 'sys/netinet/tcp_subr.c',
        'sys/netinet/tcp_timer.c', 'sys/netinet/udp_usrreq.c',
        'sys/netinet6/in6_proto.c', 'sys/netinet/ip_icmp.c',
        'sys/netinet/ip_input.c', 'sys/netinet/ip_options.c',
        'sys/netinet/if_ether.c')]
    for source in inputs + [root / 'boot/defaults/loader.conf', root / 'boot/kernel/kernel']:
        if not source.is_file():
            p.error('missing input: ' + str(source))
    kernel_config = subprocess.check_output(['config', '-x', str(kernel)], text=True)
    integrity = bool(re.search(r'^options\s+MAC_SYSTEM_INTEGRITY\b', kernel_config, re.M))
    if integrity:
        p.error('BIP kernel qualification has been retired; use the independent firmware suite')
    if storage_requested and not integrity:
        p.error('capsule-storage requires the built-in BIP kernel')
    if integrity and (provider_requested or a.case is None or any(c.startswith('capsule-native') for c in a.case)):
        if a.capsign is None or not a.capsign.is_file():
            p.error('native service case requires --capsign with a built host signer')
        a.capsign = a.capsign.resolve()
    if a.case and not integrity and any(c in a.case for c in ['mutable-root', 'root-override', 'firmware-disabled', 'capsule-bootstrap', 'capsule-isolation-off', 'capsule-native', 'capsule-native-tampered', *CRYPTO_REJECTIONS, *INVALID_CAPSULE_POLICIES, *BOOT_PREPARATION_FAILURES]):
        p.error('integrity cases require a MAC_SYSTEM_INTEGRITY kernel')
    if digest(kernel) != digest(root / 'boot/kernel/kernel'):
        p.error('staged and object kernels differ')
    if 'statically linked' not in subprocess.check_output(['file', str(fixture)], text=True):
        p.error('guest fixture must be static')
    qemu_executable = Path(shutil.which(a.qemu) or a.qemu).resolve(strict=True)
    inputs.append(qemu_executable)
    qemu_version = subprocess.check_output([a.qemu, '--version'], text=True).strip()
    run(a.vars_tool, '--help', stdout=subprocess.DEVNULL)
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    log = (work / 'build.log').open('w')
    keys = work / 'private-test-keys'
    keys.mkdir(mode=0o700)
    credentials = {name: certificate(keys, name) for name in ['PK', 'KEK', 'db', 'stranger', 'secondary']}
    generation_credentials = ((a.generation_key, a.generation_certificate)
        if a.generation_key is not None else credentials['db'])
    guid = '236a3af5-e3d3-4786-afdf-24f0a155029a'
    enrolled = work / 'enrolled.fd'
    run(a.vars_tool, '--input', template, '--output', enrolled,
        '--set-pk', guid, credentials['PK'][1], '--add-kek', guid, credentials['KEK'][1],
        '--add-db', guid, credentials['db'][1], '--add-dbx-cert', guid, credentials['stranger'][1],
        '--secure-boot', stdout=log, stderr=log)
    set_database(a.vars_tool, enrolled, 'db', b''.join(signature_list('a5c059a1-94e4-4aa7-87b5-ab155c2bf072', guid,
        [cert_der(credentials[name][1])]) for name in ['db', 'secondary']), work, log)
    baseline = work / 'baseline'
    baseline.mkdir()
    # These are private builder copies; guest modes come from its METALOG.
    # copyfile avoids inheriting read-only host modes before fixture edits.
    shutil.copytree(root / 'boot', baseline / 'boot', copy_function=shutil.copyfile, ignore=shutil.ignore_patterns(
        'kernel', 'modules', 'dtb', 'firmware', 'loader.conf', 'loader.conf.local',
        'loader.conf.d', 'zfs', 'manifest', 'manifest.sig', 'manifest.certs'))
    shutil.copyfile(root / 'boot/defaults/loader.conf', baseline / 'boot/defaults/loader.conf')
    for name in ['boot/kernel', 'dev', 'sbin']:
        (baseline / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(kernel, baseline / 'boot/kernel/kernel')
    system = work / 'system-root'
    (system / 'sbin').mkdir(parents=True)
    (system / 'dev').mkdir()
    (system / 'scratch').mkdir()
    (system / 'tmp').mkdir()
    (system / 'policy-test').mkdir()
    (system / 'Capabilities/Config/switchboard').mkdir(parents=True)
    (system / 'capsule-policy.ucl').write_text('pidfile="/selected/pid";')
    (system / 'storage-policy.ucl').write_text('pool=changed;\n')
    shutil.copyfile(fixture, system / 'sbin/secureboot-init')
    (system / 'sbin/secureboot-init').chmod(0o555)
    shutil.copyfile(runtime_module, system / 'sbin/geom_gate.ko')
    (system / 'sbin/geom_gate.ko').chmod(0o444)
    system_metalog = work / 'system.METALOG'
    system_metalog.write_text('#mtree 2.0\n. type=dir uid=0 gid=0 mode=0755\n'
        './scratch type=dir uid=0 gid=0 mode=0755\n'
        './tmp type=dir uid=0 gid=0 mode=1777\n'
        './policy-test type=dir uid=0 gid=0 mode=0755\n'
        './Capabilities type=dir uid=0 gid=0 mode=0755\n'
        './Capabilities/Config type=dir uid=0 gid=0 mode=0755\n'
        './Capabilities/Config/switchboard type=dir uid=0 gid=0 mode=0755\n'
        './capsule-policy.ucl type=file uid=0 gid=0 mode=0444\n'
        './storage-policy.ucl type=file uid=0 gid=0 mode=0444\n'
        './dev type=dir uid=0 gid=0 mode=0755\n./sbin type=dir uid=0 gid=0 mode=0755\n'
        './sbin/secureboot-init type=file uid=0 gid=0 mode=0555\n'
        './sbin/geom_gate.ko type=file uid=0 gid=0 mode=0555\n')
    if integrity:
        credential_fixture = Path(__file__).with_name('policy') / 'protected-passwd'
        inputs.append(credential_fixture.resolve())
        inputs += [Path(__file__).resolve().parents[3] / name for name in (
            'lib/libpam/modules/pam_unix/protected_passwd.c',
            'contrib/openpam/lib/libpam/openpam_check_owner_perms.c',
            'lib/libpam/modules/pam_unix/protected_passwd.h')]
        for name, mode in [('credentials.secret', 0o600), ('credentials.public', 0o644)]:
            shutil.copyfile(credential_fixture, system / name)
            (system / name).chmod(mode)
        (system / 'credentials.alias').symlink_to('credentials.secret')
        write_metalog(system, system_metalog)
    run('makefs', '-t', 'ffs', '-s', '32m', '-F', system_metalog, '-o', 'version=2',
        baseline / 'boot/system.ufs', system, stdout=log, stderr=log)
    shutil.copyfile(module, baseline / 'boot/kernel/geom_nop.ko')
    # The small fixture has an explicit module closure. Production defaults
    # request many modules which are intentionally not in this test image.
    disabled = ''.join(name + '="NO"\n' for name in re.findall(
        r'^([A-Za-z0-9_]+_load)=', (baseline / 'boot/defaults/loader.conf').read_text(), re.M))
    (baseline / 'boot/loader.conf').write_text(disabled + 'console="comconsole"\nautoboot_delay="0"\n'
        'geom_nop_load="YES"\ncapability_plane="NO"\ninit_path="/sbin/secureboot-init"\n'
        'system_root_load="YES"\nsystem_root_type="md_image_ro"\n'
        'system_root_name="/boot/system.ufs"\n'
        'vfs.root.mountfrom="ufs:/dev/md0"\nvfs.root.mountfrom.options="ro"\n')
    inventories = {}
    capsule_image = work / 'capsule.ufs'
    native_image = work / 'native.ufs'
    tampered_image = work / 'native-tampered.ufs'
    for native, names, destination in [
            (False, ['capsule-bootstrap', 'capsule-isolation-off', *INVALID_CAPSULE_POLICIES, *BOOT_PREPARATION_FAILURES], capsule_image),
            (True, ['capsule-native', 'capsule-native-tampered', *CRYPTO_REJECTIONS], native_image)]:
        if not integrity or (a.case is not None and not any(c in a.case for c in names)):
            continue
        capsule_system = work / ('native-system' if native else 'capsule-system')
        shutil.copytree(system, capsule_system)
        programs = ['/sbin/secureboot-init']
        inputs.extend(assemble(root, obj, capsule_system, native=native, capsign=a.capsign, log=log, programs=programs))
        inventories['native' if native else 'capsule'] = sorted(set(programs))
        capsule_metalog = work / ('native.METALOG' if native else 'capsule.METALOG')
        write_metalog(capsule_system, capsule_metalog)
        run('makefs', '-t', 'ffs', '-s', '64m' if native else '32m', '-F', capsule_metalog,
            '-o', 'version=2', destination, capsule_system, stdout=log, stderr=log)
    storage_challenge = secrets.token_hex(16) if provider_requested else None
    if provider_requested:
        challenge_input = work / 'storage-challenge'
        challenge_input.write_text(storage_challenge)
        inputs.append(challenge_input)
    provider_image = work / 'storage-provider.ufs'
    if provider_requested:
        provider_system = work / 'storage-provider-system'
        if a.provider_crash:
            inputs.extend([Path(__file__).with_name('provider-crash') / name
                           for name in ('Makefile', 'crash.c')])
            inputs.append(Path(__file__).resolve().parents[3] / 'usr.sbin/BSDFilesystem/Makefile.common')
        shutil.copytree(system, provider_system)
        programs = ['/sbin/secureboot-init']
        inputs.extend(assemble(root, obj, provider_system, capsign=a.capsign,
            log=log, programs=programs, storage_policy=a.storage_policy,
            filesystem_policy=a.filesystem_policy, storage_challenge=storage_challenge,
            filesystem_policy_destination=a.filesystem_policy_destination,
            provider_crash=a.provider_crash))
        inventories['storage-provider'] = sorted(set(programs))
        provider_metalog = work / 'storage-provider.METALOG'
        write_metalog(provider_system, provider_metalog)
        run('makefs', '-t', 'ffs', '-s', '64m', '-F', provider_metalog,
            '-o', 'version=2', provider_image, provider_system, stdout=log, stderr=log)
    invalid_storage_images = {}
    for name in BOOT_PREPARATION_FAILURES:
        if not integrity or (a.case is not None and name not in a.case):
            continue
        invalid_system = work / (name + '-system')
        shutil.copytree(work / 'capsule-system', invalid_system)
        if name == 'capsule-rc-authority-missing':
            (invalid_system / 'Capabilities/Config/switchboard/boot-authority.ucl').unlink()
        elif name == 'capsule-tmp-missing':
            (invalid_system / 'tmp').rmdir()
        elif name.endswith('nonempty'):
            target = 'Capabilities/Run' if name.startswith('capsule-run-') else 'tmp'
            (invalid_system / target / 'retained-data').write_text('must not hide existing data\n')
        metalog = work / (name + '.METALOG')
        write_metalog(invalid_system, metalog)
        if name == 'capsule-run-owner':
            # NO_ROOT metadata chooses the guest owner; no host chown needed.
            entries = metalog.read_text().splitlines()
            selected = [i for i, line in enumerate(entries)
                        if line.startswith('./Capabilities/Run type=dir uid=0 ')]
            if len(selected) != 1:
                raise ValueError('runtime fixture mountpoint missing or ambiguous')
            i = selected[0]
            entries[i] = entries[i].replace('uid=0 ', 'uid=65534 ', 1)
            metalog.write_text('\n'.join(entries) + '\n')
        destination = work / (name + '.ufs')
        run('makefs', '-t', 'ffs', '-s', '32m', '-F', metalog,
            '-o', 'version=2', destination, invalid_system, stdout=log, stderr=log)
        invalid_storage_images[name] = destination
    invalid_capsule_images = {}
    for name, filename in INVALID_CAPSULE_POLICIES.items():
        if not integrity or (a.case is not None and name not in a.case):
            continue
        invalid_system = work / (name + '-system')
        shutil.copytree(work / 'capsule-system', invalid_system)
        if filename is None:
            (invalid_system / 'boot/capsule.conf').unlink()
        else:
            if name == 'capsule-policy-include':
                # The include target exists and is valid: missing-file or
                # recursive-include errors must not satisfy this test.
                shutil.copyfile(invalid_system / 'boot/capsule.conf',
                    invalid_system / 'etc/capsule-included.conf')
            policy_input = Path(__file__).with_name('policy') / filename
            shutil.copyfile(policy_input, invalid_system / 'boot/capsule.conf')
            inputs.append(policy_input)
        invalid_metalog = work / (name + '.METALOG')
        write_metalog(invalid_system, invalid_metalog)
        destination = work / (name + '.ufs')
        run('makefs', '-t', 'ffs', '-s', '32m', '-F', invalid_metalog,
            '-o', 'version=2', destination, invalid_system, stdout=log, stderr=log)
        invalid_capsule_images[name] = destination
    crypto_rejection_images = {}
    for name, recipient in CRYPTO_REJECTIONS.items():
        if not integrity or (a.case is not None and name not in a.case):
            continue
        rejection_system = work / (name + '-system')
        shutil.copytree(work / 'native-system', rejection_system)
        policy = rejection_system / 'boot/capsule.conf'
        changed, count = re.subn(r'^crypto_recipient\s*=\s*"[^"\n]*";\s*$',
            'crypto_recipient = "' + recipient + '";', policy.read_text(), flags=re.M)
        if count != 1:
            raise ValueError('Crypto rejection fixture requires one explicit recipient')
        policy.write_text(changed)
        rc = rejection_system / 'etc/rc'
        original = rc.read_text()
        if original.count('/sbin/native-service-probe || exit 1') != 1:
            raise ValueError('Crypto rejection fixture requires the native probe')
        rc.write_text(original.replace('/sbin/native-service-probe || exit 1',
            '/sbin/native-service-probe --crypto-unavailable || exit 1'))
        metalog = work / (name + '.METALOG')
        write_metalog(rejection_system, metalog)
        destination = work / (name + '.ufs')
        run('makefs', '-t', 'ffs', '-s', '64m', '-F', metalog,
            '-o', 'version=2', destination, rejection_system, stdout=log, stderr=log)
        crypto_rejection_images[name] = destination
    if integrity and (a.case is None or 'capsule-native-tampered' in a.case):
        tampered_system = work / 'native-tampered-system'
        shutil.copytree(work / 'native-system', tampered_system)
        program = tampered_system / 'Capabilities/System/Notify.cap/Units/bsdnotify.unit/bin/BSDNotify'
        with program.open('r+b') as f:
            f.seek(-1, 2)
            original = f.read(1)
            f.seek(-1, 2)
            f.write(bytes([original[0] ^ 1]))
        tampered_metalog = work / 'native-tampered.METALOG'
        write_metalog(tampered_system, tampered_metalog)
        run('makefs', '-t', 'ffs', '-s', '64m', '-F', tampered_metalog,
            '-o', 'version=2', tampered_image, tampered_system, stdout=log, stderr=log)
    boot = baseline / 'boot'
    shutil.copyfile(a.startup_policy, boot / 'lua/secureboot.lua')
    # This runner explicitly qualifies the preload mechanism, not disk-image boot.
    (boot / 'boot-policy.lua').write_bytes(generation_backend().render_boot_policy(
        {'version': 1, 'mode': 'preloaded'}))
    inputs.append(Path(__file__).resolve().parents[2] / 'build/capimage/generation_boot.py')
    (boot / 'manifest').write_text(''.join(str(f.relative_to(boot)) + ' sha256=' + digest(f) + '\n'
        for f in sorted(boot.rglob('*')) if f.is_file()))
    sign_manifest(boot, *generation_credentials)
    signed = work / 'approved.efi'
    run('uefisign', '-k', credentials['db'][0], '-c', credentials['db'][1], '-o', signed, loader,
        stdout=log, stderr=log)
    storage_profile = 'provider' if provider_requested else 'none'
    cases = (full_case_names(integrity, storage_profile) if a.case is None else
        [boot for name in a.case for boot in
         ([name, 'capsule-storage-reboot'] if name == 'capsule-storage' else [name])])
    report = {'result': 'RUNNING', 'requested_cases': cases, 'complete_suite': a.case is None, 'schema': 'org.5bsd.secureboot-test.v1', 'scope': 'UEFI, required startup policy, kernel and preloaded root image authentication',
        'suite_profile': {'integrity': integrity, 'storage': storage_profile},
        'startup_policy': 'required signed Lua entrypoint; explicit required inputs; no interactive fallback',
        'authenticated_root': 'SHA256 of complete UFS image including contents and metadata',
        'root_image_management': 'read-only preload; forced detach and resize denied',
        'process_debug_isolation': 'authority-bearing fork families separated on exec; explicit debug grants remain independent',
        'runtime_root_protection': ('mandatory bootstrap MAC; production generation and delegation qualification incomplete' if integrity else 'incomplete; mandatory bootstrap MAC absent'),
        'capsule_bootstrap': any(c.startswith('capsule-') for c in cases),
        'program_inventory': inventories,
        'program_qualification': 'per-case observed operations; inclusion and readiness are not functional qualification',
        'writable_storage': ('fixture layout only: 64 MiB public nosuid/noexec /tmp; separate claimed /Capabilities/Run; persistent data not qualified' if any(c.startswith('capsule-') for c in cases) else 'fixture layout only: 64 MiB mode-1777 tmpfs /tmp for mechanism tests; persistent data not qualified' if integrity else 'not-tested'),
        'boot_storage': 'actual Capsule/SwitchBoard grant and BSDFilesystem challenge data across two boots; see continuity result' if provider_requested else 'not-tested',
        'capsule_shutdown': 'unauthorized guest poweroff denied; host cleanup after full evidence; authorized guest shutdown not qualified',
        'capsule_scope': 'actual PID 1, manager and authenticated READY with selected fixture catalogue and bounded rc probe; installed-world services not qualified',
        'session_authorization': 'protected broker leases and management roles; test-only enrolled issuer; human authentication not qualified',
        'session_lifetime': 'kernel lease; both provider endpoints, queued data, blocked receive, descriptor duplication and issuer/owner/deadline revocation',
        'invocation_binding': 'process identity and exec nonce; fork/exec reuse and revoked software denied; no human authentication',
        'native_services': 'signed BSDAudit, BSDNotify and BSDCrypto; scoped rc client, invocation-bound SwitchBoard control and explicit Crypto boot grant' if any(c.startswith('capsule-native') for c in cases) else 'not-tested',
        'mandatory_integrity': integrity, 'protected_spawn': integrity, 'kernel_config': kernel_config, 'rollback_protection': 'not-tested',
        'manifest_signer': 'explicit-generation' if a.generation_key is not None else 'firmware-db',
        'manifest_certificate_sha256': digest(boot / 'manifest.certs'),
        'private_keys': 'disposable host-only', 'inputs': {str(f): digest(f) for f in inputs},
        'qemu_version': qemu_version, 'qemu_executable': str(qemu_executable),
        'host_loader_environment': {key: os.environ[key] for key in
            ('LD_LIBMAP', 'LD_LIBRARY_PATH', 'LD_PRELOAD') if key in os.environ},
        'firmware_smm': True, 'network': False, 'cases': []}
    if provider_requested:
        report['filesystem_policy_destination'] = a.filesystem_policy_destination
        report['provider_crash'] = a.provider_crash
    (work / 'inputs.json').write_text(json.dumps(report, indent=2) + '\n')
    for name in cases:
        case = work / name
        case.mkdir()
        storage_phase = 'recovered' if name == 'capsule-storage-reboot' else 'created'
        if name == 'capsule-storage-reboot' and report['cases'][-1]['result'] != 'PASS':
            report['cases'].append({'name': name, 'result': 'FAIL', 'reason': 'first storage boot did not pass'})
            continue
        stage, esp = case / 'root', case / 'esp'
        shutil.copytree(baseline, stage)
        (esp / 'EFI/BOOT').mkdir(parents=True)
        executable = esp / 'EFI/BOOT/BOOTX64.EFI'
        shutil.copyfile(signed, executable)
        variables = case / 'vars.fd'
        shutil.copyfile(work / 'capsule-storage/vars.fd' if name == 'capsule-storage-reboot' else enrolled, variables)
        boot = stage / 'boot'
        if name in PROVIDER_CASES:
            shutil.copyfile(provider_image, boot / 'system.ufs')
            shutil.copyfile(storage_module, boot / 'kernel/zfs.ko')
            config = boot / 'loader.conf'
            config_text = config.read_text()
            if name in PROVIDER_CASES:
                config_text = config_text.replace('capability_plane="NO"', 'capability_plane="YES"').replace('/sbin/secureboot-init', '/sbin/capsule')
            config.write_text(config_text + 'zfs_load="YES"\n')
            manifest = boot / 'manifest'
            manifest.write_text(''.join(str(f.relative_to(boot)) + ' sha256=' + digest(f) + '\n'
                for f in sorted(boot.rglob('*')) if f.is_file() and f.name not in ('manifest', 'manifest.sig', 'manifest.certs')))
            sign_manifest(boot, *generation_credentials)
            storage_disk = work / 'capsule-storage/storage.img' if name == 'capsule-storage-reboot' else case / 'storage.img'
            if name != 'capsule-storage-reboot':
                shutil.copyfile(a.storage_disk, storage_disk)
            storage_before = digest(storage_disk)
            expected_storage = (report['cases'][-1]['storage_disk_after_sha256']
                if name == 'capsule-storage-reboot' else report['inputs'][str(a.storage_disk.resolve())])
            if storage_before != expected_storage:
                raise RuntimeError('storage disk changed outside the expected boot handoff')
        elif name in ['capsule-bootstrap', 'capsule-isolation-off', 'capsule-native', 'capsule-native-tampered', *CRYPTO_REJECTIONS, *INVALID_CAPSULE_POLICIES, *BOOT_PREPARATION_FAILURES]:
            shutil.copyfile(crypto_rejection_images[name] if name in crypto_rejection_images else
                invalid_capsule_images[name] if name in invalid_capsule_images else
                invalid_storage_images[name] if name in invalid_storage_images else
                tampered_image if name == 'capsule-native-tampered' else
                native_image if name == 'capsule-native' else capsule_image, boot / 'system.ufs')
            config = boot / 'loader.conf'
            config.write_text(config.read_text().replace('capability_plane="NO"', 'capability_plane="YES"')
                .replace('/sbin/secureboot-init', '/sbin/capsule'))
            if name == 'capsule-isolation-off':
                config.write_text(config.read_text() + 'kern.mac_capability_isolation.enforce="0"\n')
            manifest = boot / 'manifest'
            manifest.write_text(''.join(line.split(' ', 1)[0] + ' sha256=' +
                digest(boot / line.split(' ', 1)[0]) + '\n'
                for line in manifest.read_text().splitlines()))
            sign_manifest(boot, *generation_credentials)
        elif name in ['mutable-root', 'root-override']:
            config = boot / 'loader.conf'
            text = config.read_text()
            if name == 'mutable-root':
                text = text.replace('md_image_ro', 'md_image')
            else:
                text = text.replace('ufs:/dev/md0', 'ufs:/dev/vtbd0p2')
            config.write_text(text)
            manifest = boot / 'manifest'
            manifest.write_text(''.join('loader.conf sha256=' + digest(config) + '\n'
                if line.startswith('loader.conf ') else line
                for line in manifest.read_text().splitlines(True)))
            sign_manifest(boot, *generation_credentials)
        elif name == 'firmware-disabled':
            run(a.vars_tool, '--inplace', variables, '--delete', 'PK',
                stdout=log, stderr=log)
        elif name == 'unsigned-loader':
            shutil.copyfile(loader, executable)
        elif name == 'altered-loader':
            damage_pe(executable)
        elif name == 'untrusted-loader':
            run('uefisign', '-k', credentials['PK'][0], '-c', credentials['PK'][1],
                '-o', case / 'untrusted.efi', loader, stdout=log, stderr=log)
            shutil.copyfile(case / 'untrusted.efi', executable)
        elif name == 'revoked-loader':
            run(a.vars_tool, '--inplace', variables, '--add-dbx-cert', guid, credentials['db'][1],
                stdout=log, stderr=log)
        elif name == 'missing-manifest':
            (boot / 'manifest').unlink()
        elif name == 'altered-manifest':
            with (boot / 'manifest').open('a') as f:
                f.write('# altered\n')
        elif name == 'untrusted-manifest':
            sign_manifest(boot, *credentials['PK'])
        elif name == 'firmware-signed-manifest':
            # The EFI signer is trusted by firmware but is not a manifest anchor.
            sign_manifest(boot, *credentials['db'])
        elif name == 'revoked-generation-manifest':
            # Revoke the already staged public signer, leaving EFI db trust intact.
            run(a.vars_tool, '--inplace', variables, '--add-dbx-cert', guid,
                baseline / 'boot/manifest.certs', stdout=log, stderr=log)
        elif name == 'altered-kernel':
            with (boot / 'kernel/kernel').open('r+b') as f:
                f.seek(8192)
                byte = f.read(1)
                f.seek(8192)
                f.write(bytes([byte[0] ^ 1]))
        elif name == 'altered-config':
            with (boot / 'loader.conf').open('a') as f:
                f.write('init_path="/untrusted-init"\n')
        elif name == 'unsigned-config':
            (boot / 'loader.conf.local').write_text('init_path="/untrusted-init"\n')
        elif name == 'unsigned-esp-env':
            (esp / 'EFI/5BSD').mkdir(parents=True)
            (esp / 'EFI/5BSD/loader.env').write_text('init_path=/untrusted-init\n')
        elif name == 'no-hash-kernel':
            manifest = boot / 'manifest'
            manifest.write_text(''.join('kernel/kernel no_hash\n' if line.startswith('kernel/kernel ') else line
                for line in manifest.read_text().splitlines(True)))
            sign_manifest(boot, *generation_credentials)
        elif name == 'unsigned-kernel':
            manifest = boot / 'manifest'
            manifest.write_text(''.join(line for line in manifest.read_text().splitlines(True)
                if not line.startswith('kernel/kernel ')))
            sign_manifest(boot, *generation_credentials)
        elif name == 'altered-module':
            with (boot / 'kernel/geom_nop.ko').open('ab') as f:
                f.write(b'altered')
        elif name == 'verification-off':
            # A signed compatibility directive must not disable firmware policy.
            directive = boot / 'loader.ve.off'
            directive.write_text('# compatibility directive\n')
            config = boot / 'loader.conf'
            with config.open('a') as f:
                f.write('exec="read-conf /boot/loader.ve.off"\n')
            manifest = boot / 'manifest'
            manifest.write_text(''.join('loader.conf sha256=' + digest(config) + '\n'
                if line.startswith('loader.conf ') else line
                for line in manifest.read_text().splitlines(True))
                + 'loader.ve.off sha256=' + digest(directive) + '\n')
            sign_manifest(boot, *generation_credentials)
            (boot / 'untrusted.conf').write_text('init_path="/untrusted-init"\n')
            # Reading the signed compatibility directive must not disable the
            # check on a later explicitly requested, unsigned input.
            config.write_text(config.read_text() + 'exec="read-conf /boot/untrusted.conf"\n')
            manifest.write_text(''.join('loader.conf sha256=' + digest(config) + '\n'
                if line.startswith('loader.conf ') else line
                for line in manifest.read_text().splitlines(True)))
            sign_manifest(boot, *generation_credentials)
        elif name in ['second-db-cert', 'second-dbx-cert', 'second-dbx-hash']:
            sign_manifest(boot, *credentials['secondary'])
            if name == 'second-dbx-cert':
                data = b''.join(signature_list('a5c059a1-94e4-4aa7-87b5-ab155c2bf072', guid,
                    [cert_der(credentials[n][1])]) for n in ['stranger', 'secondary'])
                set_database(a.vars_tool, variables, 'dbx', data, case, log)
            elif name == 'second-dbx-hash':
                data = signature_list('3bd2a492-96c0-4079-b420-fcf98ef103ed', guid,
                    [hashlib.sha256(cert_tbs(cert_der(credentials[n][1]))).digest() + bytes(16)
                        for n in ['stranger', 'secondary']])
                set_database(a.vars_tool, variables, 'dbx', data, case, log)
        elif name == 'boot-options':
            run(a.vars_tool, '--inplace', variables, '--append-boot-filepath',
                '/EFI/BOOT/BOOTX64.EFI init_path=/untrusted-init', stdout=log, stderr=log)
        elif name in ['missing-policy', 'missing-config', 'missing-defaults', 'missing-module']:
            target = {'missing-policy': 'lua/secureboot.lua', 'missing-config': 'loader.conf',
                'missing-defaults': 'defaults/loader.conf', 'missing-module': 'kernel/geom_nop.ko'}[name]
            (boot / target).unlink()
        elif name in ['altered-policy', 'invalid-policy', 'returned-policy']:
            policy = boot / 'lua/secureboot.lua'
            policy.write_text('this is invalid lua\n' if name != 'returned-policy' else 'return\n')
            if name != 'altered-policy':
                manifest = boot / 'manifest'
                manifest.write_text(''.join('lua/secureboot.lua sha256=' + digest(policy) + '\n'
                    if line.startswith('lua/secureboot.lua ') else line
                    for line in manifest.read_text().splitlines(True)))
                sign_manifest(boot, *generation_credentials)
        elif name == 'unsigned-hardlink':
            # The same inode is first read under an approved name. A later
            # alias without a manifest entry must not inherit verification.
            os.link(boot / 'lua/cli.lua', boot / 'unlisted.lua')
            policy = boot / 'lua/secureboot.lua'
            policy.write_text('require("cli")\ndofile("/boot/unlisted.lua")\n' + policy.read_text())
            manifest = boot / 'manifest'
            manifest.write_text(''.join('lua/secureboot.lua sha256=' + digest(policy) + '\n'
                if line.startswith('lua/secureboot.lua ') else line
                for line in manifest.read_text().splitlines(True)))
            sign_manifest(boot, *generation_credentials)
        elif name == 'altered-root-image':
            # Alter filesystem metadata; the whole-image hash must reject it
            # before the kernel mounts or interprets the filesystem.
            with (boot / 'system.ufs').open('r+b') as f:
                f.seek(65536)
                byte = f.read(1)
                f.seek(65536)
                f.write(bytes([byte[0] ^ 1]))
        elif name == 'missing-root-image':
            (boot / 'system.ufs').unlink()
        elif name == 'unsigned-root-image':
            manifest = boot / 'manifest'
            manifest.write_text(''.join(line for line in manifest.read_text().splitlines(True)
                if not line.startswith('system.ufs ')))
            sign_manifest(boot, *generation_credentials)
        elif name == 'nextboot-config':
            (boot / 'nextboot.conf').write_text('nextboot_enable="YES"\ninit_path="/untrusted-init"\n')
        metalog = case / 'METALOG'
        entries = ['#mtree 2.0', '. type=dir uid=0 gid=0 mode=0755']
        for f in sorted(stage.rglob('*')):
            entry = './' + str(f.relative_to(stage))
            if f.is_symlink():
                entry += ' type=link uid=0 gid=0 link=' + os.readlink(f)
            elif f.is_dir():
                entry += ' type=dir uid=0 gid=0 mode=0755'
            else:
                entry += ' type=file uid=0 gid=0 mode=0555'
            entries.append(entry)
        metalog.write_text('\n'.join(entries) + '\n')
        run('makefs', '-t', 'ffs', '-s', '128m', '-F', metalog, '-o', 'version=2',
            case / 'root.ufs', stage, stdout=log, stderr=log)
        run('makefs', '-t', 'msdos', '-s', '32m', '-o', 'fat_type=16', case / 'esp.fat', esp,
            stdout=log, stderr=log)
        run('mkimg', '-s', 'gpt', '-f', 'raw', '-p', 'efi:=' + str(case / 'esp.fat'),
            '-p', 'freebsd-ufs:=' + str(case / 'root.ufs'), '-o', case / 'guest.img', stdout=log, stderr=log)
        serial, debug = case / 'serial.log', case / 'firmware.log'
        cmd = [a.qemu, '-L', str(a.qemu_data), '-accel', 'tcg,thread=multi', '-machine', 'q35,smm=on',
            '-global', 'driver=cfi.pflash01,property=secure,value=on', '-cpu', 'max', '-m', '1024', '-smp', '4',
            '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={code}',
            '-drive', f'if=pflash,format=raw,unit=1,file={variables}',
            '-drive', f'if=virtio,format=raw,snapshot=on,file={case}/guest.img',
            '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(serial),
            '-debugcon', 'file:' + str(debug), '-global', 'isa-debugcon.iobase=0x402', '-no-reboot']
        if name in PROVIDER_CASES:
            cmd[cmd.index('-m') + 1] = '2048'
            cmd += ['-drive', f'if=virtio,format=raw,file={storage_disk}']
        expected = 'capsule-policy' if name in invalid_capsule_images else 'boot-preparation' if name in invalid_storage_images else 'catalogue' if name == 'capsule-native-tampered' else 'capsule' if name in ['capsule-storage', 'capsule-storage-reboot', 'capsule-bootstrap', 'capsule-isolation-off', 'capsule-native', 'capsule-native-tampered', *CRYPTO_REJECTIONS, *INVALID_CAPSULE_POLICIES, *BOOT_PREPARATION_FAILURES] else 'boot' if name in BOOT_CASES else 'kernel' if name in ['mutable-root', 'firmware-disabled'] else 'firmware' if name.endswith('loader') else 'loader'
        kernel_error = ('System integrity: immutable preloaded md0 root required' if name == 'mutable-root'
            else 'System integrity: enforcing Secure Boot required')
        catalogue_error = "bundle_registry: SYSTEM bundle '/Capabilities/System/Notify.cap' invalid: invalid or untrusted artifact signature"
        firmware_variables_before = digest(variables)
        deadline = time.monotonic() + a.timeout
        forced, evidence = False, False
        terminated_after_completion = False
        policy_errors = ['Secure Boot: verification failed:', 'Secure Boot: startup policy failed',
            'Secure Boot: startup policy returned without booting']
        if name == 'console-input':
            # Feed keystrokes throughout startup, including escape and commands.
            # The authenticated policy must never enter an interactive interpreter.
            cmd[cmd.index('-serial') + 1] = 'stdio'
        with (case / 'qemu.log').open('w') as errors, serial.open('a') as serial_output:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if name == 'console-input' else subprocess.DEVNULL,
                stdout=serial_output if name == 'console-input' else errors, stderr=errors)
            try:
                while proc.poll() is None and time.monotonic() < deadline:
                    text = serial.read_text(errors='replace') if serial.exists() else ''
                    fw = debug.read_text(errors='replace') if debug.exists() else ''
                    if expected == 'firmware' and ('Security Violation' in text or 'Security Violation' in fw or ("The image doesn't pass verification:" in fw and 'BOOTX64.EFI' in fw and ': Access Denied' in text)):
                        evidence = True
                        break
                    if expected == 'kernel' and kernel_error in text:
                        evidence = True
                        break
                    if expected == 'capsule-policy' and 'Capsule: configuration rejected: /boot/capsule.conf' in text:
                        evidence = True
                        break
                    if expected == 'boot-preparation' and boot_preparation_rejected(text, name):
                        evidence = True
                        break
                    if expected == 'catalogue' and catalogue_error in text and 'bundle registry init failed' in text:
                        evidence = True
                        break
                    if expected == 'loader' and (generation_trust_rejected(text, name) if name in GENERATION_TRUST_CASES else any(marker in text for marker in policy_errors)):
                        evidence = True
                        break
                    if (name in PROVIDER_CASES and ('service test.StorageClient/client: exited' in text or not provider_exits_ok(text, a.provider_crash))) or 'RC_HOSTID_FAIL' in text or 'STORAGE_PROVIDER_FAIL' in text or 'BOOT_STORAGE_FAIL' in text or (expected in ('boot', 'capsule') and 'panic:' in text) or 'SYSTEM_GATE_FAIL' in text or 'STORAGE_FAIL' in text or 'STORAGE_POLICY_FAIL' in text or 'LEASE_FAIL' in text or 'INVOCATION_FAIL' in text or 'NATIVE_SERVICE_FAIL' in text or 'CAPSULE_BOOTSTRAP_FAIL' in text or 'SECUREBOOT_VM_FAIL' in text or 'Fatal trap' in text or 'mountroot>' in text or (expected == 'boot' and any(marker in text for marker in policy_errors)):
                        break
                    if expected == 'capsule' and capsule_case_completed(text, name) and (name not in PROVIDER_CASES or storage_case_completed(text, name, storage_phase, storage_challenge, a.provider_crash)):
                        terminated_after_completion = True
                        break
                    if name == 'console-input' and 'Verified /boot/lua/secureboot.lua' in text:
                        try:
                            proc.stdin.write(b'\x1bset init_path=/untrusted-init\rboot -s\r')
                            proc.stdin.flush()
                        except BrokenPipeError:
                            pass
                    time.sleep(0.25)
            finally:
                if proc.poll() is None:
                    forced = True
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
        text = serial.read_text(errors='replace') if serial.exists() else ''
        fw = debug.read_text(errors='replace') if debug.exists() else ''
        if expected == 'boot':
            evidence = boot_completed(text, fw, forced, proc.returncode, integrity, name)
        elif expected == 'capsule':
            evidence = (capsule_case_completed(text, name)
                and (name not in PROVIDER_CASES or storage_case_completed(text, name, storage_phase, storage_challenge, a.provider_crash))
                and terminated_after_completion and proc.returncode == 0)
        elif expected == 'capsule-policy':
            evidence = ('Capsule: configuration rejected: /boot/capsule.conf' in text
                and 'startup: running /etc/rc' not in text
                and 'capsule_proto: switchboard ready' not in text
                and 'going to single user mode' not in text
                and 'Enter full pathname of shell' not in text)
        elif expected == 'boot-preparation':
            evidence = boot_preparation_rejected(text, name)
        elif expected == 'catalogue':
            evidence = (catalogue_error in text and 'bundle registry init failed' in text
                and 'startup: running /etc/rc' not in text
                and 'capsule_proto: switchboard ready' not in text
                and 'NATIVE_SOFTWARE_SERVICE_PASS' not in text)
        elif expected == 'kernel':
            evidence = kernel_error in text and 'SECUREBOOT_GUEST_STARTED' not in text
        elif name in GENERATION_TRUST_CASES:
            evidence = generation_trust_rejected(text, name)
        else:
            evidence = ('Security Violation' in text or 'Security Violation' in fw or ("The image doesn't pass verification:" in fw and 'BOOTX64.EFI' in fw and ': Access Denied' in text)) if expected == 'firmware' else any(marker in text for marker in policy_errors)
            evidence = evidence and 'SECUREBOOT_GUEST_STARTED' not in text
        # Policy rejection may deliberately panic before userspace. Accepted
        # guests must never pass after a runtime panic, even if pass markers
        # were printed earlier and firmware subsequently powers off.
        passed = (evidence and not any(x in text for x in ['Fatal trap', 'lock order reversal'])
            and (expected not in ('boot', 'capsule') or 'panic:' not in text))
        record = {'name': name, 'result': 'PASS' if passed else 'FAIL', 'expected': expected,
            'explicit_evidence': evidence, 'forced_termination': forced, 'terminated_after_rejection': forced and evidence and expected not in ('boot', 'capsule'),
            'terminated_after_completion': terminated_after_completion,
            'qemu_exit': proc.returncode, 'command': cmd, 'serial_sha256': digest(serial),
            'firmware_sha256': digest(debug), 'disk_sha256': digest(case / 'guest.img'),
            'firmware_variables_before_sha256': firmware_variables_before,
            'firmware_variables_after_sha256': digest(variables),
            'root_image_sha256': digest(boot / 'system.ufs') if (boot / 'system.ufs').exists() else None}
        if name in PROVIDER_CASES:
            record['storage_disk_before_sha256'] = storage_before
            record['storage_disk_after_sha256'] = digest(storage_disk)
            record['storage_policy_sha256'] = digest(provider_system / 'boot/capsule.conf')
        if name in PROVIDER_CASES:
            record['storage_phase'] = storage_phase
            record['storage_challenge'] = storage_challenge
            record['storage_disk_path'] = str(storage_disk)
        if name.startswith('capsule-'):
            inventory = inventories['storage-provider' if name in PROVIDER_CASES else 'native' if name.startswith('capsule-native') else 'capsule']
            record['programs'] = program_results(inventory, text, provider_restart=a.provider_crash)
        report['cases'].append(record)
        write_program_report(work / 'programs.txt', report['cases'])
        report['result'] = 'RUNNING'
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(name + ': ' + record['result'], flush=True)
        if not passed:
            print('\n'.join(text.splitlines()[-35:]), flush=True)
    log.close()
    if any(digest(f) != report['inputs'][str(f)] for f in inputs):
        raise RuntimeError('qualification input changed while running')
    continuity = True
    if provider_requested:
        first = next(x for x in report['cases'] if x['name'] == 'capsule-storage')
        second = next(x for x in report['cases'] if x['name'] == 'capsule-storage-reboot')
        continuity = provider_continuity(first, second)
        report['storage_reboot_continuity'] = 'PASS' if continuity else 'FAIL'
    report['result'] = 'PASS' if continuity and all(x['result'] == 'PASS' for x in report['cases']) else 'FAIL'
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(work)
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
