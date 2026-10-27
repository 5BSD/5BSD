#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify an explicit selected system database in a disposable VM, not OS boot."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-vm', action='store_true', required=True)
    parser.add_argument('--work', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--filesystem', action='store_true')
    mode.add_argument('--database-only', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or subprocess.check_output(
            ['/sbin/sysctl', '-n', 'kern.vm_guest'], text=True).strip() in ('', 'none'):
        raise ValueError('requires root in an explicitly disposable VM')
    spec = importlib.util.spec_from_file_location('database_construction',
        Path(__file__).with_name('database_construction.py'))
    constructor = importlib.util.module_from_spec(spec); spec.loader.exec_module(constructor)
    settings = json.loads(Path('/tests/system-database-settings.json').read_text())
    if settings.get('filesystem_construction', False) != args.filesystem:
        raise ValueError('selected test mode differs from explicit construction settings')
    contract = constructor.payload.preflight.decode(Path('/tests/database-contract.json').read_bytes())
    inventory = constructor.payload.preflight.decode(Path('/tests/system-inventory.json').read_bytes())
    pkg, sqlite, selected, abi = constructor.prepare(Path('/tests/pkg-static'),
        Path('/usr/local/bin/sqlite3'), inventory, contract, settings['osversion'])
    identity = constructor.payload.preflight.decode(Path('/tests/pkg-identity.json').read_bytes())
    if (identity['abi'] != abi or identity['osversion'] != settings['osversion'] or
            identity['install_epoch'] != contract['install_epoch']):
        raise ValueError('explicit package identity differs from construction inputs')
    try:
        if settings.get('filesystem_construction', False):
            args.work.mkdir(mode=0o700)
            candidate = args.work / 'candidate'; candidate.mkdir(mode=0o700)
            output = args.work / 'constructed'
            command = ['/usr/local/bin/python3.12', '-I', '-S', '-B',
                str(Path(__file__).with_name('construction.py')),
                '--root', str(candidate), '--inventory', '/tests/system-inventory.json',
                '--generated', '/tests/system-layout.json', '--output', str(output),
                '--extract-tar', '/usr/bin/tar', '--timeout', str(settings['timeout']),
                '--database-pkg', str(pkg), '--database-sqlite', str(sqlite),
                '--database-contract', '/tests/database-contract.json',
                '--database-policy', '/tests/database-output-policy.json',
                '--database-osversion', str(settings['osversion'])]
            for key, option, name in (('certificate_policy', '--certificate-policy', 'system-certificate-policy.json'),
                                      ('module_policy', '--module-policy', 'system-module-policy.json'),
                                      ('library_policy', '--library-policy', 'system-library-policy.json'),
                                      ('installation_policy', '--installation-policy', 'system-installation-policy.json'),
                                      ('storage_layout_policy', '--storage-layout-policy', 'system-storage-layout-policy.json')):
                policy = Path('/tests') / name
                if settings.get(key, False):
                    command.extend([option, str(policy)])
            transport_receipt = None
            if settings.get('installation_policy', False):
                spec = importlib.util.spec_from_file_location('installation_transport',
                    Path(__file__).with_name('installation_transport.py'))
                transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)
                translated_policy, transport_receipt = transport.verify(Path('/tests'))
            subprocess.run(command, check=True)
            built = json.loads((output / 'construction.json').read_text())
            if built['result'] != 'PASS' or built['payload_extraction']['result'] != 'PASS':
                raise ValueError('selected filesystem construction failed')
            for key, receipt in (('certificate_policy', 'certificate_plan'),
                                 ('module_policy', 'module_plan'),
                                 ('library_policy', 'library_plan'),
                                 ('installation_policy', 'installation_configuration'),
                                 ('storage_layout_policy', 'storage_layout')):
                if settings.get(key, False) and not built.get(receipt):
                    raise ValueError('requested policy has no construction receipt: ' + key)
            if transport_receipt is not None:
                if built['installation_configuration']['policy_sha256'] != constructor.construction.digest(translated_policy):
                    raise ValueError('installed configuration differs from transported policy')
                constructor.construction.write_record(output / 'installation-transport.json', transport_receipt)
            report = json.loads((output / 'database/receipt.json').read_text())
            print('SYSTEM_FILESYSTEM_PASS packages=' + str(len(selected['packages'])), flush=True)
        else:
            report = constructor.construct(pkg, sqlite, selected, contract, abi,
                settings['osversion'], args.work, settings['timeout'])
    finally:
        # QEMU uses an ephemeral disk overlay. Preserve diagnostics on the
        # captured serial console before the guest shuts down, including failures.
        names = ['registration.log', 'construction.json', 'constructed/construction.json',
                 'constructed/database/registration.log', 'constructed/database/construction.json']
        names.extend(str(path.relative_to(args.work))
                     for path in sorted((args.work / 'constructed').glob('action-*.log')))
        for name in names:
            artifact = args.work / name
            if artifact.is_file():
                print('SYSTEM_DATABASE_ARTIFACT_BEGIN ' + name, flush=True)
                print(artifact.read_text(errors='replace'), flush=True)
                print('SYSTEM_DATABASE_ARTIFACT_END ' + name, flush=True)
    print(json.dumps(report, indent=2), flush=True)
    if report['result'] != 'PASS' or not report['verification']['database_profile_verified']:
        raise ValueError('selected system database did not satisfy its explicit profile')
    print('SYSTEM_DATABASE_PASS packages=' + str(len(selected['packages'])), flush=True)


if __name__ == '__main__':
    main()
