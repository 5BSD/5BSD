# SPDX-License-Identifier: BSD-2-Clause
"""Revalidate retained VM evidence; this is not an authenticated release receipt."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from run import full_case_names
from run import GENERATION_TRUST_CASES, generation_trust_rejected, BOOT_CASES, boot_completed
from program_report import provider_completed


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(work, require_complete=False):
    work = Path(work).resolve(strict=True)
    raw = (work / 'result.json').read_bytes()
    result = json.loads(raw)
    require(result.get('schema') == 'org.5bsd.secureboot-test.v1', 'unknown result schema')
    require(result.get('result') == 'PASS', 'run is not terminal PASS')
    require(not require_complete or result.get('complete_suite') is True, 'full suite required')
    cases = result['cases']
    names = [case['name'] for case in cases]
    require(names and names == result['requested_cases'] and len(names) == len(set(names)),
            'missing, duplicate or reordered cases')
    require(all(isinstance(name, str) and re.fullmatch('[a-z0-9-]+', name) for name in names),
            'invalid case path')
    require(not any(name in ('storage-anchor', 'storage-mapped', 'storage-attached',
                              'storage-ordinary', 'capsule-session-storage') for name in names),
            'retired BIP storage case')
    require(all(case.get('expected') != 'storage-anchor' for case in cases),
            'retired BIP storage classification')
    require('session_storage_principals' not in result and
            'provider_lifecycle' not in result, 'retired session storage metadata')
    require(not any(name.startswith('capsule-session-policy-') for name in names)
            and all(case.get('expected') != 'session-policy' for case in cases),
            'retired session policy case')
    if require_complete:
        profile = result.get('suite_profile')
        require(isinstance(profile, dict) and set(profile) == {'integrity', 'storage'},
                'suite profile missing or malformed')
        integrity, storage = profile['integrity'], profile['storage']
        require(type(integrity) is bool and integrity == result.get('mandatory_integrity')
                and storage in ('none', 'provider'), 'invalid suite profile')
        require(names == full_case_names(integrity, storage),
                'incomplete or inconsistent suite case plan')
    checks = []

    def check(path, expected):
        require(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected),
                'invalid recorded hash')
        path = Path(path)
        with path.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(actual == expected, 'retained evidence changed: ' + str(path))
        checks.append({'path': str(path), 'sha256': actual})

    require(isinstance(result['inputs'], dict) and result['inputs'], 'missing inputs')
    for path, expected in result['inputs'].items():
        require(Path(path).is_absolute(), 'input path must be absolute')
        check(path, expected)
    for case in cases:
        require(case.get('result') == 'PASS' and case.get('explicit_evidence') is True
                and case.get('qemu_exit') == 0, 'case lacks successful explicit evidence')
        if case['name'] in GENERATION_TRUST_CASES:
            require(case['expected'] == 'loader' and
                    result.get('manifest_signer') == 'explicit-generation',
                    'generation trust case classification differs')
            require(generation_trust_rejected(
                (work / case['name'] / 'serial.log').read_text(errors='replace'),
                case['name']), 'generation trust rejection evidence missing or unsafe')
        require((case['name'] in BOOT_CASES) == (case['expected'] == 'boot'),
                'accepted boot case classification differs')
        if case['expected'] == 'boot':
            require(case.get('forced_termination') is False, 'accepted boot was terminated')
        elif case['expected'] == 'capsule':
            require(case.get('terminated_after_completion') is True and
                    case.get('terminated_after_rejection') is False,
                    'capsule completion missing')
        else:
            require(case.get('terminated_after_rejection') is True and
                    case.get('terminated_after_completion') is False,
                    'negative case lacks recorded rejection')
        directory = work / case['name']
        for key, filename in [('serial_sha256', 'serial.log'),
                ('firmware_sha256', 'firmware.log'), ('disk_sha256', 'guest.img'),
                ('firmware_variables_after_sha256', 'vars.fd')]:
            check(directory / filename, case[key])
        root = directory / 'root/boot/system.ufs'
        if case['root_image_sha256'] is None:
            require(not root.exists(), 'unexpected root image')
        else:
            check(root, case['root_image_sha256'])
        if case['expected'] == 'boot':
            require(boot_completed(
                (directory / 'serial.log').read_text(errors='replace'),
                (directory / 'firmware.log').read_text(errors='replace'),
                case.get('forced_termination'), case['qemu_exit'],
                result.get('mandatory_integrity'), case['name']),
                'accepted boot assertions missing or unsafe')
    storage = 'capsule-storage' in names or 'capsule-storage-reboot' in names
    if storage:
        require('capsule-storage' in names and 'capsule-storage-reboot' in names,
                'incomplete storage boot pair')
        a, b = (next(c for c in cases if c['name'] == name)
                for name in ('capsule-storage', 'capsule-storage-reboot'))
        restart = result.get('provider_crash', False)
        require(isinstance(restart, bool), 'invalid provider crash mode')
        for case in (a, b):
            serial = (work / case['name'] / 'serial.log').read_text(errors='replace')
            require(provider_completed(serial, case.get('storage_phase'),
                    case.get('storage_challenge'), restart),
                    'provider acceptance markers missing or invalid')
        require(result.get('storage_reboot_continuity') == 'PASS' and
                a['storage_phase'] == 'created' and b['storage_phase'] == 'recovered',
                'storage recovery missing')
        require(a['storage_challenge'] and a['storage_challenge'] == b['storage_challenge'],
                'storage challenge changed')
        for before, after in [('storage_disk_after_sha256', 'storage_disk_before_sha256'),
                ('firmware_variables_after_sha256', 'firmware_variables_before_sha256'),
                ('root_image_sha256', 'root_image_sha256')]:
            require(a[before] == b[after], 'storage boot handoff mismatch')
        require(a['storage_disk_path'] == b['storage_disk_path'], 'storage backing changed')
        check(b['storage_disk_path'], b['storage_disk_after_sha256'])
    return {'status': 'verified', 'scope': 'retained bootstrap VM evidence',
            'result_sha256': hashlib.sha256(raw).hexdigest(),
            'verifier_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'cases': names,
            'verified_files': checks, 'storage_continuity_verified': storage,
            'installed_system_qualified': False, 'mandatory_persistent_storage_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--require-complete', action='store_true')
    args = parser.parse_args()
    try:
        receipt = verify(args.work, args.require_complete)
        with (args.work / 'evidence-verification.json').open('x') as stream:
            json.dump(receipt, stream, indent=2, sort_keys=True)
            stream.write('\n')
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, 'evidence verification failed: ' + str(error) + '\n')
    print('Verified', len(receipt['cases']), 'cases and', len(receipt['verified_files']), 'files')


if __name__ == '__main__':
    main()
