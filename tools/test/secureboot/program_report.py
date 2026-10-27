# SPDX-License-Identifier: BSD-2-Clause
"""Report observed VM behavior without turning image inclusion into a pass."""
import re

UTILITIES = {
    '/bin/sh': 'script-pipeline-and-redirection',
    '/bin/cat': 'read-back',
    '/bin/cp': 'copy-content',
    '/bin/mv': 'move-content',
    '/bin/rm': 'remove-file',
    '/bin/mkdir': 'create-directory',
    '/usr/bin/mktemp': 'private-directory',
    '/usr/bin/sort': 'sort-content',
    '/usr/sbin/pwd_mkdb': 'alternate-account-databases',
    '/usr/bin/cap_mkdb': 'text-input-database-construction',
}


def crypto_completed(text):
    marker = 'CRYPTO_BOOTSTRAP_PASS provider sign/verify, corrupt signature and control escalation denied'
    return (text.splitlines().count(marker) == 1
        and not any(error in text for error in
            ('NATIVE_SERVICE_FAIL', 'panic:', 'Fatal trap', 'lock order reversal')))


def hostid_completed(text):
    return (text.splitlines().count('RC_HOSTID_PASS startup caches reset kernel-and-file-denials') == 1
            and 'RC_HOSTID_FAIL' not in text)




def provider_exits_ok(text, restart=False):
    exits = [line for line in text.splitlines() if 'service system.Filesystem/bsdfilesystem: exited' in line]
    return not exits or (restart and len(exits) == 1 and re.search(
        r'service system.Filesystem/bsdfilesystem: exited status 75 \(pid [0-9]+\)$', exits[0]) is not None)


def provider_completed(text, phase=None, challenge=None, restart=False):
    markers = re.findall(r'^STORAGE_PROVIDER_PASS phase=(created|recovered) challenge=([0-9a-f]{32}) scopes=4\r?$', text, re.M)
    channels = [line for line in text.splitlines() if line.startswith('STORAGE_CHANNEL_AFTER_FORK')]
    workers = [line for line in text.splitlines() if line.startswith('STORAGE_WORKER_MANAGEMENT_CHECK')]
    retained_ok = workers == ['STORAGE_WORKER_MANAGEMENT_CHECK result=1'] and len(channels) == 1 and re.fullmatch(
        r'STORAGE_CHANNEL_AFTER_FORK result=-1 errno=(1|13)', channels[0]) is not None
    for stage in ('FORK', 'CLEAR'):
        prefix = 'STORAGE_RETAINED_AFTER_' + stage
        lines = [line for line in text.splitlines() if line.startswith(prefix)]
        retained_ok = retained_ok and len(lines) == 1 and re.fullmatch(
            prefix + r' read=-1 read_errno=(1|13) write=-1 write_errno=(1|13)', lines[0]) is not None
    for stage in ('FORK', 'CLEAR'):
        prefix = 'STORAGE_NAMESPACE_AFTER_' + stage
        lines = [line for line in text.splitlines() if line.startswith(prefix)]
        retained_ok = retained_ok and len(lines) == 4
        for operation in ('open', 'create', 'truncate', 'setmode'):
            retained_ok = retained_ok and sum(re.fullmatch(
                prefix + ' op=' + operation + r' result=-1 errno=(1|13)', line) is not None
                for line in lines) == 1
    released = [line for line in text.splitlines() if line.startswith('STORAGE_AFTER_RELEASE')]
    retained_ok = retained_ok and len(released) == 12
    for scope in range(4):
        for operation in ('read', 'write', 'open'):
            retained_ok = retained_ok and sum(re.fullmatch(
                f'STORAGE_AFTER_RELEASE scope={scope} op={operation} result=-1 errno=(1|13)',
                line) is not None for line in released) == 1
    restart_lines = [line for line in text.splitlines() if line.startswith('STORAGE_PROVIDER_RESTART')]
    if restart:
        starts = re.findall(r'service system.Filesystem/bsdfilesystem: started pid ([0-9]+) uid', text)
        exits = re.findall(r'service system.Filesystem/bsdfilesystem: exited status 75 \(pid ([0-9]+)\)', text)
        retained_ok = (retained_ok and len(starts) == 2 and starts[0] != starts[1]
            and exits == starts[:1] and len(restart_lines) == 1 and re.fullmatch(
                r'STORAGE_PROVIDER_RESTART recovered=1 read=-1 read_errno=(1|13) write=-1 write_errno=(1|13)',
                restart_lines[0]) is not None
            and text.count('service system.Filesystem/bsdfilesystem: application reported ready') == 2)
    else:
        retained_ok = retained_ok and not restart_lines
    return (retained_ok and provider_exits_ok(text, restart)
        and hostid_completed(text) and len(markers) == 1
        and sum(line.startswith('STORAGE_PROVIDER_PASS') for line in text.splitlines()) == 1
        and (phase is None or markers[0][0] == phase)
        and (challenge is None or markers[0][1] == challenge)
        and 'service system.Filesystem/bsdfilesystem: application reported ready' in text
        and 'service test.StorageClient/client: application reported ready' in text
        and not any(marker in text for marker in
            ('STORAGE_PROVIDER_FAIL', 'required storage-root grant unavailable',
             'storage-root grant rejected', 'service test.StorageClient/client: exited',
             'panic:', 'Fatal trap', 'lock order reversal')))


def provider_continuity(first, second):
    if (first.get('result') != 'PASS' or second.get('result') != 'PASS' or
            first.get('storage_phase') != 'created' or second.get('storage_phase') != 'recovered'):
        return False
    challenge = first.get('storage_challenge')
    if not isinstance(challenge, str) or not re.fullmatch('[0-9a-f]{32}', challenge) or second.get('storage_challenge') != challenge:
        return False
    for before, after in (('storage_disk_after_sha256', 'storage_disk_before_sha256'),
                          ('root_image_sha256', 'root_image_sha256'),
                          ('firmware_variables_after_sha256', 'firmware_variables_before_sha256')):
        value = first.get(before)
        if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) or second.get(after) != value:
            return False
    initial = first.get('storage_disk_before_sha256')
    disk = first.get('storage_disk_path')
    return (isinstance(initial, str) and re.fullmatch('[0-9a-f]{64}', initial) is not None
            and initial != first['storage_disk_after_sha256']
            and isinstance(disk, str) and bool(disk) and second.get('storage_disk_path') == disk)


def utility_results(text):
    markers = re.findall(r'^PROGRAM_PASS (\S+) (\S+)\r?$', text, re.M)
    return [{'path': path, 'status': 'tested-pass' if markers.count((path, check)) == 1
             else 'not-qualified', 'behavior': check, 'uid': 65534}
            for path, check in UTILITIES.items()]


def program_results(inventory, text, provider_restart=False):
    utilities = {row['path']: row for row in utility_results(text)}
    results = []
    for path in inventory:
        row = {'path': path, 'status': 'included-not-exercised', 'behavior': None}
        if path in utilities:
            row = utilities[path]
        elif path == '/usr/libexec/security-cap-test' and utilities['/usr/bin/cap_mkdb']['status'] == 'tested-pass':
            row.update(status='test-fixture-pass', behavior='text input provenance, reader selection and bounded names')
        elif path == '/usr/libexec/security-pwd-test' and utilities['/usr/sbin/pwd_mkdb']['status'] == 'tested-pass':
            row.update(status='test-fixture-pass', behavior='alternate database updates and malformed input rejection')
        elif path in ('/etc/rc.d/hostid', '/etc/rc.d/hostid_save', '/sbin/sysctl', '/sbin/md5', '/usr/bin/cmp') and hostid_completed(text):
            row.update(status='tested-pass', behavior='protected host identity startup, cache verification and denied root resets', uid=0)
        elif path == '/sbin/capsule' and 'CAPSULE_BOOTSTRAP_PASS' in text:
            row.update(status='tested-pass', behavior='PID 1 bootstrap and protected supervision')
        elif path == '/usr/libexec/switchboard' and 'CAPSULE_BOOTSTRAP_PASS' in text:
            row.update(status='tested-pass', behavior='rc launch, protected runtime, authenticated READY')
        elif path.endswith('/bin/BSDFilesystem'):
            if provider_completed(text, restart=provider_restart):
                row.update(status='tested-pass', behavior='signed client challenge data, release and reopen; cross-boot proof requires continuity report')
            elif 'service system.Filesystem/bsdfilesystem: application reported ready' in text:
                row.update(status='started-only', behavior='sandbox entry and READY; storage operations unqualified')
        elif (path.endswith('/bin/storage_client') or path == '/sbin/storage-probe') and provider_completed(text, restart=provider_restart):
            row.update(status='test-fixture-pass', behavior='provider storage assertions and authenticated result delivery')
        elif path == '/Capabilities/System/Crypto.cap/Units/bsdcrypto.unit/bin/BSDCrypto':
            if crypto_completed(text):
                row.update(status='tested-pass', behavior='ephemeral key generation, sign/verify, corrupt signature and control escalation rejection; root direct control open denied')
            elif 'service system.Crypto/bsdcrypto: application reported ready' in text:
                row.update(status='started-only', behavior='sandbox entry and READY; cryptographic operations unqualified')
        elif path.endswith('/bin/BSDNotify') and 'NATIVE_SOFTWARE_SERVICE_PASS' in text:
            row.update(status='tested-pass', behavior='notification round trip and denied operations')
        elif path.endswith('/bin/BSDAudit') and 'service system.Audit/bsdaudit: application reported ready' in text:
            row.update(status='started-only', behavior='sandbox entry and READY; durable audit output untested')
        elif path == '/sbin/secureboot-init' and 'CAPSULE_BOOTSTRAP_PASS' in text:
            row.update(status='test-fixture-pass', behavior='bootstrap, storage and root-attack assertions')
        elif path == '/sbin/native-service-probe' and 'NATIVE_SOFTWARE_SERVICE_PASS' in text:
            row.update(status='test-fixture-pass', behavior='software service assertions; login and sessions unqualified')
        results.append(row)
    return results


def write_program_report(destination, cases):
    lines = ['5BSD VM program evidence',
             'A pass covers only the listed behavior. This is not whole-world qualification.',
             'Results in rejected boots describe how far that boot reached.', '']
    for case in cases:
        if 'programs' not in case:
            continue
        lines.append(f"{case['name']}: {case['result']} (expected {case['expected']})")
        for row in case['programs']:
            lines.append(f"  {row['status']}: {row['path']} -- {row['behavior'] or 'no execution evidence'}")
        lines.append('')
    destination.write_text('\n'.join(lines))
