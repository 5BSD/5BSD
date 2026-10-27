# SPDX-License-Identifier: BSD-2-Clause
"""VM checks of real package declarations and executable bytes with explicit site inputs."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile


def require(value, message):
    if not value:
        raise AssertionError(message)


def master(uid):
    return ('root:*:0:0::0:0:Root:/root:/bin/sh\n'
            f'fixture:fixture-secret:{uid}:{uid}::0:0:Fixture:/nonexistent:/usr/sbin/nologin\n').encode()


def services(port):
    return f'fixture {port}/tcp alias\n'.encode()


def make_root(base, construction, declared, uid=42440, port=23456, malformed=False):
    base.mkdir(mode=0o755)
    root = base / 'root'; root.mkdir(mode=0o755)
    files = {path: (Path(path).read_bytes(), 0o555) for path in declared['files']}
    files.update({'/etc/master.passwd': (b'invalid account line\n' if malformed else master(uid), 0o600),
                  '/etc/services': (services(port), 0o644), '/etc/group': (b'wheel:*:0:root\n', 0o644)})
    document = json.loads(declared['declaration'])
    # These are the real package recipes. Keep fixture coverage explicit when
    # the package adds another action; do not silently execute an untested one.
    require({a['name'] for a in document['actions']} == {'account-databases', 'service-database'},
            'runtime declaration coverage changed')
    parents = {'/'}
    for path in [*files, *(p for action in document['actions'] for p in action['outputs'])]:
        parents.update(str(p) for p in Path(path).parents)
    for path in sorted(parents - {'/'}, key=lambda p: (len(Path(p).parts), p)):
        (root / path.lstrip('/')).mkdir(mode=0o755)
    initial = {'format': 1, 'entries': {p: {'type': 'directory', 'uid': 0, 'gid': 0,
        'mode': 0o755, 'flags_set': 0, 'source': 'explicit package-test layout', 'replaces': []} for p in parents}}
    manifest = {'name': 'runtime-construction-fixture', 'version': '1',
                'files': {p: {} for p in files}, 'annotations': {'5bsd.construction': declared['declaration']}}
    archive_path = base / 'fixture.pkg'
    with tarfile.open(archive_path, 'w:gz') as archive:
        data = json.dumps(manifest).encode()
        header = tarfile.TarInfo('+MANIFEST'); header.size = len(data)
        archive.addfile(header, io.BytesIO(data))
        for path, (data, mode) in files.items():
            target = root / path.lstrip('/')
            target.write_bytes(data); target.chmod(mode); os.utime(target, (1700000000, 1700000000))
            header = tarfile.TarInfo(path)
            header.size, header.mode, header.mtime = len(data), mode, 1700000000
            archive.addfile(header, io.BytesIO(data))
    inventory = construction.pkg.inventory_packages([archive_path])
    return root, inventory, initial


def check_outputs(base, root, report, uid, port):
    require(report['result'] == 'PASS' and len(report['receipts']) == 2, 'runtime receipts incomplete')
    generated = json.loads((base / 'report/generated.json').read_text())
    require(set(generated['entries']) - {p for p, m in generated['entries'].items() if m['type'] == 'directory'} >=
        {'/etc/passwd', '/etc/pwd.db', '/etc/spwd.db', '/var/db/services.db'}, 'runtime outputs missing')
    for path, mode in {'/etc/passwd': 0o644, '/etc/pwd.db': 0o644, '/etc/spwd.db': 0o600, '/var/db/services.db': 0o644}.items():
        require((root / path.lstrip('/')).stat().st_mode & 0o7777 == mode, 'runtime output mode: ' + path)
    public = (root / 'etc/passwd').read_text()
    require(f'fixture:*:{uid}:{uid}:' in public and 'fixture-secret' not in public, 'public password rendering')
    # The reader uses dbopen directly, never falls back to flat account/services
    # files, and compares by-name/by-UID and name/alias/port DB indexes.
    command = ['/tests/runtime_reader', str(root), str(uid), str(port)]
    subprocess.run(command, check=True)
    # Ancestors are deliberately traversable, so the denied secure-db read is
    # attributable to its file policy. Public database reads must succeed first.
    subprocess.run(command, check=True, user=65534, group=65534, extra_groups=[])


def run(base, construction):
    base.chmod(0o755)
    declared = json.loads(Path('/tests/runtime-declarations.json').read_text())
    before = construction.jail_list()
    for label, override in [('runtime-default', False), ('runtime-site', True)]:
        case = base / label
        root, inventory, initial = make_root(case, construction, declared)
        uid, port = (42441, 23457) if override else (42440, 23456)
        if override:
            for path, data, mode in [('/etc/master.passwd', master(uid), 0o600),
                                     ('/etc/services', services(port), 0o644)]:
                target = root / path.lstrip('/')
                target.write_bytes(data); target.chmod(mode)
                initial['entries'][path] = {'type': 'file', 'uid': 0, 'gid': 0, 'mode': mode,
                    'flags_set': 0, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                    'source': 'explicit test site input; not production authentication',
                    'replaces': [inventory['packages'][0]['archive_sha256']]}
        report = construction.construct(root, inventory, initial, case / 'report')
        check_outputs(case, root, report, uid, port)
        for receipt in report['receipts']:
            for path, observed in receipt['inputs'].items():
                require(observed['sha256'] == hashlib.sha256((root / path.lstrip('/')).read_bytes()).hexdigest(),
                        'runtime input receipt differs')
        require(construction.jail_list() == before, 'runtime jail survived')
        print('CONSTRUCTION_VM_PASS ' + label.replace('-', '_') + '_databases', flush=True)

    case = base / 'runtime-unapproved'
    root, inventory, initial = make_root(case, construction, declared)
    (root / 'etc/master.passwd').write_bytes(master(42442))
    try:
        construction.construct(root, inventory, initial, case / 'report')
    except ValueError as error:
        require('candidate does not match' in str(error), str(error))
    else:
        raise AssertionError('undeclared account input accepted')
    require(not (case / 'report').exists(), 'unapproved input executed')
    require(construction.jail_list() == before, 'unapproved-input jail survived')
    print('CONSTRUCTION_VM_PASS runtime_unapproved_input_rejected', flush=True)

    case = base / 'runtime-malformed'
    root, inventory, initial = make_root(case, construction, declared, malformed=True)
    try:
        construction.construct(root, inventory, initial, case / 'report')
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError('malformed account input accepted')
    require(not (case / 'report/generated.json').exists(), 'malformed account approval')
    require(json.loads((case / 'report/construction.json').read_text())['result'] == 'FAIL', 'missing failure receipt')
    require(construction.jail_list() == before, 'malformed-input jail survived')
    print('CONSTRUCTION_VM_PASS runtime_malformed_input_rejected', flush=True)

    case = base / 'runtime-permissions'; case.mkdir(mode=0o755)
    target = case / 'accounts'; target.mkdir(); target.chmod(0o777)
    source = target / 'master.passwd'
    source.write_bytes(master(42443)); source.chmod(0o644)
    result = subprocess.run(['/usr/sbin/pwd_mkdb', '-p', '-d', str(target), str(source)],
        user=65534, group=65534, extra_groups=[], capture_output=True, text=True)
    require(result.returncode != 0 and 'set password input permissions' in result.stderr,
            'permission failure was ignored or occurred at the wrong boundary: ' + result.stderr)
    require(source.stat().st_mode & 0o7777 == 0o644, 'foreign input permissions changed')
    require(source.read_bytes() == master(42443), 'foreign input contents changed')
    require({p.name for p in target.iterdir()} == {'master.passwd'}, 'failed generator installed outputs')
    print('CONSTRUCTION_VM_PASS runtime_permission_failure_rejected', flush=True)
