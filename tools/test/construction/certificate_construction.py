# SPDX-License-Identifier: BSD-2-Clause
"""Real jailed certificate planning/construction from the complete package corpus."""
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


def fixture(base, construction, malformed=False):
    base.mkdir()
    root = base / 'root'; root.mkdir()
    corpus = json.loads(Path('/tests/certificate-inputs.json').read_text())
    executable = json.loads(Path('/tests/certificate-executable.json').read_text())
    rules = json.loads(Path('/tests/certificate-policy.json').read_text())['selections']
    files = {path: (Path(path).read_bytes(), 0o555) for path in executable['files']}
    for item in corpus['inputs']:
        data = (Path('/tests/certificate-payload') / item['path'].lstrip('/')).read_bytes()
        require(hashlib.sha256(data).hexdigest() == item['sha256'], 'corpus input differs')
        require(item['path'] not in files, 'certificate overlaps generator closure')
        files[item['path']] = (data, 0o444)
    chosen = next(item['path'] for item in corpus['inputs'] if item['role'] == 'trusted')
    if malformed:
        files[chosen] = (b'malformed selected certificate\n', 0o444)
    policy = {'format': 1, 'name': 'certificate-store', 'program': '/usr/sbin/certctl',
              'selections': [dict(rule, package='certificate-construction-fixture') for rule in rules],
              'files': [], 'overrides': [],
              'outputs': {'trusted_directory': '/store/trusted', 'untrusted_directory': '/store/denied',
                          'bundle': '/store/bundle.pem', 'uid': 0, 'gid': 0, 'mode': 0o444, 'flags_set': 0}}
    parents = {'/', '/store', '/store/trusted', '/store/denied'}
    for path in files:
        parents.update(str(parent) for parent in Path(path).parents)
    for path in sorted(parents - {'/'}, key=lambda p: (len(Path(p).parts), p)):
        (root / path.lstrip('/')).mkdir(mode=0o755)
    initial = {'format': 1, 'entries': {path: {'type': 'directory', 'uid': 0, 'gid': 0,
        'mode': 0o755, 'flags_set': 0, 'source': 'explicit certificate fixture layout', 'replaces': []}
        for path in parents}}
    manifest = {'name': 'certificate-construction-fixture', 'version': '1', 'files': {p: {} for p in files}}
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
    return root, inventory, initial, policy, chosen, corpus


def run(base, construction):
    jails = construction.jail_list()
    selections = []
    for label, override in [('certificate-default', False), ('certificate-override', True)]:
        case = base / label
        root, inventory, initial, policy, chosen, corpus = fixture(case, construction)
        if override:
            policy['overrides'] = [{'path': chosen, 'role': 'untrusted'}]
        report = construction.construct(root, inventory, initial, case / 'report', certificate_policy=policy)
        require(report['result'] == 'PASS' and len(report['receipts']) == 1, 'certificate construction receipt missing')
        plan, receipt = report['certificate_plan'], report['receipts'][0]
        require(len(plan['selection']) == len(corpus['inputs']), 'corpus was not completely selected')
        require(len(receipt['action']['argv']) > 128, 'large argument path not exercised')
        require(set(receipt['outputs']) == set(plan['outputs']), 'actual output set differs from plan')
        for path, record in receipt['outputs'].items():
            require(record['size'] == plan['planned_sizes'][path], 'output size differs')
            require(record['mode'] == 0o444 and record['uid'] == record['gid'] == record['flags_set'] == 0,
                    'output metadata differs from policy')
        require(receipt['inputs'][chosen]['sha256'] == hashlib.sha256((root / chosen.lstrip('/')).read_bytes()).hexdigest(),
                'selected certificate input was not bound')
        expected = subprocess.check_output(['/usr/bin/openssl', 'x509', '-in', str(root / chosen.lstrip('/'))],
                                          env={'OPENSSL_CONF': '/dev/null'})
        require((expected in (root / 'store/bundle.pem').read_bytes()) != override, 'trust-role override ignored')
        selections.append(plan['selection_sha256'])
        require(construction.jail_list() == jails, 'certificate planning/construction jail survived')
        print('CERTIFICATE_CONSTRUCTION ' + json.dumps({'case': label,
            'source_archive_sha256': corpus['archive_sha256'], 'fixture_archive_sha256': inventory['packages'][0]['archive_sha256'],
            'policy_sha256': plan['policy_sha256'], 'selection_sha256': plan['selection_sha256'],
            'plan_sha256': plan['plan_sha256'], 'receipt_sha256': receipt['sha256'],
            'inputs': len(plan['selection']), 'outputs': len(receipt['outputs']),
            'arguments': len(receipt['action']['argv'])}, sort_keys=True), flush=True)
        print('CONSTRUCTION_VM_PASS ' + label.replace('-', '_') + '_recipe', flush=True)
    require(selections[0] != selections[1], 'policy override did not change selected inputs')
    case = base / 'certificate-malformed'
    root, inventory, initial, policy, _, _ = fixture(case, construction, malformed=True)
    try:
        construction.construct(root, inventory, initial, case / 'report', certificate_policy=policy)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError('malformed selected certificate approved')
    require(not (case / 'report/generated.json').exists(), 'failed certificate plan approved')
    require(not (root / 'store/bundle.pem').exists(), 'failed planning constructed output')
    require(not list((root / 'store/trusted').iterdir()) and not list((root / 'store/denied').iterdir()),
            'failed planning changed store directories')
    require(construction.jail_list() == jails, 'failed certificate jail survived')
    print('CONSTRUCTION_VM_PASS certificate_malformed_plan_rejected', flush=True)
