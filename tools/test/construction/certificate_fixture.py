# SPDX-License-Identifier: BSD-2-Clause
"""Exercise explicit certificate selection from an inventoried package corpus.

This is utility qualification, not a production construction policy compiler or
an authenticated generation. The runner supplies every selected payload hash.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def require(value, message):
    if not value:
        raise AssertionError(message)


def run():
    require(os.geteuid() != 0, 'certificate corpus tests require an unprivileged user')
    declared = json.loads(Path('/tests/certificate-inputs.json').read_text())
    environment = {'PATH': '/bin:/usr/bin:/usr/sbin', 'LC_ALL': 'C',
                   'OPENSSL_CONF': '/dev/null'}
    with tempfile.TemporaryDirectory(prefix='certificate-corpus-') as temporary:
        base = Path(temporary)
        root = base / 'root'; root.mkdir()
        selected = []
        for item in declared['inputs']:
            source = Path('/tests/certificate-payload') / item['path'].lstrip('/')
            data = source.read_bytes()
            require(hashlib.sha256(data).hexdigest() == item['sha256'], 'certificate payload changed')
            path = root / item['path'].lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            selected.append((item['role'], path))
        require(selected and any(role == 'trusted' for role, _ in selected), 'empty trusted corpus')

        def invoke(selection, *options):
            args = ['/usr/sbin/certctl', '-D', str(root), '-E']
            for role, path in selection:
                args.extend(['-T' if role == 'trusted' else '-X', str(path)])
            args.extend([*options, 'rehash'])
            return subprocess.run(args, capture_output=True, env=environment, timeout=30, umask=0o022)

        def store():
            return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode & 0o7777)
                    for p in (root / 'etc/ssl').rglob('*') if p.is_file()}

        def planned_build(selection, label):
            inputs_by_path = {item['path']: item for item in declared['inputs']}
            resolved = []
            overrides = []
            for role, path in selection:
                name = '/' + str(path.relative_to(root))
                item = inputs_by_path[name]
                require(hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'],
                        'selected certificate differs from inventoried input')
                resolved.append({'path': name, 'role': role, 'sha256': item['sha256']})
                if role != item['role']:
                    overrides.append({'path': name, 'role': role})
            selection_hash = hashlib.sha256(json.dumps(resolved, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest()
            before = store()
            plan = base / (label + '-plan.mtree')
            result = invoke(selection, '-n', '-U', '-M', str(plan))
            require(result.returncode == 0, result.stderr.decode())
            require(store() == before, 'dry run changed the certificate store')
            actual = base / (label + '-actual.mtree')
            result = invoke(selection, '-U', '-M', str(actual))
            require(result.returncode == 0, result.stderr.decode())
            require(plan.read_bytes() == actual.read_bytes(), 'planned and actual metadata differ')
            planned_paths = set()
            for line in plan.read_text().splitlines():
                name, *fields = line.split()
                require(name.startswith('./') and '..' not in Path(name).parts, 'invalid plan pathname')
                attributes = dict(field.split('=', 1) for field in fields)
                require(set(attributes) == {'type', 'uname', 'gname', 'mode', 'size'}, 'unexpected plan attributes')
                require(attributes['type'] == 'file', 'unexpected plan object type')
                path = root / name[2:]
                require(int(attributes['size']) == path.stat().st_size, 'planned size differs')
                require(int(attributes['mode'], 8) == path.stat().st_mode & 0o7777, 'planned mode differs')
                require(name[2:] not in planned_paths, 'duplicate planned output')
                planned_paths.add(name[2:])
            require(set(store()) == planned_paths, 'unplanned certificate output')
            print('CERTIFICATE_CORPUS_PLAN ' + json.dumps({
                'case': label, 'archive_sha256': declared['archive_sha256'],
                'source_policy_sha256': declared['policy_sha256'],
                'selection_sha256': selection_hash, 'overrides': overrides,
                'input_count': len(selection),
                'output_count': len(planned_paths),
                'plan_sha256': hashlib.sha256(plan.read_bytes()).hexdigest()}, sort_keys=True), flush=True)

        planned_build(selected, 'package')
        print('CONSTRUCTION_VM_PASS packaged_certificate_plan', flush=True)
        before = store()
        legacy = root / 'etc/ssl/blacklisted'; legacy.mkdir()
        # These objects are outside the output directories but would influence
        # directory-discovery mode. Explicit selection must ignore all of them.
        (legacy / 'bad.pem').write_text('malformed unselected certificate')
        chosen = next(path for role, path in selected if role == 'trusted')
        (chosen.parent / 'unselected.pem').write_text('malformed unselected certificate')
        result = invoke(selected)
        require(result.returncode == 0, result.stderr.decode())
        require({k: v for k, v in store().items() if not k.startswith('etc/ssl/blacklisted/')} == before,
                'ambient certificate input altered explicit selection')
        (legacy / 'bad.pem').unlink(); legacy.rmdir()
        print('CONSTRUCTION_VM_PASS packaged_certificate_ambient_ignored', flush=True)

        certificate = subprocess.check_output(['/usr/bin/openssl', 'x509', '-in', str(chosen)], env=environment)
        require(certificate in (root / 'etc/ssl/cert.pem').read_bytes(), 'selected root absent from baseline')
        changed = [('untrusted' if path == chosen else role, path) for role, path in selected]
        planned_build(changed, 'explicit-denial')
        require(certificate not in (root / 'etc/ssl/cert.pem').read_bytes(), 'explicit denial ignored')
        require(certificate in [p.read_bytes() for p in (root / 'etc/ssl/untrusted').iterdir()],
                'explicitly denied root absent from exclusion store')
        print('CONSTRUCTION_VM_PASS packaged_certificate_policy_change', flush=True)

        before = store()
        chosen.write_text('malformed explicitly selected certificate')
        result = invoke(changed)
        require(result.returncode != 0, 'malformed selected package certificate accepted')
        require(store() == before, 'malformed selected input changed the store')
        print('CONSTRUCTION_VM_PASS packaged_certificate_bad_input_rejected', flush=True)


if __name__ == '__main__':
    run()
