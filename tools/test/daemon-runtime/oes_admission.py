"""Stage current daemon binaries and .ucl bundles for private OES admission."""
import hashlib
import json
import shutil
import subprocess


def stage_admission(stage, obj):
    hashes = {}

    def copy(relative, target, static=False):
        origin = obj / relative
        if static and 'statically linked' not in subprocess.check_output(
                ['file', str(origin)], text=True):
            raise RuntimeError('admission input must be static: ' + str(origin))
        before = hashlib.sha256(origin.read_bytes()).hexdigest()
        destination = stage / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, destination)
        if any(hashlib.sha256(p.read_bytes()).hexdigest() != before
               for p in (origin, destination)):
            raise RuntimeError('admission input changed: ' + str(origin))
        hashes[target] = before

    for program in ('capsule', 'switchboard'):
        copy('tools/test/oes-admission/' + program, 'tests/' + program, True)
    (stage / 'tests/oes-admission-boot').write_text('PID1 Capsule admission fixture\n')
    for directory in ('Capabilities/System', 'Capabilities/Apps',
                      'Capabilities/Run', 'Capabilities/Config/switchboard',
                      'Capabilities/System/CoalitionLifecycle.cap',
                      'var/run', 'var/log', 'lib', 'usr/lib', 'libexec', 'usr/libexec'):
        (stage / directory).mkdir(parents=True, exist_ok=True)
    (stage / 'etc/capsule.conf').write_text(
        'pidfile="/tmp/oes-capsule.pid";\n'
        'control_socket="/tmp/oes-capsule.sock";\n'
        'control_socket_mode="0600";\n'
        'service_manager="/tests/switchboard";\n')
    # Empty boot authority; every protected lookup must come from its unit.
    (stage / 'Capabilities/Config/switchboard/boot-authority.ucl').write_text(
        'attributes=[]; endpoints=["system.OES"]; admin_rights=false;\n')
    (stage / 'etc/master.passwd').write_text(
        'root:*:0:0::0:0:root:/root:/bin/sh\n'
        'nobody:*:65534:65534::0:0:nobody:/nonexistent:/bin/sh\n'
        'capability:*:976:976::0:0:capability:/nonexistent:/usr/sbin/nologin\n')
    (stage / 'etc/group').write_text('wheel:*:0:root\nnobody:*:65534:\ncapability:*:976:\n')
    subprocess.run(['pwd_mkdb', '-p', '-d', str(stage / 'etc'),
                    str(stage / 'etc/master.passwd')], check=True)

    def bundle(name, unit, policy):
        base = 'Capabilities/System/' + name + '.cap/'
        directory = stage / base
        directory.mkdir()
        metadata = {'schema': 'org.5bsd.capability-bundle',
                    'bundle_id': 'system.' + name, 'version': '1.0.0',
                    'sequence': 1, 'author': '5BSD', 'publisher': 'org.5bsd.base',
                    'units': [unit]}
        (directory / 'Bundle.ucl').write_text(json.dumps(metadata) + '\n')
        target = base + 'Units/' + unit + '.unit/'
        copy('tools/test/oes-admission/oes_fixture', target + 'bin/' + unit, True)
        (stage / target / 'Unit.ucl').write_text(json.dumps(policy) + '\n')

    bundle('OESProvider', 'provider', {
        'program': 'provider', 'user': 'root', 'restart': 'never',
        'directories': ['/'], 'visible': ['user'],
        'activation': {'boot': True, 'ipc': [
            {'name': 'system.OES', 'requires': ['system.oes']}]},
        'arguments': ['provider']})
    for name, result, allowed, root, attributes in [
            ('OESAllowed', 'allow', True, False, ['system.oes']),
            ('OESDenied', 'deny', False, False, []),
            ('OESRootDenied', 'root-deny', False, True, []),
            ('OESWrongAttribute', 'wrong-attribute', False, False, ['system.OES'])]:
        bundle(name, 'client', {
            'program': 'client', 'activation': {'boot': True},
            'ambient': True, 'protocol': 'unix', 'restart': 'never',
            'user': 'root' if root else 'nobody', 'attributes': attributes,
            'arguments': ['consumer', 'allow' if allowed else 'deny',
                          '/tmp/oes-' + result, '0' if root else '65534']})
    bundle('OESCoordinator', 'coordinator', {
        'program': 'coordinator', 'activation': {'boot': True},
        'ambient': True, 'protocol': 'unix', 'restart': 'never',
        'user': 'root', 'attributes': ['system.switchboard.admin'],
        'arguments': ['coordinator']})
    for name, attributes in [('OESApplicationAllowed', ['system.oes']),
                             ('OESApplicationDenied', [])]:
        bundle(name, 'client', {'program': 'client', 'activation': {'exec': True},
                                'attributes': attributes})
    copy('tools/test/oes-admission/oes_fixture', 'tests/oes-unregistered', True)
    (stage / 'etc/ttys').write_text('')
    # Include configuration bytes in the evidence, not only executables.
    for path in list(stage.rglob('*.ucl')) + [stage / 'etc/capsule.conf']:
        hashes[str(path.relative_to(stage))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes, []
