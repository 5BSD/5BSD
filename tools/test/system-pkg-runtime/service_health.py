# SPDX-License-Identifier: BSD-2-Clause
"""Installed-manifest inventory and complete manager-state validation."""
import json
from pathlib import PurePosixPath
import re


def absolute(value):
    if (not isinstance(value, str) or not value.startswith('/') or
            value.startswith('//') or str(PurePosixPath(value)) != value or
            '..' in PurePosixPath(value).parts or
            any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('canonical absolute service path required')
    return value


def inventory(data, roots):
    document = json.loads(data)
    if (set(document) != {'format', 'bundles'} or
            type(document['format']) is not int or document['format'] != 1 or
            not isinstance(document['bundles'], list)):
        raise ValueError('exact format-1 installed service inventory required')
    roots = {absolute(root) for root in roots}
    bundles, identities, services = set(), set(), {}
    for bundle in document['bundles']:
        if set(bundle) != {'path', 'id', 'services'}:
            raise ValueError('complete bundle inventory record required')
        path = absolute(bundle['path'])
        if (str(PurePosixPath(path).parent) not in roots or
                not path.endswith('.cap') or path in bundles or
                not isinstance(bundle['id'], str) or not bundle['id'] or
                bundle['id'] in identities or not isinstance(bundle['services'], list)):
            raise ValueError('unexpected or duplicate installed bundle')
        bundles.add(path)
        identities.add(bundle['id'])
        for service in bundle['services']:
            if set(service) != {'label', 'program', 'boot', 'endpoints'}:
                raise ValueError('complete service inventory record required')
            label = service['label']
            if (not isinstance(label, str) or
                    not re.fullmatch(r'[A-Za-z0-9_.:/-]+', label) or label in services or
                    type(service['boot']) is not bool or
                    not isinstance(service['endpoints'], list) or
                    any(not isinstance(e, str) or not e for e in service['endpoints']) or
                    len(service['endpoints']) != len(set(service['endpoints']))):
                raise ValueError('invalid or duplicate service declaration')
            program = absolute(service['program'])
            if not program.startswith(path + '/'):
                raise ValueError('service executable outside declared bundle')
            services[label] = service
    if not bundles or not services:
        raise ValueError('empty installed service inventory')
    return services


def manager_states(data):
    if not data.endswith(b'\n'):
        raise ValueError('unterminated or truncated manager status')
    count = None
    manager = False
    states = {}
    for line in data.decode().splitlines():
        if not line:
            continue
        if line == 'switchboard: running':
            if manager:
                raise ValueError('duplicate manager header')
            manager = True
        elif line.startswith('services: '):
            match = re.fullmatch(r'services: ([0-9]+) loaded(?: \([^\n]+\))?', line)
            if count is not None or match is None:
                raise ValueError('invalid manager inventory count')
            count = int(match[1])
        elif line.startswith('fd-budget: '):
            continue
        elif line.startswith('  '):
            match = re.fullmatch(r'  (\S+) +(stopped|starting|running|stopping|done) *'
                                 r'(?: pid ([1-9][0-9]*))? restart=(?:never|always|on-failure|on-crash) mgmt=(?:system|core|user)(.*)', line)
            if match is None or match[1] in states:
                raise ValueError('malformed or duplicate manager service row')
            states[match[1]] = dict(state=match[2], pid=int(match[3]) if match[3] else None,
                                    cleanup=' cleanup=' in match[4])
        else:
            raise ValueError('unrecognized manager status output')
    if not manager or count is None or count != len(states):
        raise ValueError('missing or truncated manager service inventory')
    return states


def required_services(services, states):
    required = {name: value for name, value in services.items() if value['boot']}
    if not required:
        raise ValueError('this full-base qualification requires boot services')
    failures = []
    for name in sorted(required):
        state = states.get(name)
        if (state is None or state['state'] != 'running' or
                state['pid'] is None or state['cleanup']):
            failures.append(name)
    if failures:
        raise ValueError('required boot services not ready: ' + ', '.join(failures))
    return sorted(required)


USER_OPERATIONS = frozenset(('time', 'sysctl', 'notify', 'log', 'memory', 'power', 'device-denied'))


def operation_settings(value):
    fields = {'qualification', 'target', 'output', 'guest_directory', 'cases'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('explicit captured ordinary-operation helper required')
    for field in ('qualification', 'target', 'output'):
        if not isinstance(value[field], str) or not value[field]:
            raise ValueError('nonempty operation helper selection required')
    absolute(value['qualification'])
    absolute(value['guest_directory'])
    cases = value['cases']
    if (not isinstance(cases, list) or not cases or
            any(not isinstance(case, str) or case not in USER_OPERATIONS for case in cases) or
            len(cases) != len(set(cases))):
        raise ValueError('distinct supported ordinary-session operations required')
    return value


def operation_result(data, expected):
    record = json.loads(data)
    if (not isinstance(record, dict) or set(record) != {'format', 'operation', 'status'} or
            type(record['format']) is not int or record['format'] != 1 or
            record['operation'] != expected or record['status'] != 'passed'):
        raise ValueError('complete matching provider-operation success record required')
    return record


# These are installed operator interfaces, not authority granted to the uploaded
# ordinary client. Their argument vectors exercise real provider methods.
INSTALLED_OPERATIONS = {
    'network-resolve': ('ordinary', ('resolve', '-4', '192.0.2.1', '443')),
    'system-extension-config': ('root', ('config',)),
}


def installed_settings(value, payloads):
    if not isinstance(value, list) or not value:
        raise ValueError('nonempty installed operator selection required')
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {'operation', 'program'}:
            raise ValueError('exact installed operator selection required')
        operation = item['operation']
        if (not isinstance(operation, str) or operation not in INSTALLED_OPERATIONS or
                operation in seen):
            raise ValueError('distinct supported installed operations required')
        seen.add(operation)
        if absolute(item['program']) not in payloads:
            raise ValueError('installed operator must be a regular image payload')
    return value


def installed_result(data, operation):
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not data.endswith(b'\n') or len(data) > 1024 * 1024:
        raise ValueError('complete bounded installed operator output required')
    lines = data.decode().splitlines()
    if operation == 'network-resolve':
        header = re.fullmatch(r'count=([0-9]+) ttl_seconds=([0-9]+) canonname=(.*)', lines[0])
        if header is None or not 0 < int(header[1]) == len(lines) - 1:
            raise ValueError('complete nonempty numeric resolution required')
        # Numeric documentation address/service: no external DNS or peer needed.
        results = []
        for index, line in enumerate(lines[1:]):
            row = re.fullmatch(r'result\[([0-9]+)\].family=inet4 address=192\.0\.2\.1 '
                               r'port=443 scope_id=0 socket_type=([0-9]+) protocol=([0-9]+)', line)
            if row is None or int(row[1]) != index:
                raise ValueError('numeric resolve reply differs from requested endpoint')
            if (int(row[2]), int(row[3])) not in ((1, 6), (2, 17)):
                raise ValueError('numeric resolve requires TCP or UDP endpoint semantics')
            results.append(dict(socket_type=int(row[2]), protocol=int(row[3])))
        return dict(operation=operation, status='passed', results=results)
    if operation == 'system-extension-config':
        modules = {}
        for line in lines:
            row = re.fullmatch(r'([A-Za-z0-9_.-]+): (allowed|denied), '
                               r'boot=(enabled|blocked|disabled), loaded=(yes|no|undisclosed), '
                               r'installed=(yes|no|unknown), policy=(override|default)', line)
            if row is None or row[1] in modules:
                raise ValueError('complete unique ready extension policy records required')
            if ((row[2] == 'denied' and (row[3] == 'enabled' or row[4] != 'undisclosed')) or
                    (row[2] == 'allowed' and (row[3] == 'blocked' or row[4] == 'undisclosed'))):
                raise ValueError('inconsistent extension policy reply')
            modules[row[1]] = dict(allowed=row[2], boot=row[3], loaded=row[4],
                                  installed=row[5], policy=row[6])
        if not modules:
            raise ValueError('nonempty extension policy enumeration required')
        return dict(operation=operation, status='passed', modules=modules)
    raise ValueError('unsupported installed operation')


def load(path, report):
    from pathlib import Path
    from qualification_artifacts import resolve, digest
    path = Path(path).resolve(strict=True)
    policy_bytes = path.read_bytes()
    policy = json.loads(policy_bytes)
    fields = {'format', 'qualification', 'target', 'output', 'roots',
              'control_program', 'deadline_seconds'}
    if policy.get('format') in (2, 3):fields.add('operations')
    if policy.get('format') == 3:fields.add('installed_operations')
    if (set(policy) != fields or type(policy['format']) is not int or
            policy['format'] not in (1, 2, 3)):
        raise ValueError('exact format-1/2/3 service qualification policy required')
    operations = operation_settings(policy['operations']) if policy['format'] >= 2 else None
    installed = installed_settings(policy['installed_operations'], report['payload_sha256']) if policy['format'] == 3 else []
    roots = policy['roots']
    if (not isinstance(roots, list) or not roots or
            any(not isinstance(root, str) for root in roots) or
            len(roots) != len(set(roots))):
        raise ValueError('distinct explicit installed bundle roots required')
    for root in roots:absolute(root)
    control = absolute(policy['control_program'])
    if control not in report['payload_sha256']:
        raise ValueError('manager control program must be an image payload')
    if type(policy['deadline_seconds']) is not int or policy['deadline_seconds'] <= 0:
        raise ValueError('positive service qualification deadline required')
    helper, binding = resolve(Path(policy['qualification']), policy['target'], policy['output'])
    bindings = {str(path): digest(path), str(helper): digest(helper)}
    operation_helper = operation_binding = None
    if operations is not None:
        operation_helper, operation_binding = resolve(Path(operations['qualification']), operations['target'], operations['output'])
        bindings[str(operation_helper)] = digest(operation_helper)
    return dict(policy=policy, policy_bytes=policy_bytes, helper=helper,
                helper_binding=binding, bindings=bindings, operations=operations,
                installed_operations=installed, installed_payload_sha256={item['program']: report['payload_sha256'][item['program']] for item in installed},
                operation_helper=operation_helper, operation_helper_binding=operation_binding)


def exercise(loaded, invoke, output, label, user_invoke=None):
    import shlex
    import time
    import uuid
    policy = loaded['policy']
    operations = loaded.get('operations')
    installed = loaded.get('installed_operations', [])
    needs_user = operations is not None or any(INSTALLED_OPERATIONS[item['operation']][0] == 'ordinary' for item in installed)
    if needs_user and not callable(user_invoke):
        raise ValueError('authenticated ordinary-session operation callback required')
    work = '/root/.service-audit-' + uuid.uuid4().hex
    q = shlex.quote
    def command(name, text, source=None):
        return invoke(label + '-service-' + name, text, source)
    result = dict(status='running', scope='Installed-manifest boot-unit readiness and manager status RPC; not per-provider operation coverage',
                  helper=loaded['helper_binding'], roots=policy['roots'])
    if operations is not None:
        result.update(scope='Installed-manifest boot readiness plus selected ordinary-login operations; not complete provider operation coverage',
                      operation_helper=loaded['operation_helper_binding'], ordinary_operations=[],
                      all_provider_operations_qualified=False)
    if installed:
        result.update(installed_operations=[], installed_payload_sha256=loaded['installed_payload_sha256'],
                      all_provider_operations_qualified=False,
                      scope='Installed-manifest readiness, selected login operations and installed operator RPCs; not complete provider operation coverage')
    report = output / (label + '-service-health.json')
    def save():report.write_text(json.dumps(result, indent=2) + '\n')
    save()
    try:
        command('work', '/bin/mkdir -m 700 ' + q(work))
        command('upload', 'umask 077; /bin/cat > ' + q(work + '/inventory') +
                ' && /bin/chmod 500 ' + q(work + '/inventory'), loaded['helper'])
        raw = command('inventory', q(work + '/inventory') + ' ' +
                      ' '.join(q(root) for root in policy['roots']))
        services = inventory(raw, policy['roots'])
        result['declared_services'] = services
        if not any(service['boot'] for service in services.values()):
            raise ValueError('this full-base qualification requires boot services')
        until = time.monotonic() + policy['deadline_seconds']
        attempt = 0
        while True:
            attempt += 1
            states = manager_states(command('status-' + str(attempt),
                                            q(policy['control_program']) + ' services'))
            result['states'] = states
            try:
                result['required_boot_services'] = required_services(services, states)
                break
            except ValueError as error:
                result['readiness_error'] = str(error)
                save()
                if time.monotonic() >= until:
                    raise TimeoutError('manifest-derived service readiness deadline: ' + str(error)) from error
                time.sleep(0.5)
        if operations is not None:
            operation_work = operations['guest_directory'].rstrip('/') + '/.provider-operations-' + uuid.uuid4().hex
            result['operation_work'] = operation_work
            command('operation-work', '/bin/mkdir -m 755 ' + q(operation_work))
            program = operation_work + '/client'
            command('operation-upload', 'umask 077; /bin/cat > ' + q(program) +
                    ' && /bin/chmod 555 ' + q(program), loaded['operation_helper'])
            for case in operations['cases']:
                raw = user_invoke(label + '-provider-' + case, q(program) + ' ' + q(case))
                result['ordinary_operations'].append(operation_result(raw, case))
                save()
            command('operation-cleanup', '/bin/rm -rf -- ' + q(operation_work))
        for item in installed:
            operation = item['operation']
            session, arguments = INSTALLED_OPERATIONS[operation]
            text = ' '.join(q(arg) for arg in (item['program'], *arguments))
            raw = (user_invoke(label + '-operator-' + operation, text) if session == 'ordinary'
                   else command('operator-' + operation, text))
            record = installed_result(raw, operation)
            record.update(program=item['program'], session=session)
            result['installed_operations'].append(record)
            save()
        command('cleanup', '/bin/rm -rf -- ' + q(work))
        result.update(status='passed', attempts=attempt)
        result.pop('readiness_error', None)
    except Exception as error:
        result.update(status='failed', error=repr(error))
        raise
    finally:
        save()
    return result
