#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise real pkg registration controls in disposable VM construction jails.

This is not full database verification or generation acceptance.
The explicit executable is trusted. Fixture hooks only print diagnostic markers.
"""
import argparse
import hashlib
import importlib.util
import shutil
import shlex
import json
import re
import os
from pathlib import Path
import subprocess


def fingerprint(path):
    info = path.stat()
    return (info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest())


def jailed_pkg(root, program, argv, log, construction, epoch, *, expect_failure=False):
    # The explicit trusted executable opens its null descriptor before attaching.
    # Database operations take place inside the private construction jail.
    before = construction.jail_list()
    status = 0
    try:
        with construction.private_jail(root) as jid:
            with log.open('xb') as stream:
                try:
                    construction.command(['/usr/bin/env', 'PKG_INSTALL_EPOCH=' + str(epoch),
                        str(program), '-j', jid, *argv], stdout=stream,
                        stderr=subprocess.STDOUT, timeout=60)
                except subprocess.CalledProcessError as error:
                    status = error.returncode
                    stream.flush()
                    if not expect_failure or status <= 0:
                        print('FAILED_PKG_COMMAND ' + repr(argv), flush=True)
                        print(log.read_text(), flush=True)
                        raise
    finally:
        if construction.jail_list() != before:
            raise ValueError('registration jail survived cleanup')
    if expect_failure and status == 0:
        raise ValueError('expected registration refusal: ' + repr(argv))
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pkg', type=Path, required=True)
    parser.add_argument('--shell-closure', type=Path, required=True)
    parser.add_argument('--disposable-vm', action='store_true')
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--identity', type=Path, required=True)
    args = parser.parse_args()
    identity = json.loads(args.identity.read_text())
    if set(identity) != {'abi', 'osversion', 'install_epoch'} or not isinstance(identity['abi'], str) or type(identity['osversion']) is not int or identity['osversion'] <= 0:
        parser.error('invalid explicit package identity')
    if type(identity['install_epoch']) is not int or not 0 <= identity['install_epoch'] <= 2**63 - 1:
        parser.error('invalid explicit installation epoch')
    args.abi, args.osversion = identity['abi'], identity['osversion']
    args.install_epoch = identity['install_epoch']
    if not args.disposable_vm or os.geteuid() != 0:
        parser.error('requires root in an explicitly disposable VM')
    guest = subprocess.check_output(['/sbin/sysctl', '-n', 'kern.vm_guest'], text=True).strip()
    if guest == 'none':
        parser.error('requires a virtual machine')
    spec = importlib.util.spec_from_file_location('construction', Path(__file__).with_name('construction.py'))
    construction = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(construction)
    program = args.pkg.resolve(strict=True)
    work = args.work.absolute()
    work.mkdir(mode=0o700)  # Never reuse a prior fixture or database.
    sentinel = work / 'outside-only'
    sentinel.write_text('must not be visible inside the candidate')
    report = {'result': 'RUNNING', 'scope': 'pkg-registration-hook-controls',
              'pkg': str(program), 'pkg_sha256': hashlib.sha256(program.read_bytes()).hexdigest(),
              'install_epoch': args.install_epoch, 'cases': []}
    try:
        for enabled in (True, False):
            case = work / ('enabled' if enabled else 'disabled')
            case.mkdir()
            root = case / 'root'; root.mkdir()
            (root / 'var/db/pkg').mkdir(parents=True)
            for entry in json.loads(args.shell_closure.read_text())['files']:
                destination = root / entry.lstrip('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(entry, destination); destination.chmod(0o755)
            # Explicit synthetic account inputs; use the selected package's real
            # generator, not host NSS or a privilege-drop bypass.
            runtime = json.loads(Path('/tests/runtime-declarations.json').read_text())
            actions = [a for a in json.loads(runtime['declaration'])['actions']
                       if a['name'] == 'account-databases']
            if len(actions) != 1:
                raise ValueError('expected one packaged account recipe')
            for entry in runtime['files']:
                destination = root / entry.lstrip('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(entry, destination); destination.chmod(0o755)
            (root / 'etc').mkdir(exist_ok=True)
            accounts = (root / 'etc/master.passwd')
            accounts.write_text('root:*:0:0::0:0:Root:/root:/bin/sh\n'
                'nobody:*:65534:65534::0:0:Unprivileged:/nonexistent:/usr/sbin/nologin\n')
            accounts.chmod(0o600)
            (root / 'etc/group').write_text('wheel:*:0:root\nnobody:*:65534:\n')
            construction.run_jailed(root, actions[0]['argv'], case / 'accounts.log', 60)
            for entry, mode in [('pwd.db', 0o644), ('spwd.db', 0o600)]:
                if (root / 'etc' / entry).stat().st_mode & 0o7777 != mode:
                    raise ValueError('account database mode mismatch')
            repos = root / 'repos'; repos.mkdir()
            payload = root / 'payload'; payload.write_bytes(b'preverified payload\n')
            payload.chmod(0o644)
            before = fingerprint(payload)
            lua_sequence = ['pkg.print_msg(\"REGISTRATION_LUA_A\")',
                            'pkg.print_msg(\"REGISTRATION_LUA_B\")',
                            'pkg.print_msg(\"REGISTRATION_LUA_A\")']
            manifest = {'name': 'registration-fixture', 'version': '1',
                'origin': 'tests/registration-fixture', 'comment': 'registration controls',
                'desc': 'Private registration fixture', 'maintainer': 'test@example.invalid',
                'www': 'https://example.invalid', 'prefix': '/', 'abi': args.abi,
                'flatsize': payload.stat().st_size,
                'files': {'/payload': {'sum': before[-1], 'uname': 'root', 'gname': 'wheel', 'perm': '0644'}},
                'scripts': {'post-install': 'printf "REGISTRATION_SHELL_EXECUTED\\n"; '
                    + 'if test -e ' + shlex.quote(str(sentinel)) + '; then '
                    + 'printf "REGISTRATION_ESCAPE\\n"; else printf "REGISTRATION_ISOLATED\\n"; fi'},
                'lua_scripts': {'post-install': lua_sequence, 'post-deinstall': lua_sequence}}
            path = root / 'manifest.json'; path.write_text(json.dumps(manifest))
            command = ['-C', '/empty-config', '-R', '/repos']
            (root / 'empty-config').write_text('')
            for option in ['ABI=' + args.abi, 'OSVERSION=' + str(args.osversion),
                    'PKG_DBDIR=/var/db/pkg',
                    'PKG_CACHEDIR=/var/cache/pkg',
                    'PKG_ENABLE_PLUGINS=no', 'PKG_TRIGGERS_ENABLE=no',
                    'REPO_AUTOUPDATE=no', 'SYSLOG=no', 'INSTALL_AS_USER=yes',
                    'RUN_SCRIPTS=' + ('yes' if enabled else 'no')]:
                command.extend(['-o', option])
            log = case / 'registration.log'
            jailed_pkg(root, program, command + ['register', '-M', '/manifest.json'], log, construction, args.install_epoch)
            output = log.read_text()
            record = {'scripts_enabled': enabled, 'argv': command, 'output': output,
                      'runtime_archive_sha256': runtime['archive_sha256'],
                      'account_input_sha256': hashlib.sha256(accounts.read_bytes()).hexdigest()}
            report['cases'].append(record)
            if 'REGISTRATION_ESCAPE' in output:
                raise ValueError('hook could inspect outside jail')
            for marker in ('REGISTRATION_SHELL_EXECUTED', 'REGISTRATION_ISOLATED'):
                if (marker in output) != enabled:
                    raise ValueError('script control failed: ' + marker)
            expected_lua = ['REGISTRATION_LUA_A', 'REGISTRATION_LUA_B', 'REGISTRATION_LUA_A'] if enabled else []
            if re.findall(r'REGISTRATION_LUA_[AB]', output) != expected_lua:
                raise ValueError('registration Lua occurrence order/count mismatch')
            if fingerprint(payload) != before:
                raise ValueError('registration changed existing payload')
            query = case / 'database-manifests.json'
            jailed_pkg(root, program, command + ['info', '-a', '--raw', '--raw-format', 'json'], query, construction, args.install_epoch)
            records = json.loads(query.read_text())
            if len(records) != 1:
                raise ValueError('unexpected registered package count')
            if records[0].get('timestamp') != args.install_epoch:
                raise ValueError('registration ignored explicit installation epoch')
            record['verified_install_epoch'] = records[0]['timestamp']
            for key in ('name', 'version', 'files', 'scripts', 'lua_scripts'):
                if records[0].get(key) != manifest[key]:
                    raise ValueError('registered metadata mismatch: ' + key)
            deletion = case / 'deletion.log'
            jailed_pkg(root, program, command + ['delete', '-y', 'registration-fixture'], deletion, construction, args.install_epoch)
            deleted_output = deletion.read_text()
            if re.findall(r'REGISTRATION_LUA_[AB]', deleted_output) != expected_lua:
                raise ValueError('stored Lua occurrence execution order/count mismatch')
            if payload.exists():
                raise ValueError('fixture package deletion did not remove its payload')
            record['deletion_output'] = deleted_output
            record['stored_hook_sequence_verified'] = True
            # Archive registration must retain merge baselines without touching
            # already reconciled candidate files, even when those differ locally.
            stage = root / 'archive-stage'; stage.mkdir()
            archives = root / 'archives'; archives.mkdir()
            inputs = root / 'archive-inputs'; inputs.mkdir()
            config_bodies = {'/config space.conf': b'original baseline\n',
                             '/literal%20.conf': b'literal percent baseline\n',
                             '/empty.conf': b''}
            candidate_before = {}
            for name, body in config_bodies.items():
                (stage / name.lstrip('/')).write_bytes(body)
                candidate = root / name.lstrip('/')
                candidate.write_bytes(b'site configuration must survive\n')
                candidate.chmod(0o640)
                candidate_before[name] = fingerprint(candidate)
            (stage / 'archive-only').write_bytes(b'must not be extracted\n')
            archive_manifest = dict(manifest, name='archive-registration-fixture',
                origin='tests/archive-registration-fixture')
            archive_manifest.pop('files')
            archive_manifest.pop('flatsize')
            archive_manifest['scripts'] = {
                phase: 'printf "ARCHIVE_SHELL_EXECUTED\\n"'
                for phase in ('pre-install', 'post-install')}
            archive_manifest['lua_scripts'] = {
                phase: ['pkg.print_msg("ARCHIVE_LUA_EXECUTED")']
                for phase in ('pre-install', 'post-install')}
            (inputs / 'manifest.json').write_text(json.dumps(archive_manifest))
            (inputs / 'plist').write_text(''.join('@config ' + n + '\n'
                for n in config_bodies) + '/archive-only\n')
            jailed_pkg(root, program, command + ['create', '-M', '/archive-inputs/manifest.json',
                '-p', '/archive-inputs/plist', '-r', '/archive-stage', '-o', '/archives'],
                case / 'archive-create.log', construction, args.install_epoch)
            archive_path = root / 'archives/archive-registration-fixture-1.pkg'
            archive_before = fingerprint(archive_path)
            register_log = case / 'archive-registration.log'
            jailed_pkg(root, program, command + ['install', '--register-only',
                '--local-only', '--yes', '/archives/archive-registration-fixture-1.pkg'],
                register_log, construction, args.install_epoch)
            archive_output = register_log.read_text()
            if 'ARCHIVE_SHELL_EXECUTED' in archive_output or 'ARCHIVE_LUA_EXECUTED' in archive_output:
                raise ValueError('archive registration executed package hooks')
            if archive_before != fingerprint(archive_path):
                raise ValueError('archive registration changed its archive input')
            for name, expected in candidate_before.items():
                if fingerprint(root / name.lstrip('/')) != expected:
                    raise ValueError('archive registration changed candidate config: ' + name)
            if (root / 'archive-only').exists():
                raise ValueError('archive registration extracted an absent payload')
            baseline_log = case / 'archive-baselines.json'
            jailed_pkg(root, program, command + ['shell', '-readonly', '-batch', '-json',
                'SELECT p.name AS package,c.path,typeof(c.content) AS storage, '
                'hex(CAST(c.content AS BLOB)) AS content FROM config_files c '
                'JOIN packages p ON p.id=c.package_id ORDER BY c.path'],
                baseline_log, construction, args.install_epoch)
            expected_baselines = [dict(package='archive-registration-fixture', path=name,
                storage='text', content=body.hex().upper())
                for name, body in sorted(config_bodies.items())]
            if json.loads(baseline_log.read_text()) != expected_baselines:
                raise ValueError('archive registration did not retain original configuration baselines')
            selection_log = case / 'archive-selection.json'
            jailed_pkg(root, program, command + ['shell', '-readonly', '-batch', '-json',
                'SELECT name,time FROM packages ORDER BY name'],
                selection_log, construction, args.install_epoch)
            if json.loads(selection_log.read_text()) != [
                    dict(name='archive-registration-fixture', time=args.install_epoch)]:
                raise ValueError('archive registration package selection or epoch mismatch')
            record['archive_registration'] = dict(result='PASS',
                archive_sha256=archive_before[-1], baselines=expected_baselines,
                candidate_payload_unchanged=True, absent_payload_not_extracted=True,
                hooks_suppressed=True, exact_selection_and_epoch=True,
                output=archive_output)
            # A dependency failure must not partially register the requested
            # package. Supplying the exact missing archive must permit retry.
            dependency_name = 'registration-required-fixture'
            dependent_name = 'registration-dependent-fixture'
            for name in (dependent_name, dependency_name):
                meta = dict(name=name, origin='tests/' + name, version='1',
                    comment='dependency registration fixture', desc='dependency fixture',
                    maintainer='test@example.invalid', www='https://example.invalid',
                    prefix='/', abi=args.abi, files={})
                if name == dependent_name:
                    meta['deps'] = {dependency_name: dict(origin='tests/' + dependency_name, version='1')}
                (inputs / (name + '.json')).write_text(json.dumps(meta))
                jailed_pkg(root, program, command + ['create', '-M',
                    '/archive-inputs/' + name + '.json', '-o', '/archives'],
                    case / (name + '-create.log'), construction, args.install_epoch)
            dump_before = case / 'before-refusal.sql'
            jailed_pkg(root, program, command + ['shell', '-readonly', '-batch', '.dump'],
                dump_before, construction, args.install_epoch)
            refusal_log = case / 'missing-dependency.log'
            status = jailed_pkg(root, program, command + ['install', '--register-only',
                '--local-only', '--yes', '/archives/' + dependent_name + '-1.pkg'],
                refusal_log, construction, args.install_epoch, expect_failure=True)
            dump_after = case / 'after-refusal.sql'
            jailed_pkg(root, program, command + ['shell', '-readonly', '-batch', '.dump'],
                dump_after, construction, args.install_epoch)
            if dump_before.read_bytes() != dump_after.read_bytes():
                raise ValueError('failed dependency registration changed logical database contents')
            retry_log = case / 'dependency-retry.log'
            jailed_pkg(root, program, command + ['install', '--register-only',
                '--local-only', '--yes', '/archives/' + dependent_name + '-1.pkg',
                '/archives/' + dependency_name + '-1.pkg'], retry_log,
                construction, args.install_epoch)
            retry_selection = case / 'retry-selection.json'
            jailed_pkg(root, program, command + ['shell', '-readonly', '-batch', '-json',
                'SELECT name,time FROM packages ORDER BY name'],
                retry_selection, construction, args.install_epoch)
            wanted = [dict(name=name, time=args.install_epoch) for name in sorted(
                ['archive-registration-fixture', dependency_name, dependent_name])]
            if json.loads(retry_selection.read_text()) != wanted:
                raise ValueError('dependency retry changed exact selected package set or epoch')
            for name, expected in candidate_before.items():
                if fingerprint(root / name.lstrip('/')) != expected:
                    raise ValueError('dependency failure/retry changed candidate config: ' + name)
            if (root / 'archive-only').exists():
                raise ValueError('dependency retry extracted a payload')
            record['dependency_failure_retry'] = dict(result='PASS', refusal_exit=status,
                database_unchanged_on_refusal=True, exact_retry_selection=True,
                candidate_payload_unchanged=True, refusal_output=refusal_log.read_text(),
                retry_output=retry_log.read_text())
            contract_path = Path('/tests/database-contract.json')
            if contract_path.exists():
                spec = importlib.util.spec_from_file_location('database_construction',
                    Path(__file__).with_name('database_construction.py'))
                constructor = importlib.util.module_from_spec(spec); spec.loader.exec_module(constructor)
                policy = constructor.payload.preflight.decode(contract_path.read_bytes())
                if policy['install_epoch'] != args.install_epoch:
                    raise ValueError('constructor contract epoch differs from explicit fixture epoch')
                inventory = constructor.payload.archive.inventory_packages([archive_path])
                m = inventory['packages'][0]['manifest']
                policy['packages'] = [dict(name=m['name'], origin=m['origin'], version=m['version'],
                    abi=m['abi'], automatic=0, locked=0, vital=int(m.get('vital', False)))]
                tool, sqlite, inventory, abi = constructor.prepare(program,
                    Path('/usr/local/bin/sqlite3'), inventory, policy, args.osversion)
                accepted = constructor.construct(tool, sqlite, inventory, policy, abi,
                    args.osversion, case / 'database-construction', 60)
                if accepted['result'] != 'PASS' or not accepted['verification']['database_profile_verified']:
                    raise ValueError('database constructor did not verify profile')
                record['database_construction'] = accepted
                # Build a candidate from explicit fixture inputs and archive
                # metadata, never from a scan that approves arbitrary contents.
                candidate = case / 'generation-root'; candidate.mkdir()
                generated = dict(format=1, entries={})
                layout = ['/', '/etc', '/var', '/var/db', '/var/db/pkg']
                for name in layout:
                    directory = candidate / name.lstrip('/')
                    directory.mkdir(exist_ok=True, parents=True); directory.chmod(0o755)
                    generated['entries'][name] = dict(type='directory', uid=0, gid=0,
                        mode=0o755, flags_set=0, source='explicit VM fixture layout', replaces=[])
                bodies = dict(config_bodies, **{'/archive-only': b'must not be extracted\n'})
                entries = inventory['packages'][0]['entries']
                if set(entries) != set(bodies):
                    raise ValueError('unexpected archive fixture payload shape')
                for name, body in bodies.items():
                    item = entries[name]
                    if item['type'] != 'file' or hashlib.sha256(body).hexdigest() != item['sha256']:
                        raise ValueError('fixture bytes differ from archive input')
                    target = candidate / name.lstrip('/'); target.write_bytes(body)
                    if item.get('uname') != 'root' or item.get('gname') != 'wheel':
                        raise ValueError('unexpected symbolic fixture ownership')
                    # Resolve declared names through the explicit fixture accounts
                    # below, as generation reconciliation does; never host NSS.
                    os.chown(target, 0, 0); target.chmod(item['mode'])
                    timestamp = item['mtime'] * 1000000000 + item['mtime_nsec']
                    os.utime(target, ns=(timestamp, timestamp)); os.chflags(target, item['flags_set'])
                account_inputs = {'/etc/master.passwd': b'root:*:0:0::0:0:Root:/root:/bin/sh\n',
                                  '/etc/group': b'wheel:*:0:root\n'}
                for name, body in account_inputs.items():
                    target = candidate / name.lstrip('/'); target.write_bytes(body)
                    mode = 0o600 if name.endswith('master.passwd') else 0o644
                    target.chmod(mode); os.chflags(target, 0)
                    generated['entries'][name] = dict(type='file', uid=0, gid=0, mode=mode,
                        flags_set=0, size=len(body), sha256=hashlib.sha256(body).hexdigest(),
                        source='explicit VM fixture account input', replaces=[])
                for name in layout:
                    os.chflags(candidate / name.lstrip('/'), 0)
                output_policy = dict(path='/var/db/pkg/local.sqlite', uid=0, gid=0, mode=0o644, flags_set=0)
                plan = dict(pkg=tool, sqlite=sqlite, contract=policy, policy=output_policy,
                            abi=abi, osversion=args.osversion)
                generation_output = case / 'generation-construction'
                built = construction.construct(candidate, inventory, generated,
                    generation_output, 60, database=(constructor, plan))
                approved = json.loads((generation_output / 'generated.json').read_text())
                construction.require_match(candidate, inventory, approved)
                database_record = approved['entries']['/var/db/pkg/local.sqlite']
                if database_record['mode'] != 0o644 or not database_record['source'].startswith('database installation receipt sha256:'):
                    raise ValueError('database installation metadata or receipt source missing')
                before_existing = fingerprint(candidate / 'var/db/pkg/local.sqlite')
                try:
                    constructor.install(candidate, inventory, approved,
                        generation_output / 'database', policy, sqlite, output_policy)
                except ValueError as error:
                    if 'already exists' not in str(error):
                        raise
                else:
                    raise ValueError('database installer replaced existing output')
                if fingerprint(candidate / 'var/db/pkg/local.sqlite') != before_existing:
                    raise ValueError('refused replacement changed existing database')
                record['database_generation'] = dict(result=built['result'],
                    full_filesystem_reconciled=True, existing_output_refused=True,
                    database_record=database_record, receipts=built['receipts'])
                invalid = dict(policy, schema_sha256='0' * 64)
                rejected_work = case / 'database-construction-rejected'
                try:
                    constructor.construct(tool, sqlite, inventory, invalid, abi,
                        args.osversion, rejected_work, 60)
                except ValueError as error:
                    if 'schema differs' not in str(error):
                        raise
                else:
                    raise ValueError('constructor accepted unapproved schema')
                if (rejected_work / 'receipt.json').exists() or (rejected_work / 'local.sqlite').exists():
                    raise ValueError('failed constructor published accepted output')
                rejected = json.loads((rejected_work / 'construction.json').read_text())
                if rejected['result'] != 'FAIL':
                    raise ValueError('failed constructor did not retain failure report')
                record['database_construction_rejection'] = dict(result='PASS',
                    no_receipt=True, no_accepted_database=True, error=rejected['error'])
            record['result'] = 'PASS'
        report['result'] = 'PASS'
    except BaseException as error:
        report['result'] = 'FAIL'
        report['error'] = str(error)
        for log in sorted(work.glob('*/*.log')):
            print('REGISTRATION_LOG ' + str(log), flush=True)
            print(log.read_text(), flush=True)
        raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2), flush=True)
    print('PKG_REGISTRATION_PASS shell_and_lua_controls_payload_and_metadata')


if __name__ == '__main__':
    main()
