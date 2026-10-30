# SPDX-License-Identifier: BSD-2-Clause
"""Minimal actual Capsule/SwitchBoard closure for the Secure Boot VM fixture.

All executable dependencies come from the supplied world stage or object tree;
never resolve against host libraries or execute staged code on the host.
"""
from pathlib import Path
import json
import os
import re
import stat
import shutil
import subprocess


def policy_destination(system, destination):
    if (not destination.startswith('/') or
            any(part in ('', '.', '..') for part in destination[1:].split('/')) or
            any(ord(c) < 32 or ord(c) == 127 for c in destination)):
        raise ValueError('filesystem policy destination must be a canonical absolute path')
    target = system / destination[1:]
    if target.parent.resolve() != target.parent or target.is_symlink():
        raise ValueError('filesystem policy destination crosses a symlink')
    return target


def install_switchboard_policy(system, source, filename):
    source = Path(source).resolve(strict=True)
    if not source.is_file() or source.stat().st_size > 1024 * 1024:
        raise ValueError('switchboard policy must be a regular file no larger than 1 MiB')
    if source.is_relative_to(system.resolve()):
        raise ValueError('switchboard policy input must be outside the image')
    target = policy_destination(system, '/Capabilities/Config/switchboard/' + filename)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if not target.is_file():
            raise ValueError('unexpected switchboard policy destination')
        target.unlink()
    # Replace the staging entry; never chmod or reopen an inherited read-only
    # inode, which may also be linked outside this private image.
    if target.exists():
        if not target.is_file():
            raise ValueError('policy destination is not a regular file')
        target.unlink()
    target.write_bytes(source.read_bytes())
    target.chmod(0o444)
    return source






def assemble(root, obj, system, *, native=False, capsign=None, log=None, programs=None,
             storage_policy=None, filesystem_policy=None, storage_challenge=None,
             filesystem_policy_destination='/Capabilities/Config/bsdfilesystem.ucl',
             provider_crash=False):
    inputs = []
    seen = set()
    if provider_crash and filesystem_policy is None:
        raise ValueError('provider crash fixture requires filesystem policy')
    def copy(source, destination):
        source = source.resolve(strict=True)
        if not (source.is_relative_to(root) or source.is_relative_to(obj)):
            raise ValueError('input escapes the supplied world/object trees: ' + str(source))
        target = system / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.parent.resolve(strict=True) != target.parent:
            raise ValueError('fixture destination parent crosses a symlink: ' + str(target))
        # The inherited baseline contains read-only executables. Replace the
        # private staging entry, never reopen or chmod its existing inode.
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError('unexpected fixture destination: ' + str(target))
        if target.exists():
            target.unlink()
        shutil.copyfile(source, target)
        shutil.copymode(source, target)
        inputs.append(source)
        return source

    def elf(source, destination):
        if destination in seen:
            return
        seen.add(destination)
        source = copy(source, destination)
        headers = subprocess.check_output(['readelf', '-l', str(source)], text=True)
        with source.open('rb') as file:
            header = file.read(18)
        byteorder = 'little' if header[5] == 1 else 'big'
        executable = (int.from_bytes(header[16:18], byteorder) == 2 or
                      'Requesting program interpreter:' in headers)
        if executable and not source.stat().st_mode & 0o111:
            raise ValueError('fixture executable lacks execute permission: ' + str(source))
        if programs is not None and executable:
            programs.append('/' + destination)
        for interpreter in re.findall(r'Requesting program interpreter: ([^\]]+)', headers):
            if interpreter != '/libexec/ld-elf.so.1':
                raise ValueError('unexpected native fixture interpreter: ' + interpreter)
            # Match the loader rebuilt by the maintained bootstrap step.
            elf(obj / 'libexec/rtld-elf/ld-elf.so.1', interpreter.lstrip('/'))
        dynamic = subprocess.check_output(['readelf', '-d', str(source)], text=True)
        if re.search(r'\((?:RPATH|RUNPATH)\)', dynamic):
            raise ValueError('unexpected runtime search path in ' + str(source))
        for library in re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic):
            if '/' in library:
                raise ValueError('unexpected dependency path: ' + library)
            matches = [Path(directory) / library for directory in ('lib', 'usr/lib')
                       if (root / directory / library).is_file()]
            if len(matches) != 1:
                raise ValueError('missing or ambiguous staged library: ' + library)
            relative = matches[0]
            # The maintained bootstrap step rebuilds this public API library.
            # Its staged predecessor may not contain newly added API symbols.
            rebuilt = {'libc.so.7': 'lib/libc',
                       'libservice.so.2': 'lib/libservice',
                       'libcapsulert.so.1': 'lib/libcapsulert',
                       'libpam.so.6': 'lib/libpam/libpam'}
            dependency = (obj / rebuilt[library] / library
                          if library in rebuilt else root / relative)
            elf(dependency, str(relative))

    elf(obj / 'usr.sbin/capsule/capsule', 'sbin/capsule')
    elf(obj / 'usr.sbin/switchboard/switchboard', 'usr/libexec/switchboard')
    elf(root / 'bin/sh', 'bin/sh')
    elf(obj / 'usr.sbin/pwd_mkdb/pwd_mkdb', 'usr/sbin/pwd_mkdb')
    elf(obj / 'tools/test/secureboot/accounts/alternate_test', 'usr/libexec/security-pwd-test')
    elf(obj / 'usr.bin/cap_mkdb/cap_mkdb', 'usr/bin/cap_mkdb')
    elf(obj / 'tools/test/secureboot/accounts/input_test', 'usr/libexec/security-cap-test')
    for program in ('bin/cat', 'bin/cp', 'bin/mv', 'bin/rm', 'bin/mkdir',
                    'usr/bin/mktemp', 'usr/bin/sort'):
        elf(root / program, program)
    (system / 'etc').mkdir(exist_ok=True)
    program_script = Path(__file__).with_name('programs.sh')
    shutil.copyfile(program_script, system / 'etc/security-programs.sh')
    (system / 'etc/security-programs.sh').chmod(0o444)
    inputs.append(program_script)
    for name in ('etc/pwd.db', 'etc/spwd.db', 'etc/group', 'etc/master.passwd',
                 'etc/passwd', 'etc/capsule.conf', 'boot/capsule.conf'):
        copy(root / name, name)
    for name in ('Capabilities/System', 'Capabilities/Apps', 'Capabilities/Users',
                 'Capabilities/Run', 'Capabilities/Config/switchboard', 'tmp',
                 'var/run', 'var/log'):
        (system / name).mkdir(parents=True, exist_ok=True)
    # The basic fixture uses the supplied world's boot admission policy.
    # Native/provider cases below replace it with their explicit fixture input.
    copy(root / 'Capabilities/Config/switchboard/boot-authority.ucl',
         'Capabilities/Config/switchboard/boot-authority.ucl')
    policy = Path(__file__).resolve().parents[3] / 'usr.sbin/BSDFilesystem/bsdfilesystem.ucl'
    shutil.copyfile(policy, system / 'Capabilities/Config/bsdfilesystem.ucl')
    (system / 'Capabilities/Config/bsdfilesystem.ucl').chmod(0o444)
    inputs.append(policy)
    (system / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\n')
    (system / 'etc/ttys').write_text('')
    # Exercise actual rc launch with an authenticated, bounded guest probe.
    # This does not run the staged world's general-purpose rc scripts.
    (system / 'etc/rc').write_text('exec /sbin/secureboot-init --capsule-child\n')
    if filesystem_policy is not None:
        if storage_policy is None or capsign is None:
            raise ValueError('storage provider requires explicit boot policy and signer')
        source_root = Path(__file__).resolve().parents[3]
        policy_target = policy_destination(system, filesystem_policy_destination)
        default_target = system / 'Capabilities/Config/bsdfilesystem.ucl'
        if policy_target != default_target and policy_target.exists():
            raise ValueError('filesystem policy destination would replace another fixture input')
        policy_target.parent.mkdir(parents=True, exist_ok=True)
        for source, target in ((storage_policy, system / 'boot/capsule.conf'),
                               (filesystem_policy, policy_target)):
            target.unlink(missing_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o444)
            inputs.append(source.resolve(strict=True))
        if storage_challenge is None or not re.fullmatch('[0-9a-f]{32}', storage_challenge):
            raise ValueError('storage provider fixture requires an explicit challenge')
        (system / 'etc/storage-test-challenge').write_text(storage_challenge)
        (system / 'etc/storage-test-challenge').chmod(0o444)
        # Compatibility identity files are explicit stage inputs. The runner
        # neither invents a UUID nor derives policy by parsing UCL a second way.
        for name in ('etc/hostid', 'etc/machine-id'):
            copy(root / name, name)
        for program in ('bin/kenv', 'sbin/sysctl', 'sbin/md5', 'usr/bin/cmp'):
            rebuilt = {'sbin/md5': 'sbin/md5/md5', 'sbin/sysctl': 'sbin/sysctl/sysctl',
                       'usr/bin/cmp': 'usr.bin/cmp/cmp'}
            elf(obj / rebuilt[program] if program in rebuilt else root / program, program)
        for name, destination in (
                ('rc.subr', 'etc/rc.subr'), ('hostid.subr', 'etc/hostid.subr'),
                ('rc.conf', 'etc/defaults/rc.conf'),
                ('rc.d/hostid', 'etc/rc.d/hostid'),
                ('rc.d/hostid_save', 'etc/rc.d/hostid_save'),
                ('safe_eval.sh', 'libexec/safe_eval.sh'),
                ('debug.sh', 'libexec/debug.sh')):
            source = source_root / 'libexec/rc' / name
            target = system / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o444)
            inputs.append(source)
        hostid_probe = Path(__file__).with_name('hostid.sh')
        shutil.copyfile(hostid_probe, system / 'etc/security-hostid.sh')
        (system / 'etc/security-hostid.sh').chmod(0o444)
        inputs.append(hostid_probe)
        if programs is not None:
            programs.extend(['/etc/rc.d/hostid', '/etc/rc.d/hostid_save'])
        elf(obj / 'tools/test/secureboot/storage-observer/storage_probe', 'sbin/storage-probe')
        (system / 'etc/rc').write_text('/bin/sh /etc/security-hostid.sh || exit 1\n'
            + '/sbin/storage-probe' + (' --provider-crash' if provider_crash else '') + ' || exit 1\n'
            'exec /sbin/secureboot-init --capsule-child\n')
        observer_policy = Path(__file__).with_name('storage-client') / 'boot-authority.ucl'
        inputs.append(install_switchboard_policy(system, observer_policy, 'boot-authority.ucl'))
        consumer = (Path(__file__).with_name('storage-client'),
             obj / 'tools/test/secureboot/storage-client/storage_client.capimage.install',
             'StorageClient', 'client', 'Unit.ucl', 'storage_client')
        for source, binary, bundle, unit, manifest, executable in (
                (source_root / 'usr.sbin/BSDFilesystem',
                 obj / ('tools/test/secureboot/provider-crash/storage_crash_provider.capimage.install'
                        if provider_crash else 'usr.sbin/BSDFilesystem/BSDFilesystem.capimage.install'),
                 'Filesystem', 'bsdfilesystem',
                 'capbundle/bsdfilesystem.ucl',
                 'BSDFilesystem'),
                consumer):
            base = 'Capabilities/System/' + bundle + '.cap'
            unit_path = base + '/Units/' + unit + '.unit'
            elf(binary, unit_path + '/bin/' + executable)
            for src, dest in ((source / ('capbundle/Bundle.ucl' if bundle == 'Filesystem' else 'Bundle.ucl'), base + '/Bundle.ucl'),
                              (source / manifest, unit_path + '/Unit.ucl')):
                shutil.copyfile(src, system / dest)
                (system / dest).chmod(0o444)
                inputs.append(src)
    if native:
        source_root = Path(__file__).resolve().parents[3]
        for program, bundle, unit, manifest in (
                ('BSDAudit', 'Audit', 'bsdaudit', 'bsdaudit'),
                ('BSDNotify', 'Notify', 'bsdnotify', 'bsdnotify'),
                ('BSDCrypto', 'Crypto', 'bsdcrypto', 'crypto')):
            source = source_root / 'usr.sbin' / program
            base = 'Capabilities/System/' + bundle + '.cap'
            unit_path = base + '/Units/' + unit + '.unit'
            # Install-format image retains embedded policy through stripping.
            elf(obj / 'usr.sbin' / program / (program + '.capimage.install'),
                unit_path + '/bin/' + program)
            for src, dest in [('Bundle.ucl', base + '/Bundle.ucl'),
                              (manifest + '.ucl', unit_path + '/Unit.ucl')]:
                target = system / dest
                shutil.copyfile(source / 'capbundle' / src, target)
                target.chmod(0o444)
                inputs.append(source / 'capbundle' / src)
            if program == 'BSDNotify':
                config = system / unit_path / 'Config'
                config.mkdir()
                source_config = source / 'capbundle/bsdnotify.conf'
                shutil.copyfile(source_config, config / 'bsdnotify.conf')
                (config / 'bsdnotify.conf').chmod(0o444)
                inputs.append(source_config)
        elf(obj / 'tools/test/secureboot/native/native_service_probe',
            'sbin/native-service-probe')
        (system / 'etc/rc').write_text('/sbin/native-service-probe || exit 1\n'
            'exec /sbin/secureboot-init --capsule-child\n')
        # Explicit boot software grant; UNIX UID 0 adds no authority.
        policy_input = Path(__file__).with_name('policy') / 'boot-authority.ucl'
        inputs.append(install_switchboard_policy(system, policy_input, 'boot-authority.ucl'))
    if native or filesystem_policy is not None:
        write_metalog(system, system / 'METALOG')
        key = system.parent / 'private-test-keys' / ('code-storage.pem' if filesystem_policy is not None else 'code.pem')
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', str(key)],
            check=True, stdout=log, stderr=log)
        key.chmod(0o600)
        public = key.with_suffix('.pub')
        subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(public)],
            check=True, stdout=log, stderr=log)
        environment = dict(os.environ, CAPSIGN=str(capsign))
        for helper, args in [('sign-stage.sh', ['-e', '-k', str(key)]),
                             ('verify-stage.sh', [])]:
            if helper == 'verify-stage.sh':
                args = ['-p', str(public)]
            script = source_root / 'tools/build/capimage' / helper
            subprocess.run(['sh', str(script), '-r', str(system), *args],
                env=environment, check=True, stdout=log, stderr=log)
            inputs.append(script)
        inputs.append(capsign)
        (system / 'METALOG').unlink()
    return inputs


def write_metalog(system, destination):
    """Preserve fixture metadata, including private account database modes."""
    entries = ['#mtree 2.0', '. type=dir uid=0 gid=0 mode=0755']
    for entry in sorted(system.rglob('*')):
        if entry == destination:
            continue
        mode = entry.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
            raise ValueError('fixture requires regular files, directories or symlinks: ' + str(entry))
        kind = 'link' if stat.S_ISLNK(mode) else ('dir' if stat.S_ISDIR(mode) else 'file')
        relative = entry.relative_to(system)
        parts = relative.parts
        owner, group = 0, 0
        if len(parts) >= 3 and parts[:2] == ('Capabilities', 'Users'):
            if parts[2] not in ('31001', '31002'):
                raise ValueError('unexpected personal fixture UID: ' + parts[2])
            owner, group = int(parts[2]), 65534
        # mtree consumes whitespace-separated tokens and backslash escapes.
        # Quote bytes, including non-ASCII bytes, without changing filenames.
        path_token = ''.join(chr(byte) if 33 <= byte <= 126 and byte not in (35, 92)
                             else '\\%03o' % byte for byte in os.fsencode(relative))
        link = ''
        if stat.S_ISLNK(mode):
            target = ''.join(chr(byte) if 33 <= byte <= 126 and byte not in (35, 92)
                             else '\\%03o' % byte for byte in os.fsencode(os.readlink(entry)))
            link = ' link=' + target
        entries.append('./' + path_token + link +
            f' type={kind} uid={owner} gid={group} mode={stat.S_IMODE(mode):04o} tags=package=secureboot-fixture')
    destination.write_text('\n'.join(entries) + '\n')
