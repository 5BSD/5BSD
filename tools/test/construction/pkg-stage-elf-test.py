#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify staged pkg ELF inspection against an absolute symlink to a host file.

Builds distinguishable host/stage ELF fixtures in a private work directory. Does
not install packages or execute fixture binaries. PASS requires dependencies from
the staged payload only; the archived link must retain its absolute target.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('pkg', 'cc', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--abi', required=True)
    args = parser.parse_args()
    pkg = args.pkg.resolve(strict=True)
    cc = args.cc.resolve(strict=True)
    work = args.work.absolute()
    if not work.is_relative_to('/usr/obj/usr/src'):
        parser.error('qualification work must be under /usr/obj/usr/src')
    work.mkdir(mode=0o700)
    env = {'PATH': '/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin',
           'HOME': str(work), 'LC_ALL': 'C'}
    commands = []
    report = {'result': 'RUNNING', 'scope': 'staged ELF symlink inspection',
              'abi': args.abi, 'commands': commands,
              'tools_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in (pkg, cc)}}

    def run(argv, check=True):
        command = list(map(str, argv))
        result = subprocess.run(command, cwd=work, env=env, text=True,
                                capture_output=True, timeout=120)
        commands.append({'argv': command, 'exit': result.returncode,
                         'stdout': result.stdout, 'stderr': result.stderr})
        if check:
            result.check_returncode()
        return result

    try:
        stage = work / 'stage'; stage.mkdir()
        outside = work / 'outside'; outside.mkdir()
        target = outside / 'image'
        staged_target = stage / str(target).lstrip('/')
        staged_target.parent.mkdir(parents=True)
        marker = work / 'marker.c'
        marker.write_text('int fixture_marker(void) { return 17; }\n')
        payload = work / 'payload.c'
        payload.write_text('extern int fixture_marker(void);\n'
                           'int fixture_payload(void) { return fixture_marker(); }\n')
        for name, image in [('host', target), ('stage', staged_target)]:
            library = work / ('lib' + name + 'marker.so.1')
            run([cc, '-shared', '-fPIC', '-Wl,-soname,' + library.name,
                 '-o', library, marker])
            run([cc, '-shared', '-fPIC', '-Wl,-soname,libfixture.so.1',
                 '-o', image, payload, library])
        alias = stage / 'usr/lib/libfixture.so.1'
        alias.parent.mkdir(parents=True)
        manifest = work / 'manifest.json'
        manifest.write_text(json.dumps({'name': 'stage-elf-fixture', 'version': '1',
            'origin': 'tests/stage-elf-fixture', 'comment': 'staged ELF fixture',
            'desc': 'staged ELF fixture', 'maintainer': 'test@example.invalid',
            'www': 'https://example.invalid', 'prefix': '/', 'abi': args.abi}))
        plist = work / 'plist'
        plist.write_text(str(target) + '\n/usr/lib/libfixture.so.1\n')
        repos = work / 'repos'; repos.mkdir()
        cases = [
            ('absolute', str(target), True, True),
            ('absolute-alias-first', str(target), True, True),
            ('relative', os.path.relpath(staged_target, alias.parent), True, True),
            ('root-parent', '/../../' + str(target).lstrip('/'), True, True),
            ('directory-link', 'directory/image', True, True),
            ('directory-parent', 'directory/../outside/image', True, True),
            ('relative-chain', 'chain', True, True),
            ('dangling-host-present', str(outside / 'host-only'), True, False),
            ('self-loop', 'libfixture.so.1', False, False),
            ('two-link-loop', 'cycle', False, False),
            ('not-directory', str(target) + '/child', False, False),
        ]
        (outside / 'host-only').write_bytes(target.read_bytes())
        (alias.parent / 'directory').symlink_to(target.parent)
        (alias.parent / 'chain').symlink_to(os.path.relpath(staged_target, alias.parent))
        (alias.parent / 'cycle').symlink_to('libfixture.so.1')
        report['cases'] = []
        for name, destination, accepted, provider in cases:
            paths = [str(target), '/usr/lib/libfixture.so.1']
            if name == 'absolute-alias-first':
                paths.reverse()
            plist.write_text('\n'.join(paths) + '\n')
            alias.unlink(missing_ok=True)
            alias.symlink_to(destination)
            output = work / name; output.mkdir()
            result = run([pkg, '-C', '/dev/null', '-R', repos,
                 '-o', 'PKG_ENABLE_PLUGINS=no', '-o', 'PKG_DBDIR=' + str(work / 'db'),
                 '-o', 'ABI=' + args.abi, 'create', '-r', stage, '-M', manifest,
                 '-p', plist, '-o', output], check=False)
            archive = output / 'stage-elf-fixture-1.pkg'
            case = {'name': name, 'exit': result.returncode, 'expected_accept': accepted}
            report['cases'].append(case)
            if not accepted:
                assert result.returncode != 0, name + ': invalid resolution accepted'
                assert not archive.exists(), name + ': failed package archive retained'
                case['result'] = 'PASS'
                continue
            result.check_returncode()
            package = json.loads(run(['/usr/bin/tar', '-xOf', archive, '+MANIFEST']).stdout)
            # Native libarchive supports pkg's Zstandard compression. Do not
            # extract archive paths to disk.
            listing = run(['/usr/bin/tar', '-tvf', archive]).stdout
            assert '/usr/lib/libfixture.so.1 -> ' + destination in listing, 'archive link changed'
            case['manifest'] = package
            required = set(package.get('shlibs_required', []))
            assert 'libstagemarker.so.1' in required, name + ': staged dependency missing'
            assert 'libhostmarker.so.1' not in required, name + ': ELF inspection escaped stage into host'
            if provider:
                assert 'libfixture.so.1' in package.get('shlibs_provided', []), name + ': alias provider lost'
            case['result'] = 'PASS'
        report['result'] = 'PASS'
    except Exception as error:
        report['result'] = 'FAIL'
        report['error'] = str(error)
        raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
