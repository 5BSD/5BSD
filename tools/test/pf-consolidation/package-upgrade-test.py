#!/usr/bin/env python3
"""Exercise IPFW package retirement in a fresh, unprivileged pkg root.

This uses small fixture packages and the production rc package scripts.
It does not replace qualification of a complete repository in a booted VM.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='new evidence directory')
    parser.add_argument('--pkg', default='/usr/local/sbin/pkg-static')
    parser.add_argument('--flua', default='/usr/libexec/flua')
    parser.add_argument('--source', type=Path,
                        default=Path(__file__).resolve().parent.parent.parent.parent)
    args = parser.parse_args()
    base = args.directory.resolve()
    base.mkdir()  # Never reuse a package database or overwrite previous evidence.
    root, repos, old, repo = (base / n for n in ('root', 'repos', 'old', 'repo'))
    for directory in (root, repos, old, repo):
        directory.mkdir()
    env = os.environ.copy()
    env['INSTALL_AS_USER'] = 'yes'
    config = base / 'pkg.conf'
    config.write_text('RUN_SCRIPTS: true\nSYSLOG: false\nPKG_ENABLE_PLUGINS: false\n')
    log = (base / 'commands.log').open('w')

    def run(command):
        log.write(repr(command) + '\n')
        log.flush()
        proc = subprocess.run(command, env=env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        log.write(proc.stdout)
        log.flush()
        if proc.returncode:
            raise RuntimeError(f'{command}: exit {proc.returncode}; see {log.name}')
        return proc.stdout

    lua = ('local ucl=require("ucl"); local p=ucl.parser(); '
           'assert(p:parse_file(arg[1])); '
           'print(ucl.to_format(p:get_object(), "json", true))')
    lua_file = base / 'read-manifest.lua'
    lua_file.write_text(lua)
    rc = json.loads(run([args.flua, str(lua_file),
                        str(args.source / 'packages/rc/rc.ucl')]))

    def create(name, version, files, dependencies, output, scripts=None):
        stage = base / (name + '-' + version)
        stage.mkdir()
        for file in files:
            path = stage / file.lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name + ' ' + version + '\n')
        manifest = {
            'name': name, 'version': version, 'origin': 'base/' + name,
            'comment': 'PF package retirement regression fixture',
            'desc': 'Temporary package-root fixture only.',
            'maintainer': 'test@example.invalid', 'www': 'https://example.invalid',
            'prefix': '/', 'files': {file: '-' for file in files},
            'config': [file for file in files if file.startswith('/etc/')],
            'deps': {n: {'origin': 'base/' + n, 'version': v}
                     for n, v in dependencies.items()},
        }
        if scripts:
            manifest['scripts'] = scripts
        path = stage / 'manifest.json'
        path.write_text(json.dumps(manifest))
        run([args.pkg, '-C', str(config), 'create', '-M', str(path),
             '-r', str(stage), '-o', str(output)])

    create('5BSD-ipfw', '1', ['/sbin/ipfw', '/sbin/dnctl',
           '/etc/rc.d/ipfw', '/etc/rc.d/dnctl'], {}, old)
    create('5BSD-fixture-rc', '1', ['/etc/rc.firewall'], {}, old)
    create('5BSD-fixture-set', '1', [],
           {'5BSD-ipfw': '1', '5BSD-fixture-rc': '1'}, old)
    create('5BSD-dummynet', '2', ['/sbin/dnctl', '/etc/rc.d/dnctl'], {}, repo)
    create('5BSD-fixture-rc', '2', ['/etc/rc'], {}, repo, rc['scripts'])
    create('5BSD-fixture-set', '2', [],
           {'5BSD-dummynet': '2', '5BSD-fixture-rc': '2'}, repo)
    run([args.pkg, '-C', str(config), 'repo', str(repo)])
    (repos / 'fixture.conf').write_text(
        'fixture: {url: ' + json.dumps('file://' + str(repo.resolve())) +
        ', enabled: yes, signature_type: "none"}\n')
    cmd = [args.pkg, '-r', str(root), '-C', str(config), '-R', str(repos)]
    run(cmd + ['add'] + [str(old / (n + '-1.pkg')) for n in
                        ('5BSD-ipfw', '5BSD-fixture-rc', '5BSD-fixture-set')])
    policy = '# Customized administrator rc.firewall canary\n'
    unmanaged = '# PF upgrade policy preservation canary\n'
    previous = 'Existing backup must survive\n'
    (root / 'etc/rc.firewall').write_text(policy)
    (root / 'etc/ipfw.rules').write_text(unmanaged)
    (root / 'etc/rc.firewall.pkgsave.previous').write_text(previous)
    run(cmd + ['update', '-f'])
    run(cmd + ['upgrade', '-y'])
    run(cmd + ['check', '-d', '-a'])
    installed = run(cmd + ['query', '%n %v']).splitlines()
    backups = [f for f in (root / 'etc').glob('rc.firewall.pkgsave.*')
               if f.name != 'rc.firewall.pkgsave.previous']
    checks = {
        'dummynet_installed': '5BSD-dummynet 2' in installed,
        'ipfw_package_absent': not any(n.startswith('5BSD-ipfw ') for n in installed),
        'ipfw_files_absent': not any((root / f).exists() for f in
                                    ('sbin/ipfw', 'etc/rc.d/ipfw')),
        'retired_config_absent': not (root / 'etc/rc.firewall').exists(),
        'policy_saved': len(backups) == 1 and backups[0].read_text() == policy,
        'existing_backup_untouched':
            (root / 'etc/rc.firewall.pkgsave.previous').read_text() == previous,
        'unmanaged_policy_untouched': (root / 'etc/ipfw.rules').read_text() == unmanaged,
    }
    fresh = base / 'fresh-root'
    fresh.mkdir()
    run([args.pkg, '-r', str(fresh), '-C', str(config), '-R', str(repos),
         'add', str(repo / '5BSD-fixture-rc-2.pkg')])
    checks['fresh_install_no_backup'] = not list(
        (fresh / 'etc').glob('rc.firewall.pkgsave.*'))
    report = {'passed': all(checks.values()), 'checks': checks,
              'scope': 'Synthetic package transition; complete VM upgrade still required.'}
    (base / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
