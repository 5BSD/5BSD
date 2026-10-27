#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise deletion failures against an explicit pkg binary and temporary DB."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pkg', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('requires an unprivileged user for permission-denial checks')
    pkg = args.pkg.resolve(strict=True)
    cases = []
    for kind in ('denied', 'ordinary', 'missing', 'upgrade-denied'):
        with tempfile.TemporaryDirectory(prefix='pkg-removal-') as temp:
            root = Path(temp)
            for name in ('db', 'repos', 'files'):
                (root/name).mkdir()
            files = root/'files'; payload = files/'payload'
            payload.write_text('fixture\n')
            name = 'removal-fixture'
            manifest = dict(name=name, origin='test/'+name, version='1',
                maintainer='test', categories=['test'], comment='isolated fixture',
                www='https://example.invalid', prefix=str(files), abi='*',
                desc='isolated fixture', files={str(payload):''})
            mf = root/'manifest.json'; mf.write_text(json.dumps(manifest))
            env = dict(PATH='/bin:/usr/bin:/sbin:/usr/sbin', INSTALL_AS_USER='yes',
                PKG_DBDIR=str(root/'db'), PKG_CACHEDIR=str(root/'cache'),
                PKG_ENABLE_PLUGINS='false', PKG_TRIGGERS_ENABLE='false',
                RUN_SCRIPTS='false', HANDLE_RC_SCRIPTS='false',
                REPO_AUTOUPDATE='false', SYSLOG='false', NO_TICK='yes')
            commands = []
            def run(argv):
                p = subprocess.run([str(pkg), '-C', '/dev/null', '-R', str(root/'repos'), *argv],
                    env=env, capture_output=True, text=True, timeout=30)
                commands.append(dict(argv=argv, exit=p.returncode, stdout=p.stdout, stderr=p.stderr))
                return p
            registered = run(['register', '-M', str(mf)])
            if registered.returncode or run(['query','%n']).stdout.strip() != name:
                raise RuntimeError('fixture registration failed: '+repr(commands))
            archive = None
            if kind == 'upgrade-denied':
                replacement = dict(manifest, version='2', files={})
                new_manifest = root/'replacement.json'
                new_manifest.write_text(json.dumps(replacement))
                if run(['create', '-M', str(new_manifest), '-o', str(root)]).returncode:
                    raise RuntimeError('replacement archive creation failed: '+repr(commands))
                archive = root/(name+'-2.pkg')
                if not archive.is_file():
                    raise RuntimeError('replacement archive missing')
            if kind in ('denied', 'upgrade-denied'): files.chmod(0o500)
            if kind == 'missing': payload.unlink()
            try:
                result = (run(['install', '-y', '--local-only', str(archive)]) if archive is not None
                          else run(['delete','-y',name]))
                after = run(['query','%n-%v'])
                present = payload.exists(); recorded = name+'-1' in after.stdout.splitlines()
            finally:
                files.chmod(0o700)
            passed = ((result.returncode != 0 and present and recorded) if kind in ('denied', 'upgrade-denied')
                      else (result.returncode == 0 and not present and not recorded))
            cases.append(dict(case=kind, passed=passed, payload_present=present,
                              package_recorded=recorded, commands=commands))
    report = dict(scope='native isolated package deletion; not BIP or transaction atomicity',
        pkg_sha256=hashlib.sha256(pkg.read_bytes()).hexdigest(), cases=cases,
        result='PASS' if all(c['passed'] for c in cases) else 'FAIL')
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(report['result'])
    raise SystemExit(0 if report['result']=='PASS' else 1)


if __name__ == '__main__':
    main()
