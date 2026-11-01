#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run the complete native makefs ATF inventory inside an explicit private guest root."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess


def listing(text):
    sections = text.strip().split('\n\n')
    if sections.pop(0) != 'Content-Type: application/X-atf-tp; version="1"':
        raise ValueError('invalid ATF listing content type')
    cases = {}
    for section in sections:
        fields = {}
        for line in section.splitlines():
            key, separator, value = line.partition(': ')
            if not separator or key in fields:
                raise ValueError('malformed or duplicate ATF field')
            fields[key] = value
        name = fields.get('ident', '')
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,126}', name) or name in cases:
            raise ValueError('invalid or duplicate ATF case')
        timeout = fields.get('timeout', '300')
        if not re.fullmatch(r'[1-9][0-9]{0,3}', timeout) or int(timeout) > 3600:
            raise ValueError('invalid declared ATF timeout')
        if fields.get('has.cleanup', 'false') not in ('true', 'false'):
            raise ValueError('invalid declared ATF cleanup')
        cases[name] = fields
    if not cases:
        raise ValueError('empty ATF listing')
    return cases


def reconcile(suite, actual):
    expected = suite['cases']
    if len(set(expected)) != len(expected) or set(expected) != set(actual):
        raise ValueError('native inventory differs from complete original ATF listing')
    if set(suite['source_skips']) - set(expected):
        raise ValueError('skip declaration for missing case')
    if suite['policy'].get('required_user') != 'root':
        raise ValueError('preserve installed suite root requirement')


def require_programs(root, names):
    paths, missing = {}, []
    for name in names:
        if not name or name in ('.','..') or '/' in name or any(c.isspace() for c in name):
            raise ValueError('invalid runtime program basename')
        for directory in ['sbin','bin','usr/sbin','usr/bin']:
            candidate=root/directory/name
            if candidate.is_file() and candidate.resolve().is_relative_to(root) and candidate.stat().st_mode & 0o111:
                paths[name]='/'+directory+'/'+name
                break
        else:
            missing.append(name)
    if missing:
        raise ValueError('unsupported fixture: declared runtime programs missing: '+', '.join(missing))
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['root', 'manifest', 'inventory', 'output']:
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if os.geteuid() != 0 or root == Path('/'):
        parser.error('a private disposable guest root and guest root privileges are required')
    for name, digest in json.loads(args.manifest.read_text())['files'].items():
        relative = Path(name)
        path = (root / relative).resolve(strict=True)
        if (relative.is_absolute() or '..' in relative.parts or str(relative) != name or
                not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError('fixture input content/path mismatch: '+name)
    inventory = json.loads(args.inventory.read_text())
    if inventory.get('format') != 1 or not inventory.get('suites'):
        raise ValueError('native suite inventory format1 required')
    prefix = ['/usr/sbin/chroot', '-u', '0', '-g', '0', '-G', '0', str(root)]
    report = {'status':'RUNNING','cases':[], 'suite_listings':{}, 'setup':{}, 'limitations':[
        'explicit execution kernel/module bootstrap, not native kernel qualification',
        'disposable fixture PID1, not normal Capsule startup or complete pkgbase system',
        'resource samples are not controlled performance comparisons']}
    environment = {'PATH':'/sbin:/bin:/usr/sbin:/usr/bin', 'LC_ALL':'C',
                   'HOME':'/root', 'SHELL':'/bin/zsh', 'TMPDIR':'/tmp'}

    def invoke(command, directory=None, timeout=30, tmpdir=None):
        if directory:
            command = ['/bin/sh','-c','cd "$1" && shift && exec "$@"','makefs-runtime',directory]+command
        env = dict(environment)
        if tmpdir:
            env['TMPDIR'] = tmpdir
        try:
            child = subprocess.Popen(prefix+command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=env, start_new_session=True)
            try:
                stdout, stderr = child.communicate(timeout=timeout)
                status = child.returncode
            except subprocess.TimeoutExpired:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                stdout, stderr = child.communicate()
                status = 124
            return {'status':status, 'stdout':stdout.decode(errors='replace'),
                    'stderr':stderr.decode(errors='replace')}
        except OSError as error:
            return {'status':125,'stdout':'','stderr':str(error)}

    def snapshot():
        result = {}
        for name, command in [('md',['/sbin/mdconfig','-l']),('mounts',['/sbin/mount','-p']),
                              ('pools',['/sbin/zpool','list','-H','-o','name'])]:
            item = invoke(command)
            if item['status'] != 0 and not (name == 'pools' and item['status'] == 1 and
                    not item['stdout'] and 'no pools available' in item['stderr']):
                raise ValueError('cannot inventory guest '+name+': '+str(item))
            result[name] = sorted(item['stdout'].splitlines())
        return result

    def save():
        args.output.write_text(json.dumps(report,indent=2)+'\n')

    try:
        # Use the standard source-owned account data and native database builder.
        database = invoke(['/usr/sbin/pwd_mkdb','-p','-d','/etc','/etc/master.passwd'])
        report['setup']['account_database'] = database
        if database['status']:
            raise ValueError('native standard account database generation failed')
        for name in ['var/run','var/log','var/db','etc/zfs','root']:
            (root/name).mkdir(parents=True,exist_ok=True)
        account = next(line.split(':') for line in (root/'etc/master.passwd').read_text().splitlines() if line.startswith('tests:'))
        transition = invoke(['/usr/bin/su','-m','tests','-c','/usr/bin/id -u'])
        report['setup']['native_su_tests_identity'] = transition
        if transition['status'] or transition['stdout'] != account[2]+'\n':
            raise ValueError('native su/PAM/default shell failed standard tests-account identity transition')
        baseline = snapshot()
        report['setup']['baseline'] = baseline
        # Reconcile every suite before executing any body; omitted cases are errors.
        for name, suite in inventory['suites'].items():
            item = invoke([suite['program'],'-l'])
            if item['status']:
                raise ValueError('ATF listing failed: '+name+': '+str(item))
            actual = listing(item['stdout'])
            reconcile(suite,actual)
            report['suite_listings'][name] = actual
            for path in suite['policy'].get('required_files','').split():
                if not (root/path.lstrip('/')).is_file():
                    raise ValueError('missing installed suite requirement: '+path)
            for module in suite['policy'].get('required_kmods','').split():
                check=invoke(['/sbin/kldstat','-m',module])
                if check['status']:
                    raise ValueError('missing suite kernel module requirement: '+module+': '+str(check))
        requirements=set(inventory['required_programs'])
        for cases in report['suite_listings'].values():
            for fields in cases.values():
                requirements.update(fields.get('require.progs','').split())
        report['setup']['runtime_programs']=require_programs(root,sorted(requirements))
        save()
        for name,suite in inventory['suites'].items():
            for case in suite['cases']:
                fields = report['suite_listings'][name][case]
                directory = '/tmp/'+name+'-'+case
                work = root/directory.lstrip('/')
                work.mkdir(mode=0o755)
                base = [suite['program'],'-s','/usr/tests/usr.sbin/makefs']
                record = {'suite':name,'case':case,'metadata':fields,'state':'FAIL'}
                before = snapshot()
                print('MAKEFS_CASE_START '+name+':'+case,flush=True)
                try:
                    body=invoke(base+['-r','atf.result',case],directory,int(fields.get('timeout','300')),directory)
                    record['body']=body
                    result=(work/'atf.result').read_text().strip() if (work/'atf.result').is_file() else ''
                    record['atf_result']=result
                    if body['status']==0 and result=='passed':
                        record['state']='PASS'
                    elif body['status']==0 and result.startswith('skipped: '):
                        reason=result.removeprefix('skipped: ')
                        record['state']='SKIP' if suite['source_skips'].get(case)==reason else 'UNEXPECTED_SKIP'
                finally:
                    if fields.get('has.cleanup','false')=='true':
                        cleanup=invoke(base+['-r','cleanup.result',case+':cleanup'],directory,int(fields.get('timeout','300')),directory)
                        record['cleanup']=cleanup
                        if cleanup['status']:
                            record['state']='FAIL'
                    after=snapshot()
                    record['restored_inventory']=after==before==baseline
                    if not record['restored_inventory']:
                        record['state']='FAIL';record['before']=before;record['after']=after
                    report['cases'].append(record)
                    save()
                print('MAKEFS_CASE_'+record['state']+' '+name+':'+case,flush=True)
                if record['state'] in ['PASS','SKIP']:
                    shutil.rmtree(work)
                if not record['restored_inventory']:
                    raise ValueError('guest device/mount/pool inventory not restored; refusing contaminated later cases')
        counts=dict(collections.Counter(item['state'] for item in report['cases']))
        expected=sum(len(s['cases']) for s in inventory['suites'].values())
        report['counts']=counts
        report['expected_cases']=expected
        report['status']=('COMPLETE_WITH_SOURCE_SKIPS' if counts.get('SKIP') else 'PASS') if len(report['cases'])==expected and all(item['state'] in ['PASS','SKIP'] for item in report['cases']) else 'FAIL'
    except BaseException as error:
        report['status']='FAIL';report['error']=str(error)
    finally:
        save()
    print(json.dumps({'status':report['status'],'counts':report.get('counts',{}),'report':str(args.output)}),flush=True)
    return 0 if report['status'] in ['PASS','COMPLETE_WITH_SOURCE_SKIPS'] else 1

if __name__=='__main__':raise SystemExit(main())
