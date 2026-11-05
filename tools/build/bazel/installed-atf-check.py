#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Execute explicit installed ATF programs inside a private prepared guest root."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pty
import re
import signal
import subprocess


def absolute(value):
    if not isinstance(value, str) or not value.startswith('/') or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('absolute installed path required')
    path = PurePosixPath(value)
    if str(path) != value or any(p in ('.', '..') for p in path.parts):
        raise ValueError('canonical installed path required')
    return value


def validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != {'format', 'programs'} or type(plan['format']) is not int or plan['format'] != 1:
        raise ValueError('versioned installed ATF plan required')
    if not isinstance(plan['programs'], list) or not plan['programs']:
        raise ValueError('nonempty explicit program inventory required')
    seen = set()
    for entry in plan['programs']:
        if not isinstance(entry, dict) or set(entry) != {'path', 'case_user', 'stdin_tty_cases'}:
            raise ValueError('program requires path, case_user and stdin_tty_cases')
        path = absolute(entry['path'])
        if not path.startswith('/usr/tests/') or path in seen:
            raise ValueError('unique installed test program required')
        seen.add(path)
        if entry['case_user'] not in ('all', 'root', 'unprivileged'):
            raise ValueError('invalid case user selection')
        tty = entry['stdin_tty_cases']
        if not isinstance(tty, list) or any(not isinstance(c, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', c) for c in tty) or len(set(tty)) != len(tty):
            raise ValueError('distinct terminal case identifiers required')
    return plan


def parse_listing(text):
    blocks = text.strip().split('\n\n')
    if blocks.pop(0) != 'Content-Type: application/X-atf-tp; version="1"':
        raise ValueError('invalid ATF content type')
    result = {}
    for block in blocks:
        fields = {}
        for line in block.splitlines():
            key, sep, value = line.partition(': ')
            if not sep or key in fields:
                raise ValueError('invalid or duplicate ATF metadata')
            fields[key] = value
        name = fields.get('ident', '')
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', name) or name in result:
            raise ValueError('invalid or duplicate ATF case')
        timeout = fields.get('timeout', '300')
        if not re.fullmatch(r'[1-9][0-9]{0,3}', timeout) or int(timeout) > 3600:
            raise ValueError('invalid ATF deadline')
        if fields.get('has.cleanup', 'false') not in ('true', 'false') or fields.get('require.user', '') not in ('', 'root', 'unprivileged'):
            raise ValueError('unsupported ATF cleanup/user contract')
        result[name] = fields
    if not result:
        raise ValueError('empty ATF program')
    return result


def case_outcome(text):
    if text == 'passed':
        return 'passed'
    match = re.fullmatch(r'(expected_failure|skipped): ([^\x00-\x1f\x7f]+)', text)
    return match[1] if match else 'failed'


def run_process(command, environment, terminal=False, timeout=300):
    master = slave = None
    try:
        if terminal:
            master, slave = pty.openpty()
        process = subprocess.Popen(command, env=environment,
            stdin=slave if terminal else subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            stdout, stderr = process.communicate()
            return subprocess.CompletedProcess(command,124,stdout,stderr+b'\nphase timeout')
        finally:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
    finally:
        if slave is not None: os.close(slave)
        if master is not None: os.close(master)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['root', 'manifest', 'plan', 'output']:
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ['uid', 'gid']:
        parser.add_argument('--'+name, type=int, required=True)
    a = parser.parse_args()
    root = a.root.resolve(strict=True)
    if os.geteuid() != 0 or root == Path('/') or a.uid <= 0 or a.gid <= 0:
        parser.error('private guest root and explicit nonzero test identity required')
    plan = validate_plan(json.loads(a.plan.read_text()))
    inventory = json.loads(a.manifest.read_text())
    for name, expected in inventory['files'].items():
        path = (root / name).resolve(strict=True)
        if Path(name).is_absolute() or '..' in Path(name).parts or not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('fixture content mismatch: '+name)
    results = []
    environment = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C', 'DTRACE_DOF_INIT_DISABLE':'1'}

    def execute(command, privileged=False, terminal=False, timeout=300):
        uid, gid = (0, 0) if privileged else (a.uid, a.gid)
        prefix = ['/usr/sbin/chroot','-u',str(uid),'-g',str(gid),'-G',str(gid),str(root)]
        return run_process(prefix+command, environment, terminal, timeout)

    for opt, expected in [('-u', a.uid), ('-g', a.gid), ('-G', a.gid)]:
        value = execute(['/usr/bin/id',opt]);results.append(dict(name='identity '+opt,passed=value.returncode==0 and value.stdout==f'{expected}\n'.encode(),accepted=value.returncode==0 and value.stdout==f'{expected}\n'.encode()))
    for entry in plan['programs']:
        program = entry['path'];listing = execute([program,'-l'])
        if listing.returncode:
            raise RuntimeError('ATF listing failed: '+program+': '+listing.stderr.decode(errors='replace'))
        cases = parse_listing(listing.stdout.decode());selected = [(c,m) for c,m in cases.items() if entry['case_user']=='all' or (m.get('require.user')=='root')==(entry['case_user']=='root')]
        if not selected or not set(entry['stdin_tty_cases']) <= set(cases):
            raise ValueError('empty or inconsistent selected case inventory: '+program)
        for case, metadata in selected:
            private = metadata.get('require.user') == 'root';uid,gid=(0,0) if private else (a.uid,a.gid)
            work = root/'tmp'/('atf-'+str(len(results)));work.mkdir();os.chown(work,uid,gid);work.chmod(0o700)
            result_file = work/'result';args=['/usr/libexec/atf-cwd-exec','/tmp/'+work.name,program,'-s',str(PurePosixPath(program).parent),'-r','result']
            body = execute(args+[case],private,case in entry['stdin_tty_cases'],int(metadata.get('timeout','300')))
            outcome = result_file.read_text().strip() if result_file.is_file() else 'missing result'
            cleanup = execute(args+[case+':cleanup'],private,case in entry['stdin_tty_cases']) if metadata.get('has.cleanup')=='true' else None
            status=case_outcome(outcome)
            phases_ok=body.returncode==0 and (cleanup is None or cleanup.returncode==0)
            if not phases_ok: status='failed'
            results.append(dict(name=program+':'+case,required_user=metadata.get('require.user',''),outcome=outcome,status=status,
                passed=phases_ok and status=='passed', accepted=phases_ok and status in ('passed','expected_failure'),
                exit=body.returncode,cleanup_exit=cleanup.returncode if cleanup else None,
                stdout=body.stdout.decode(errors='backslashreplace'),stderr=body.stderr.decode(errors='backslashreplace')))
    counts={}
    for item in results:
        if 'status' in item: counts[item['status']]=counts.get(item['status'],0)+1
    report=dict(accepted=bool(results) and all(v['accepted'] for v in results),case_counts=counts,checks=results,
        scope='Explicit installed ATF programs/cases inside private guest root; bootstrap kernel/loader/Python are separate inputs.')
    a.output.write_text(json.dumps(report,indent=2)+'\n')
    return 0 if report['accepted'] else 1


if __name__=='__main__':
    raise SystemExit(main())
