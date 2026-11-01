#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run every installed original base-accounts case in a private disposable guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

SUITE = '/usr/tests/usr.sbin/base-accounts'
PROGRAM = SUITE + '/base_accounts_test'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def listing(text):
    sections = text.strip().split('\n\n')
    if sections.pop(0) != 'Content-Type: application/X-atf-tp; version="1"':
        raise ValueError('invalid original ATF listing header')
    cases = {}
    for section in sections:
        fields = {}
        for line in section.splitlines():
            key, separator, value = line.partition(': ')
            if not separator or key in fields:
                raise ValueError('invalid or duplicate ATF metadata')
            fields[key] = value
        name = fields.get('ident', '')
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,126}', name) or name in cases:
            raise ValueError('invalid or duplicate original case')
        value = fields.get('timeout', '300')  # ATF/Kyua default body deadline.
        if not re.fullmatch(r'[1-9][0-9]{0,3}', value) or int(value) > 3600:
            raise ValueError('invalid original case deadline')
        if fields.get('has.cleanup', 'false') not in ('true', 'false'):
            raise ValueError('invalid original cleanup declaration')
        if fields.get('require.user', '') not in ('', 'unprivileged'):
            raise ValueError('guest suite requires an explicit new identity policy')
        cases[name] = fields
    if not cases:
        raise ValueError('empty original ATF listing')
    return cases


def verify(root, manifest):
    for name, expected in manifest['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative) != name:
            raise ValueError('invalid fixture inventory path: ' + name)
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or digest(path) != expected:
            raise ValueError('fixture content mismatch: ' + name)


def execute(command, directory, timeout, prefix, logs):
    """Retain the group leader until descendant cleanup, avoiding PID reuse."""
    if directory:
        command = ['/bin/sh', '-c', 'cd "$1" && shift && exec "$@"',
                   'base-accounts-guest', directory] + command
    argv = prefix + command
    stdout, stderr = logs.with_suffix('.stdout'), logs.with_suffix('.stderr')
    timed_out = False
    with stdout.open('wb') as out, stderr.open('wb') as err:
        child = subprocess.Popen(argv, stdout=out, stderr=err, start_new_session=True,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'})
        deadline = time.monotonic() + timeout
        try:
            while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                time.sleep(.02)
        finally:
            # WNOWAIT keeps the leader reserved until all group signalling ends.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            status = child.wait()
    return {'argv': argv, 'timeout_seconds': timeout, 'effective_timeout_seconds': timeout,
            'timeout_scale': 1, 'timed_out': timed_out, 'exit_status': status,
            'stdout': stdout.read_text(errors='replace'), 'stderr': stderr.read_text(errors='replace')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'manifest', 'output', 'profile'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('uid', 'gid'):
        parser.add_argument('--' + name, type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0:
        parser.error('private guest root and nonzero test uid/gid required')
    root = args.root.resolve(strict=True)
    if root == Path('/'):
        parser.error('a private prepared guest root is required')
    if json.loads(args.profile.read_text()) != {'timeout_scale': 1}:
        parser.error('this qualification preserves original, unscaled deadlines')
    report = {'status': 'failed', 'scope': 'all original installed base-accounts cases in private guest',
              'uid': args.uid, 'gid': args.gid, 'cases': [], 'timeout_scale': 1}
    logs = args.output.parent / 'base-accounts-logs'
    logs.mkdir()
    try:
        manifest = json.loads(args.manifest.read_text())
        verify(root, manifest)
        prefix = ['/usr/sbin/chroot', '-u', str(args.uid), '-g', str(args.gid),
                  '-G', str(args.gid), str(root)]
        identities = []
        for option, expected in [('-u', args.uid), ('-g', args.gid), ('-G', args.gid)]:
            result = execute(['/usr/bin/id', option], None, 30, prefix, logs / ('id' + option))
            if result['exit_status'] or result['timed_out'] or result['stdout'] != str(expected) + '\n':
                raise ValueError('guest identity transition failed: ' + json.dumps(result))
            identities.append(result)
        report['identity_checks'] = identities
        result = execute([PROGRAM, '-l'], None, 30, prefix, logs / 'listing')
        if result['exit_status'] or result['timed_out']:
            raise ValueError('original ATF listing failed: ' + json.dumps(result))
        cases = listing(result['stdout'])
        report['listing'] = result
        report['original_metadata'] = cases
        for name, metadata in cases.items():
            print('BASE_ACCOUNTS_CASE_BEGIN ' + name, flush=True)
            work = root / 'tmp' / ('base-accounts-' + name)
            work.mkdir(mode=0o700)
            os.chown(work, args.uid, args.gid)
            command = [PROGRAM, '-s', SUITE]
            record = {'name': name, 'metadata': metadata}
            try:
                body = execute(command + ['-r', 'atf.result', name], '/tmp/' + work.name,
                               int(metadata.get('timeout', '300')), prefix, logs / name)
                result_file = work / 'atf.result'
                body['atf_result'] = result_file.read_text() if result_file.is_file() else None
                record['body'] = body
                record['passed'] = (body['exit_status'] == 0 and not body['timed_out'] and
                                    body['atf_result'] is not None and body['atf_result'].strip() == 'passed')
            finally:
                if metadata.get('has.cleanup') == 'true':
                    cleanup = execute(command + [name + ':cleanup'], '/tmp/' + work.name,
                                      300, prefix, logs / (name + '-cleanup'))
                    record['cleanup'] = cleanup
                    record['passed'] = record.get('passed', False) and cleanup['exit_status'] == 0 and not cleanup['timed_out']
                shutil.rmtree(work)
                record['work_removed'] = not work.exists()
                record['passed'] = record.get('passed', False) and record['work_removed']
            report['cases'].append(record)
            print('BASE_ACCOUNTS_CASE_RESULT ' + json.dumps(record), flush=True)
        verify(root, manifest)
        report['fixture_inputs_unchanged'] = True
        report['all_original_cases_attempted'] = [r['name'] for r in report['cases']] == list(cases)
        report['status'] = 'passed' if report['all_original_cases_attempted'] and all(r['passed'] for r in report['cases']) else 'failed'
    except Exception as error:
        report['error'] = str(error)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('BASE_ACCOUNTS_REPORT_BEGIN\n' + json.dumps(report) + '\nBASE_ACCOUNTS_REPORT_END', flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
