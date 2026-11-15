# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Exercise default TLS trust and local CA lifecycle inside an owned guest."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shlex
import uuid

MARKERS = ['BQL_TLS_UNTRUSTED_REJECTED', 'BQL_TLS_LOCAL_CA_ACCEPTED',
           'BQL_TLS_REMOVED_CA_REJECTED', 'BQL_TLS_ORIGINAL_BUNDLE_RESTORED']


def absolute(value):
    if (not isinstance(value, str) or value == '/' or not value.startswith('/')
            or value.startswith('//') or str(PurePosixPath(value)) != value
            or '..' in PurePosixPath(value).parts
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('canonical nonroot certificate policy path required')
    return value


def load(path, report):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    policy = json.loads(data)
    fields = {'format', 'openssl', 'certctl', 'fetch', 'bundle', 'local_directory',
              'port', 'deadline_seconds'}
    if set(policy) != fields or type(policy['format']) is not int or policy['format'] != 1:
        raise ValueError('exact format-1 certificate runtime policy required')
    for key in ('openssl', 'certctl', 'fetch', 'bundle', 'local_directory'):
        absolute(policy[key])
    for key in ('openssl', 'certctl', 'fetch', 'bundle'):
        if policy[key] not in report['payload_sha256']:
            raise ValueError('certificate runtime input absent from image: ' + key)
    if type(policy['port']) is not int or not 1024 <= policy['port'] <= 65535:
        raise ValueError('explicit nonprivileged local TLS port required')
    if type(policy['deadline_seconds']) is not int or not 1 <= policy['deadline_seconds'] <= 600:
        raise ValueError('bounded certificate phase deadline required')
    script = Path(__file__).with_name('certificate-store.sh')
    return dict(policy=policy, policy_bytes=data, script=script,
                bindings={str(path): hashlib.sha256(data).hexdigest(),
                          str(script): hashlib.sha256(script.read_bytes()).hexdigest()})


def exercise(loaded, invoke, output, user, uid):
    policy = loaded['policy']
    work = '/tmp/.bql-certificate-' + uuid.uuid4().hex
    q = shlex.quote
    invoke('certificate-work', '/bin/mkdir -m 700 ' + q(work))
    try:
        invoke('certificate-script-upload', 'umask 077; /bin/cat > ' + q(work + '/probe.sh'), loaded['script'])
        args = [policy[key] for key in ('openssl', 'certctl', 'fetch', 'bundle', 'local_directory')]
        args += [str(policy['port']), user, str(uid), work]
        transcript = invoke('certificate-default-trust', '/bin/sh ' + q(work + '/probe.sh') + ' ' + ' '.join(map(q, args)))
        markers = [line for line in transcript.decode().splitlines() if line.startswith('BQL_TLS_')]
        if markers != MARKERS:
            raise ValueError('incomplete or out-of-order certificate runtime evidence')
        result = dict(status='passed', checks=markers,
                      transcript_sha256=hashlib.sha256(transcript).hexdigest(),
                      user=user, uid=uid, bundle=policy['bundle'],
                      scope='Ordinary-user fetch default TLS verification, normal local-CA add/rehash/removal and original bundle-byte restoration; owned guest loopback, not external public TLS or Secure Boot')
        (output / 'certificate-proof.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    finally:
        invoke('certificate-work-cleanup', '/bin/rm -rf -- ' + q(work))
