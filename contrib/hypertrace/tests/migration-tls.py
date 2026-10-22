#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import hashlib
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
for name in ('peer', 'untrusted'):
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes',
        '-keyout', str(out / (name + '.key')), '-out', str(out / (name + '.pem')),
        '-days', '1', '-subj', '/CN=' + name], check=True, capture_output=True)
    (out / (name + '.key')).chmod(0o600)
der = subprocess.check_output(['openssl', 'x509', '-in', str(out / 'peer.pem'),
    '-outform', 'DER'])
(out / 'pin').write_bytes(hashlib.sha256(der).digest())
der = subprocess.check_output(['openssl', 'x509', '-in', str(out / 'untrusted.pem'),
    '-outform', 'DER'])
(out / 'other.pin').write_bytes(hashlib.sha256(der).digest())
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-pthread',
    '-fsanitize=address,undefined', '-I' + str(root / 'usr.sbin/bhyve'),
    str(Path(__file__).with_suffix('.c')), str(root / 'usr.sbin/bhyve/migration_tls.c'),
    str(root / 'usr.sbin/bhyve/migration_session.c'),
    '-lssl', '-lcrypto', '-lz', '-o', str(out / 'tls')], check=True)
subprocess.run([str(out / 'tls')], cwd=out, check=True, timeout=30)
subprocess.run([str(out / 'tls'), '--capsicum'], cwd=out, check=True, timeout=30)
