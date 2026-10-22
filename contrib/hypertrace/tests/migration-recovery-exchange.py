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
for name in ('source', 'destination'):
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes',
        '-keyout', str(out / (name + '.key')), '-out', str(out / (name + '.pem')),
        '-days', '1', '-subj', '/CN=' + name], check=True, capture_output=True)
    (out / (name + '.key')).chmod(0o600)
    der = subprocess.check_output(['openssl', 'x509', '-in', str(out / (name + '.pem')), '-outform', 'DER'])
    (out / (name + '.pin')).write_bytes(hashlib.sha256(der).digest())
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-pthread',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
    '-I' + str(root / 'usr.sbin/bhyve'), str(Path(__file__).with_suffix('.c')),
    str(root / 'usr.sbin/bhyve/migration_tls.c'),
    str(root / 'usr.sbin/bhyve/migration_session.c'),
    '-lmd', '-lssl', '-lcrypto', '-lz', '-o', str(out / 'exchange')], check=True)
subprocess.run([str(out / 'exchange')], cwd=out, check=True, timeout=30)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-pthread',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
    '-I' + str(root / 'usr.sbin/bhyve'), str(Path(__file__).with_name('migration-recovery-execute.c')),
    str(root / 'usr.sbin/bhyve/migration_tls.c'),
    str(root / 'usr.sbin/bhyve/migration_session.c'), '-Wl,--wrap=fsync',
    '-lmd', '-lssl', '-lcrypto', '-lz', '-o', str(out / 'execute')], check=True)
subprocess.run([str(out / 'execute')], cwd=out, check=True, timeout=30)
subprocess.run([str(out / 'execute'), '--capsicum'], cwd=out, check=True, timeout=30)

# Exercise the production restart adapter with actual TLS and executors.
# Only VM/kernel retirement operations are substituted in the fixture.
source = (root / 'usr.sbin/bhyve/migration_session.c').read_text()
start = source.index('int\nmigration_prod_source_finish_intent(')
end = source.index('/* A recovery request cannot replace', start)
(out / 'source-restart.inc').write_text(source[source.index('/* The IPC controller owns this context'):source.index('static int\nprod_retire(')] + source[start:end])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-pthread',
    '-fsanitize=address,undefined', '-DTEST_SOURCE_RESTART',
    '-I' + str(out), '-I' + str(root / 'sys'),
    '-I' + str(root / 'usr.sbin/bhyve'), str(Path(__file__).with_name('migration-recovery-execute.c')),
    str(root / 'usr.sbin/bhyve/migration_tls.c'),
    str(root / 'usr.sbin/bhyve/migration_session.c'), '-Wl,--wrap=fsync',
    '-lmd', '-lssl', '-lcrypto', '-lz', '-o', str(out / 'restart')], check=True)
subprocess.run([str(out / 'restart')], cwd=out, check=True, timeout=30)
subprocess.run([str(out / 'restart'), '--capsicum'], cwd=out, check=True, timeout=30)
