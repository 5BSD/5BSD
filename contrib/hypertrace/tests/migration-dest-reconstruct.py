#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual production reconstruction adapter with real journals and real TLS.

Extracts the destination owner, resume adapter and owner/recovery/reconstruct
functions from migration_session.c. VM primitives and the kernel retirement
witness are substituted. No VM, device, module or daemon is used.
"""
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
source = (root / 'usr.sbin/bhyve/migration_session.c').read_text()
structure = source[source.index('struct migration_prod_dest {'):source.index('static int\nprod_dest_local_hello(')]
resume = source[source.index('static int\nprod_dest_resume('):source.index('static int\nprod_prepare_commit(')]
def strip_resolution(text):
    """Drop the operator-resolution section (migrate_resolve IPC, the
    resolution wait and its notification); this fixture does not model IPC."""
    a = text.find('/*\n * Operator resolution of a retained inbound migration')
    if a < 0:
        return text
    end = 'IPC_COMMAND(migrate_resolve, vm_do_migrate_resolve);\n'
    return text[:a] + text[text.index(end, a) + len(end):]


functions = source[source.index('static void\nprod_dest_retain('):source.index('int\nmigration_prod_source_finish_intent(')]
functions = strip_resolution(functions)
for required in ('prod_dest_preserve(', 'migration_prod_dest_reconstruct_begin(',
                 'migration_prod_dest_reconstruct_prepared(', 'prod_dest_image_retire('):
    if required not in functions:
        raise SystemExit('production extraction lost ' + required)
(out / 'dest-reconstruct.inc').write_text(structure + resume + functions)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-pthread',
    '-fsanitize=address,undefined', '-I' + str(out), '-I' + str(root / 'sys'),
    '-I' + str(root / 'usr.sbin/bhyve'), '-I' + str(Path(__file__).parent),
    str(Path(__file__).with_suffix('.c')),
    str(root / 'usr.sbin/bhyve/migration_tls.c'),
    str(root / 'usr.sbin/bhyve/migration_session.c'),
    '-lmd', '-lssl', '-lcrypto', '-lz', '-o', str(out / 'reconstruct')], check=True)
subprocess.run([str(out / 'reconstruct')], cwd=out, check=True, timeout=120)
subprocess.run([str(out / 'reconstruct'), '--capsicum'], cwd=out, check=True, timeout=120)
