#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
parts = []
for path, signature in [('sys/net/if_tuntap.c', 'static\tint\ntunwrite('),
    ('usr.sbin/bhyve/net_backends.c', 'static int\ntap_tagging_enable('),
    ('usr.sbin/bhyve/net_backends.c', 'static int\ntap_tagging_enable_v2('),
    ('usr.sbin/bhyve/net_backends.c', 'static int\ntap_tagging_disable('),
    ('usr.sbin/bhyve/net_backends.c', 'int\nnetbe_tagging_disable('),
    ('usr.sbin/bhyve/net_backends.c', 'int\nnetbe_tagging_v2_supported('),
    ('usr.sbin/bhyve/net_backends.c', 'int\nnetbe_tagging_enable_v2('),
    ('usr.sbin/bhyve/net_backends.c', 'static int\ntap_probe_id_bytes('),
    ('usr.sbin/bhyve/net_backends.c', 'static int\ntap_probe_mbufid('),
    ('usr.sbin/bhyve/net_backends.c', 'static int\ntap_probe_mbufid_v2('),
    ('usr.sbin/bhyve/net_backends.c', 'ssize_t\ntap_send('),
    ('usr.sbin/bhyve/net_backends.c', 'ssize_t\ntap_recv('),
    ('sys/kern/subr_mbufid.c', 'void\nmbufid_generate('),
    ('sys/kern/subr_mbufid.c', 'int\nmbufid_isvalid('),
    ('sys/kern/subr_sglist.c', 'int\nsglist_append_mbuf_with_id(')]:
    s = (root / path).read_text(); a = s.index(signature); b = s.index('\n}', a) + 2
    parts.append(s[a:b])
(out / 'packet-provenance.inc').write_text('\n'.join(parts))
crypto = (root / 'sys/kern/uipc_mbuf.c').read_text()
parts = []
for signature in ('static uint64_t\nmbufid_v2_mac(',
                  'int\nmbufid_v2_stamp(',
                  'int\nmbufid_v2_verify('):
    a = crypto.index(signature); b = crypto.index('\n}', a) + 2
    parts.append(crypto[a:b])
(out / 'packet-v2-auth.inc').write_text('\n\n'.join(parts) + '\n')
siphash = out / 'siphash.o'
subprocess.run(['cc', '-std=gnu17', '-Werror', '-Wno-incompatible-library-redeclaration',
    '-Wno-implicit-function-declaration', '-include', 'stdbool.h',
    '-I' + str(root / 'sys'), '-c', str(root / 'sys/crypto/siphash/siphash.c'),
    '-o', str(siphash)], check=True)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-fsanitize=address,undefined',
    '-I' + str(out), '-I' + str(root / 'sys'), str(Path(__file__).with_suffix('.c')),
    str(siphash), '-o', str(out / 'packet-provenance')], check=True)
subprocess.run([str(out / 'packet-provenance')], check=True, timeout=30)
