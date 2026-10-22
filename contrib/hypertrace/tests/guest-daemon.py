#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/dtraced/dtraced_dttransport.cc').read_text()
process = (root / 'usr.sbin/dtraced/dtraced_process.cc').read_text()
a = source.index('struct dtt_elf_state {')
b = source.index('\nstatic bool\ndtt_kill', a)
c = source.index('void\nwrite_dttransport(')
d = source.index('\n}', c) + 2
e = source.index('static int\ndtt_wait_socket(')
f = source.index('\n}', e) + 2
g = process.index('bool\nhandle_host_observation(')
h = process.index('\n}', g) + 2
(out / 'guest-daemon.inc').write_text(source[a:b] + source[e:f] +
    source[c:d] + process[g:h])
subprocess.run(['c++', '-std=c++17', '-pthread', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'usr.sbin/dtraced'), '-I' + str(root / 'sys/dev/dttransport'),
    '-idirafter', str(root / 'sys'),
    str(Path(__file__).with_name('guest-daemon.cc')), '-lcrypto',
    '-o', str(out / 'guest-daemon-test')], check=True)
subprocess.run([str(out / 'guest-daemon-test')], check=True, timeout=30)
