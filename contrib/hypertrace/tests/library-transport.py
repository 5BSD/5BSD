#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
lib = root / 'cddl/contrib/opensolaris/lib/libdtrace/common'
source = (lib / 'dt_subr.c').read_text()
a = source.index('static int\ndtraced_self_procdesc(')
b = source.index('\nint\ndtrace_oformat_configure', a)
c = source.index('int\ndtrace_program_source_id(', b)
d = source.index('\nint\ndtrace_program_compiled_digest(', c)
e = source.index('\nstatic int\ndtrace_send_elf_impl(', d)
f = source.index('\nvoid\ndtrace_enable_hypertrace', e)
(out / 'library-transport.inc').write_text(
    source[a:b] + source[c:d] + source[e:f])
subprocess.run(['cc', '-pthread', '-Wall', '-Wextra', '-Werror', '-Wno-unknown-pragmas',
    '-fsanitize=address,undefined', '-include', str(root / 'contrib/hypertrace/tests/consumer-birth-mock.h'), '-I' + str(out), '-I' + str(lib),
    '-I' + str(root / 'usr.sbin/dtraced'), '-I' + str(root / 'sys'), str(lib / 'dt_list.c'),
    str(Path(__file__).with_name('library-transport.c')), '-o',
    str(out / 'library-transport-test'), '-lcrypto'], check=True)
subprocess.run([str(out / 'library-transport-test')], check=True, timeout=30)
