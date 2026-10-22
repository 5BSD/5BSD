#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/dev/dttransport/dttransport.c').read_text()
a = source.index('static struct sx dtt_transport_lock;')
b = source.index('\n/*\n * cdevsw', a)
(out / 'registration.inc').write_text(source[a:b])
subprocess.run(['cc', '-pthread', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(out), '-I' + str(root / 'sys'),
    str(Path(__file__).with_name('transport-registration.c')),
    '-o', str(out / 'transport-registration-test')], check=True)
subprocess.run([str(out / 'transport-registration-test')], check=True, timeout=30)
# The transport is a provider; it must not depend on its driver client.
assert 'MODULE_DEPEND(dttransport, virtio_dtrace' not in source
assert 'virtio_dtrace_enqueue' not in source
