#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Test actual map and provider-table code with userspace allocation/lock stubs."""
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/dev/hypertrace/hypertrace_map.c').read_text()
(out / 'map.inc').write_text('\n'.join(line for line in source.splitlines()
                                    if not line.startswith('#include')))
source = (root / 'sys/cddl/dev/hypertrace/hypertrace.c').read_text()
start = source.index('static hypertrace_vprovider_t *\nhypertrace_find_vprovider(')
end = source.index('static uint64_t\nhypertrace_priv_epoch_byid(', start)
(out / 'provider.inc').write_text(source[start:end])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-pthread',
                '-fsanitize=address,undefined', '-I' + str(out),
                str(Path(__file__).with_name('probe-map.c')), '-o',
                str(out / 'probe-map-test')], check=True)
subprocess.run([str(out / 'probe-map-test')], check=True, timeout=30)
