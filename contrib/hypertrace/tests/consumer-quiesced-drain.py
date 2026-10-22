#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual libdtrace quiesced-buffer drain without a live VM."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/lib/libdtrace/common/dt_work.c').read_text()
start = source.index('int\ndtrace_consume_quiesced(')
end = source.index('\n}', start) + 2
(out / 'consumer-quiesced-drain.inc').write_text(source[start:end] + '\n')
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'consumer-quiesced-drain-test')], check=True)
subprocess.run([str(out / 'consumer-quiesced-drain-test')],
    check=True, timeout=30)
