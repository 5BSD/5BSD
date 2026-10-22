#!/usr/bin/env python3.12
"""Exercise the production DTrace drainability ioctl decision."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/dev/dtrace/dtrace_ioctl.c').read_text()
start = source.index('\tcase DTRACEIOC_DRAINABLE:')
end = source.index('\n\tcase DTRACEIOC_STATUS:', start)
(out / 'consumer-speculation-kernel.inc').write_text(source[start:end] + '\n')
binary = out / 'consumer-speculation-kernel'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
