#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import resource, subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('struct dtrace_probe_cookie {')
end = source.index('\n/*\n * If you\'re looking for the epicenter', start)
(out / 'entry.inc').write_text(source[start:end])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
               '-I' + str(out), str(Path(__file__).with_name('probe-entry.c')),
               '-o', str(out / 'probe-entry-test')], check=True)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
subprocess.run([str(out / 'probe-entry-test')], check=True, timeout=30)
