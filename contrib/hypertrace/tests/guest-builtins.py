#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run actual DIF string/path/JSON switch arms over synthetic guest page tables."""
from pathlib import Path
import os, re, subprocess, sys
root = Path(__file__).resolve().parents[3]
tests = Path(__file__).resolve().parent
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
sanitizer_env = os.environ.copy()
for name in ('UBSAN_OPTIONS', 'ASAN_OPTIONS'):
    existing = sanitizer_env.get(name, '')
    sanitizer_env[name] = (existing + ':' if existing else '') + 'halt_on_error=1'
subprocess.run([sys.executable, str(tests / 'pagewalk.py'), str(out)],
               check=True, env=sanitizer_env)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
def function(name):
    match = re.search(r'static [^\n]+\n' + name + r'\(', source)
    if not match: raise SystemExit('Missing function: ' + name)
    end = source.index('\n}', match.start()) + 2
    return source[match.start():end]
# pagewalk.c, included first, defines ASSERT and dtrace_strncmp().
parts = [function(name) for name in ('dtrace_canload_tagged', 'dtrace_guest_user_copy',
         'dtrace_strtoll', 'dtrace_strlen', 'dtrace_strjoin',
         'dtrace_store_by_ref')]
start = source.index('typedef enum dtrace_json_state {')
end = source.index('} dtrace_json_state_t;', start) + len('} dtrace_json_state_t;')
parts += [source[start:end], function('dtrace_json')]
(out / 'builtin-helpers.inc').write_text('\n'.join(parts))
markers = [('STRLEN', '\tcase DIF_SUBR_STRCHR:'),
           ('STRCHR', '\tcase DIF_SUBR_STRSTR:'),
           ('BCOPY', '\tcase DIF_SUBR_ALLOCA:'),
           ('ALLOCA', '\tcase DIF_SUBR_COPYINTO:'),
           ('COPYINTO', '\tcase DIF_SUBR_COPYINSTR:'),
           ('COPYINSTR', '\n#ifdef illumos'),
           ('STRSTR', '\tcase DIF_SUBR_STRTOK:'),
           ('STRTOK', '\tcase DIF_SUBR_SUBSTR:'),
           ('SUBSTR', '\tcase DIF_SUBR_JSON:'),
           ('JSON', '\tcase DIF_SUBR_TOUPPER:'),
           ('TOUPPER', '\n#ifdef illumos'),
           ('STRTOLL', '\tcase DIF_SUBR_LLTOSTR:'),
           ('DIRNAME', '\n#ifdef notyet'),
           ('CLEANPATH', '\tcase DIF_SUBR_INET_NTOA:'),
           ('INET_NTOA', '\tcase DIF_SUBR_MEMREF:'),
           ('MEMSTR', '\n#endif')]
arms = []
for name, marker in markers:
    start = source.index('\tcase DIF_SUBR_' + name + ':')
    end = source.index(marker or '\tcase DIF_SUBR_', start + 8)
    arms.append(source[start:end])
(out / 'builtin-arms.inc').write_text('\n'.join(arms))
header = (root / 'sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h').read_text()
names = set(re.findall(r'\bDIF_SUBR_\w+', '\n'.join(arms)))
names.update(('DIF_TYPE_STRING', 'DIF_TF_BYREF', 'DIF_TF_BYUREF', 'DTRACEOPT_STRSIZE'))
(out / 'builtin-constants.inc').write_text('\n'.join(line for line in header.splitlines()
    if re.match(r'#define\s+(\w+)', line) and re.match(r'#define\s+(\w+)', line)[1] in names))
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
               '-Wno-sign-compare', '-fsanitize=address,undefined', '-I' + str(out),
               '-I' + str(root / 'sys/cddl/contrib/opensolaris/common/util'),
               str(tests / 'guest-builtins.c'), '-o', str(out / 'guest-builtins-test')], check=True)
subprocess.run([str(out / 'guest-builtins-test')], check=True, timeout=30,
               env=sanitizer_env)
