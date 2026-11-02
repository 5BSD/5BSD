# SPDX-License-Identifier: BSD-2-Clause
"""Exercise only source-reviewed paths before debugger initialization."""
import os
import re
from pathlib import Path
import subprocess

name = Path(__file__).parent.name
assert name in ('lldb', 'lldb-server')
root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
program = root / 'usr.bin/clang' / name / name
assert program.is_file()
env = {'PATH': '/bin:/usr/bin', 'LC_ALL': 'C',
       'HOME': os.environ['TEST_TMPDIR'], 'DTRACE_DOF_INIT_DISABLE': '1'}
# Loader-only inspection precedes execution; the three private DSOs must be native.
expected = {library: (root / directory / library).resolve(strict=True) for directory, library in [
    ('lib/clang/liblldb', 'libprivatelldb.so.21'),
    ('lib/clang/libclang', 'libprivateclang.so.21'),
    ('lib/clang/libllvm', 'libprivatellvm.so.21')]}
trace_env = dict(env, LD_TRACE_LOADED_OBJECTS='1')
trace = subprocess.run([str(program)], env=trace_env, cwd=env['HOME'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=30, check=False)
print('LOADER STDOUT\n' + trace.stdout.decode(errors='replace'), flush=True)
print('LOADER STDERR\n' + trace.stderr.decode(errors='replace'), flush=True)
assert trace.returncode == 0
loaded = dict(re.findall(r'^\s*(\S+) => (\S+)',
                         (trace.stdout + trace.stderr).decode(), re.M))
for library, path in expected.items():
    assert library in loaded and Path(loaded[library]).resolve(strict=True) == path
cases = ([(['--help'], 0, b'USAGE:'),
          (['--native-qualification-unknown-option'], 1, b'unknown option:'),
          (['--file'], 1, b'is missing')]
         if name == 'lldb' else
         [([], 0, b'Usage:'), (['version'], 0, b'lldb version'),
          (['--native-qualification-unknown-command'], 0, b'Usage:')])
for args, status, token in cases:
    result = subprocess.run([str(program), *args], env=env, cwd=env['HOME'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=30, check=False)
    print('CASE', name, args, 'status', result.returncode, flush=True)
    print('STDOUT\n' + result.stdout.decode(errors='replace'), flush=True)
    print('STDERR\n' + result.stderr.decode(errors='replace'), flush=True)
    assert result.returncode == status
    assert token in result.stdout + result.stderr
print('PASS', name, len(cases), 'pre-initialization command paths; no attach/launch/listen')
