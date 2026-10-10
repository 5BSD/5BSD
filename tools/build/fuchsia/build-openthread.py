#!/usr/bin/env python3.12
"""Configure, build, and optionally test the native OpenThread port."""
import argparse
import json
import os
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--src', type=Path, default=Path('/usr/src'))
p.add_argument('--obj', type=Path)
p.add_argument('--platform', choices=['simulation', 'posix'], default='simulation')
p.add_argument('--cmake', default='cmake')
p.add_argument('--ctest', default='ctest')
p.add_argument('--test', action='store_true')
a = p.parse_args()
if a.test and a.platform != 'simulation':
    p.error('--test requires --platform simulation; real radio testing is separate')
obj = a.obj or Path('/usr/obj/5bsd-openthread' + ('-posix' if a.platform == 'posix' else ''))
source = a.src / 'contrib/openthread'
rev = json.loads((source / 'UPSTREAM.5BSD.json').read_text())['commit']
cmd = [a.cmake, '-G', 'Unix Makefiles', '-S', str(source), '-B', str(obj),
       '-DCMAKE_MAKE_PROGRAM=/usr/bin/make', '-DOT_PLATFORM=' + a.platform,
       '-DOT_PACKAGE_VERSION=5bsd-' + rev, '-DUNIFDEFALL_EXE=',
       '-DCMAKE_POLICY_VERSION_MINIMUM=3.5', '-DPython3_EXECUTABLE=' + os.sys.executable,
       '-DBUILD_TESTING=' + ('ON' if a.test else 'OFF')]
if a.platform == 'posix':
    # Use OpenThread's UDP stack. BSD has no IPV6_BOUND_IF/SO_BINDTODEVICE;
    # implementing equivalent receive and transmit scoping is separate work.
    cmd += ['-UREADLINE', '-DOT_DAEMON=ON', '-DOT_READLINE=edit', '-DOT_UPTIME=ON',
            '-DOT_PLATFORM_UDP=OFF']
env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
subprocess.run(cmd, check=True, env=env)
subprocess.run(['/usr/bin/make', '-C', str(obj), '-j' + str(os.cpu_count())], check=True, env=env)
if a.test:
    subprocess.run([a.ctest, '--test-dir', str(obj), '--output-on-failure',
                    '--timeout', '120', '-j', str(os.cpu_count())], check=True, env=env)
