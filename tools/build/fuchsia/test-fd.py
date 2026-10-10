#!/usr/bin/env python3.12
"""Compile and run the native descriptor/FIDL-wire feasibility test."""
import argparse
import os
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--src', type=Path, default=Path('/usr/src'))
p.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-fidl'))
a = p.parse_args()
a.obj.mkdir(parents=True, exist_ok=True)
exe = a.obj / 'fd-transport-test'
subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                '-Wno-macro-redefined', '-I' + str(a.src / 'sys'),
                '-I' + str(a.src / 'lib/libchannel'),
                '-I' + str(a.src / 'contrib/fuchsia/zircon/system/public'),
                '-I' + str(a.src / 'contrib/fuchsia/sdk/lib/fidl_base/include'),
                str(a.src / 'tools/build/fuchsia/fd_transport_test.c'),
                str(a.src / 'lib/libchannel/channel_syscall.c'), '-o', str(exe)], check=True)
subprocess.run([str(exe.resolve())], check=True, cwd=a.obj)
