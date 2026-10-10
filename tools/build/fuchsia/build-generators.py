#!/usr/bin/env python3.12
"""Build and test upstream FIDL generators without fetching Go modules."""
import argparse
import os
import shutil
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--src', type=Path, default=Path('/usr/src'))
p.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-fidl'))
p.add_argument('--go', default='go')
p.add_argument('--test', action='store_true')
a = p.parse_args()
obj = a.obj.resolve()
root = (a.src / 'contrib/fuchsia').resolve()
for d in ['gopath', 'gocache', 'tmp']:
    (obj / d).mkdir(parents=True, exist_ok=True)
for name, target in [('go.fuchsia.dev/fuchsia', root),
                     ('github.com/google/go-cmp', root / 'third_party/go-cmp')]:
    link = obj / 'gopath/src' / name
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink():
        if link.resolve() != target:
            raise RuntimeError('Unexpected GOPATH link: ' + str(link))
    else:
        link.symlink_to(target, target_is_directory=True)
env = dict(os.environ, GO111MODULE='off', GOTOOLCHAIN='local', GOPROXY='off',
           GOPATH=str(obj / 'gopath'), GOCACHE=str(obj / 'gocache'),
           GOTMPDIR=str(obj / 'tmp'))
prefix = 'go.fuchsia.dev/fuchsia/tools/fidl/'
for name in ['fidlgen_cpp', 'fidlgen_rust', 'gidl/cmd/gidl']:
    output = obj / Path(name).name
    subprocess.run([a.go, 'build', '-o', str(output), prefix + name], env=env, check=True)
# fidlgen_cpp links the Go runtime statically; ship that toolchain's notice.
goroot = Path(subprocess.check_output([a.go, 'env', 'GOROOT'], env=env, text=True).strip())
(obj / 'go').mkdir(exist_ok=True)
shutil.copyfile(goroot / 'LICENSE', obj / 'go' / 'LICENSE')
if a.test:
    subprocess.run([a.go, 'test', prefix + 'lib/fidlgen'], env=env, check=True)
    subprocess.run([a.go, 'test', prefix + 'lib/fidlgen_cpp', prefix + 'lib/fidlgentest',
                    prefix + 'fidlgen_rust/codegen', '-args', '-fidlc', str(obj / 'fidlc')],
                   env=env, check=True)
