#!/usr/local/bin/python3.12
"""Build private static OES admission fixtures under the standard /usr/obj."""
from pathlib import Path
import os
import argparse
import shlex
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixture-objtop', type=Path)
args = parser.parse_args()
source = Path('/usr/src')


def value(directory, variable, environment=None):
    return subprocess.check_output(
        ['make', '-C', str(directory), 'NO_SHARED=yes', 'NO_SUBDIR=yes',
         '-V', '${' + variable + '}'],
        env=environment, text=True).strip()


obj = Path(value(source / 'usr.sbin/switchboard', 'OBJTOP'))
if not obj.is_relative_to('/usr/obj/usr/src'):
    raise RuntimeError('standard /usr/obj/usr/src object tree required')
syscalls = obj / 'lib/libsys/libsys.a'
if not syscalls.is_file():
    raise RuntimeError('build the matching object-tree libsys first')
fixtures = (args.fixture_objtop or obj).resolve()
if not fixtures.is_relative_to('/usr/obj/usr/src'):
    raise RuntimeError('fixtures must use standard /usr/obj/usr/src staging')
fixture_objects = fixtures / 'tools/test/oes-admission'
fixture_objects.mkdir(parents=True, exist_ok=True)
fixture_environment = dict(os.environ, MAKEOBJDIR=str(fixture_objects))
# Standalone make dependency paths may refer to installed libraries; always
# relink this private binary against the selected current object-tree archives.
for suffix in ('', '.full', '.debug'):
    (fixture_objects / ('oes_fixture' + suffix)).unlink(missing_ok=True)
fixture_source = source / 'tools/test/oes-admission'
subprocess.run(['make', '-C', str(fixture_source), 'obj'], env=fixture_environment, check=True)
subprocess.run(['make', '-j' + str(os.cpu_count()), '-C', str(fixture_source),
                'LDADD.oes_fixture=' + str(syscalls),
                'all'], env=fixture_environment, check=True)
for name in ('capsule', 'switchboard'):
    directory = source / 'usr.sbin' / name
    private_objects = fixtures / 'tools/test/oes-admission' / (name + '-objects')
    private_objects.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, MAKEOBJDIR=str(private_objects))
    objects = shlex.split(value(directory, 'OBJS', environment))
    libraries = shlex.split(value(directory, 'LDADD', environment))
    # Compile the static objects without changing the normal daemon executable.
    subprocess.run(['make', '-j' + str(os.cpu_count()), '-C', str(directory),
                    'NO_SHARED=yes', 'NO_SUBDIR=yes', *objects],
                   env=environment, check=True)
    # Resolve the new capability syscall ABI before an installed libc can
    # supply older wrappers. Keep the daemon's complete dependency list.
    libraries.insert(libraries.index('-lc'), str(syscalls))
    destination = fixtures / 'tools/test/oes-admission' / name
    subprocess.run(['cc', '-static', '-o', str(destination), *objects, *libraries],
                   cwd=private_objects, check=True)
    if 'statically linked' not in subprocess.check_output(['file', str(destination)], text=True):
        raise RuntimeError('static link required: ' + str(destination))
print('OES admission fixtures built:', fixtures / 'tools/test/oes-admission')
