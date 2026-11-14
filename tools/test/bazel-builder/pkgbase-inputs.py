#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise original Make pkgbase timestamp/placement inputs on real staged files.

This is a private comparison control, never a native product build action.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--request', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
c = json.loads(args.request.read_text())
required = {'src', 'objtop', 'src_conf', 'stage', 'pkg', 'flua', 'make', 'repository',
            'component', 'version', 'output_prefix', 'jobs', 'abi', 'osversion', 'target',
            'target_arch', 'scenarios'}
if set(c) != required:
    raise ValueError('exact pkgbase input test request required')
paths = {n: Path(c[n]).resolve(strict=True) for n in
         ('src', 'objtop', 'src_conf', 'stage', 'pkg', 'flua', 'make', 'repository')}
if paths['repository'] != Path('/usr/obj/usr/src/repo'):
    raise ValueError('standard repository root required; no alternate update repository')
if args.output.exists() or not args.output.resolve().is_relative_to('/usr/obj'):
    raise ValueError('fresh private object-root test output required')
component = (paths['src'] / c['component']).resolve(strict=True)
if not component.is_relative_to(paths['src'] / 'packages') or not (component / 'Makefile').is_file():
    raise ValueError('maintained package component required')
for key in ('version', 'output_prefix', 'target', 'target_arch'):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', c[key]):
        raise ValueError('safe explicit identity required: ' + key)
if not re.fullmatch(r'FreeBSD:[0-9]+:[A-Za-z0-9_]+', c['abi']) or type(c['osversion']) is not int or c['osversion'] < 1:
    raise ValueError('explicit safe ABI and positive OS version required')
if type(c['jobs']) is not int or c['jobs'] < 1:
    raise ValueError('positive job count required')
if {row['variable'] for row in c['scenarios']} != {'PKG_TIMESTAMP', 'SOURCE_DATE_EPOCH'}:
    raise ValueError('both maintained timestamp input paths required')
if len({row['epoch'] for row in c['scenarios']}) != len(c['scenarios']):
    raise ValueError('distinct epochs required to reject a constant substitute')
for row in c['scenarios']:
    if set(row) != {'variable', 'epoch'} or type(row['epoch']) is not int or not 0 <= row['epoch'] <= 2**63 - 1:
        raise ValueError('explicit nonnegative timestamp scenario required')
sys.path.insert(0, str(paths['src'] / 'tools/build/bazel'))
import archive_headers


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pointers():
    root = paths['repository'] / c['abi']
    return {name: os.readlink(root / name) if (root / name).is_symlink() else None
            for name in ('latest', 'latest-built')}


output = args.output.resolve()
output.mkdir()
shutil.copyfile(__file__, output / 'driver.py')
inputs = [args.request.resolve(), Path(__file__).resolve(), paths['pkg'], paths['flua'],
          paths['make'], paths['src_conf'], component / 'Makefile',
          paths['src'] / 'share/mk/bsd.pkg.mk', paths['src'] / 'share/mk/bsd.pkg.pre.mk',
          Path(archive_headers.__file__).resolve(), archive_headers.LIBRARY, Path('/usr/bin/bsdtar')]
report = {'status': 'running', 'scope': 'Actual original Make pkgbase timestamp/placement inputs; no world rebuild, native product action, publication or installation',
          'inputs_sha256': {str(p): digest(p) for p in inputs},
          'pointers_before': pointers(), 'scenarios': []}
try:
    for index, scenario in enumerate(c['scenarios']):
        label = c['output_prefix'] + '-' + str(index)
        destination = paths['repository'] / c['abi'] / label
        if destination.exists():
            raise ValueError('fresh archive output subdirectory required')
        objects = output / ('objects-' + str(index))
        objects.mkdir()
        env = dict(os.environ, MAKEFLAGS='', MAKEOBJDIR='${REFERENCE_OBJROOT}${.CURDIR}',
                   REFERENCE_OBJROOT=str(objects), LC_ALL='C')
        env.pop('PKG_TIMESTAMP', None)
        env.pop('SOURCE_DATE_EPOCH', None)
        command = [str(paths['make']), '-C', str(component), '-j' + str(c['jobs']),
                   'SRCTOP=' + str(paths['src']), 'OBJTOP=' + str(paths['objtop']),
                   'SRCCONF=' + str(paths['src_conf']), '__MAKE_CONF=/dev/null',
                   'TARGET=' + c['target'], 'TARGET_ARCH=' + c['target_arch'],
                   'REPODIR=' + str(paths['repository']), 'WSTAGEDIR=' + str(paths['stage']),
                   'PKG_CMD=' + str(paths['pkg']), 'FLUA=' + str(paths['flua']),
                   'PKG_VERSION=' + c['version'], 'PKG_OUTPUT_DIR=' + label,
                   'PKG_ABI=' + c['abi'], 'PKG_OSVERSION=' + str(c['osversion']),
                   'PKG_CTHREADS=1', 'MK_AUTO_OBJ=yes',
                   scenario['variable'] + '=' + str(scenario['epoch']), 'stagepackages']
        with (output / (label + '.stdout')).open('wb') as stdout, (output / (label + '.stderr')).open('wb') as stderr:
            subprocess.run(command, env=env, stdout=stdout, stderr=stderr, check=True)
        archives = sorted(destination.glob('*.pkg'))
        if not archives:
            raise ValueError('package output placement input was not honored')
        record = {'input': scenario, 'argv': command, 'output': str(destination), 'packages': {}}
        for archive in archives:
            headers = archive_headers.read(archive)
            metadata = [row for row in headers if row['pathname'] in ('+MANIFEST', '+COMPACT_MANIFEST')]
            payload = [row for row in headers if row['pathname'] not in ('+MANIFEST', '+COMPACT_MANIFEST')]
            # pkg's packing_append_buffer creates format metadata without a
            # timestamp; pkg -t controls installed payload and manifest files.
            if len(metadata) != 2 or {row['pathname'] for row in metadata} != {'+MANIFEST', '+COMPACT_MANIFEST'}:
                raise ValueError('complete distinct package metadata headers required')
            if any(row['mtime'] != 0 or row['mtime_nsec'] != 0 for row in metadata):
                raise ValueError('unexpected package format metadata timestamp')
            if any(row['mtime'] != scenario['epoch'] or row['mtime_nsec'] != 0 for row in payload):
                raise ValueError('archive payload timestamps differ from input: ' + archive.name)
            manifest = json.loads(subprocess.check_output(['/usr/bin/bsdtar', '-xOf', str(archive), '+MANIFEST']))
            if manifest['version'] != c['version']:
                raise ValueError('output placement changed package version')
            values = manifest.get('files', {}).values()
            if any(not isinstance(row, dict) or row.get('mtime', 0) != scenario['epoch'] for row in values):
                raise ValueError('manifest file timestamp differs from input')
            record['packages'][archive.name] = digest(archive)
        report['scenarios'].append(record)
    if pointers() != report['pointers_before']:
        raise ValueError('qualification advanced repository pointers')
    if any(digest(Path(n)) != value for n, value in report['inputs_sha256'].items()):
        raise ValueError('test input changed')
    report.update(status='passed', pointers_after=pointers())
except Exception as error:
    report.update(status='failed', error=repr(error))
    raise
finally:
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    shutil.copyfile(args.request, output / 'request.json')
print(output / 'result.json')
