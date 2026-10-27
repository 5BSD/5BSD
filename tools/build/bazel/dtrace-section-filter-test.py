#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Verify section-scoped DTrace generation against a captured multi-section action.

This is a bounded build-tool check, not live tracing or a GC integration test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--qualification', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
q = a.qualification.resolve(strict=True)
out = a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out == Path('/usr/obj'):
    p.error('fresh output below /usr/obj required')
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
receipt = json.loads((q / 'receipt.json').read_text())
assert digest(q / 'execution.json') == receipt['execution_log_sha256']
assert digest(q / 'artifacts/manifest.json') == receipt['artifacts']['sha256']
manifest = json.loads((q / 'artifacts/manifest.json').read_text())
uri = manifest['targets'][0]['outputs'][0]['uri']
assert uri.startswith('file://')
root = Path(uri[7:].split('/bazel-out/')[0])
raw = (q / 'execution.json').read_text()
decoder = json.JSONDecoder()
index = 0
actions = []
while index < len(raw):
    while index < len(raw) and raw[index].isspace():
        index += 1
    if index == len(raw):
        break
    action, index = decoder.raw_decode(raw, index)
    if action.get('mnemonic') == 'BSDDTraceArchiveMember' and action.get('targetLabel', '').endswith(':multiple_rewritten'):
        actions.append(action)
assert len(actions) == 1
act = actions[0]
args = act['commandArgs']
inputs = {i['path']: i for i in act['inputs']}
used = {}
def checked(relative):
    path = root / relative
    expected = inputs[relative]['digest']['hash']
    assert digest(path) == expected, relative
    used[str(path)] = expected
    return path
out.mkdir()
shutil.copyfile(checked(args[1]), out / 'input.o')
base = [str(checked(args[5]))]
# Retain the exact action options, resolving tool paths for the fresh cwd.
i = 6
while args[i] != '-G':
    value = args[i]
    if '=' in value and value.split('=', 1)[0] in ('cpppath', 'ldpath', 'objcopypath'):
        key, relative = value.split('=', 1)
        value = key + '=' + str(checked(relative))
    elif value.startswith('syslibdir='):
        relative = value.split('=', 1)[1]
        checked(relative + '/drti.o')
        value = 'syslibdir=' + str(root / relative)
    base.append(value)
    i += 1
provider = args[args.index('-s') + 1]
shutil.copyfile(checked(provider), out / 'provider.d')
env = {'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'}
for item in act['environmentVariables']:
    if item['name'] == 'LD_LIBRARY_PATH':
        dirs = item['value'].split(':')
        env['LD_LIBRARY_PATH'] = ':'.join(str(root / d) for d in dirs)
        for name in inputs:
            if str(Path(name).parent) in dirs:
                checked(name)

def sections(path):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01', 'fixture requires ELF64 LE'
    off = struct.unpack_from('<Q', data, 40)[0]
    size, count, strings = struct.unpack_from('<HHH', data, 58)
    assert size == 64
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, off + i * size) for i in range(count)]
    s = headers[strings]
    names = data[s[4]:s[4] + s[5]]
    return {names[s[0]:].split(b'\0', 1)[0].decode(): (i, data[s[4]:s[4] + s[5]]) for i, s in enumerate(headers)}
original = sections(out / 'input.o')
selected = original['.text.multiple_selected'][0]
unselected = original['.text.multiple_unselected'][0]
records = []
def generate(name, section=None, count=1, reuse=None):
    obj = out / (reuse or (name + '.o'))
    if reuse is None:
        shutil.copyfile(out / 'input.o', obj)
    before = digest(obj)
    command = base + ([] if section is None else ['-x', 'linksection=' + str(section)])
    command += ['-G', '-o', name + '.dof.o', '-s', 'provider.d'] + [obj.name] * count
    result = subprocess.run(command, cwd=out, env=env, capture_output=True, text=True, timeout=30)
    record = dict(name=name, argv=command, returncode=result.returncode, stdout=result.stdout, stderr=result.stderr, before=before, after=digest(obj))
    records.append(record)
    (out / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
    return result.returncode, obj

def references(name):
    text = subprocess.check_output(['/usr/bin/nm', '-u', str(out / (name + '.dof.o'))], text=True)
    return set(re.findall(r'\$dtrace[^.\s]+\.(multiple_\w+)', text))
assert generate('default')[0] == 0
assert references('default') == {'multiple_selected', 'multiple_unselected'}
for name, idx, expected, untouched in [('first', selected, 'multiple_selected', 'multiple_unselected'), ('second', unselected, 'multiple_unselected', 'multiple_selected')]:
    status, obj = generate(name, idx)
    assert status == 0
    assert references(name) == {expected}
    assert sections(obj)['.text.' + untouched][1] == original['.text.' + untouched][1]
    assert sections(obj)['.text.' + expected][1] != original['.text.' + expected][1]
assert generate('sequential', unselected, reuse='first.o')[0] == 0
assert references('sequential') == {'multiple_unselected'}
for function in ['multiple_selected', 'multiple_unselected']:
    assert sections(out / 'first.o')['.text.' + function][1] != original['.text.' + function][1]
assert generate('repeat', unselected, reuse='first.o')[0] == 0
assert (out / 'repeat.dof.o').read_bytes() == (out / 'sequential.dof.o').read_bytes()
# A provider absent from this code section is valid only for section-scoped
# generation. Ordinary linking must retain its missing-provider error.
provider_path = out / 'provider.d'
provider_original = provider_path.read_bytes()
try:
    provider_path.write_bytes(provider_original +
        b'\nprovider absent_provider { probe never(int value); };\n')
    assert generate('extra-provider-default')[0] != 0
    assert generate('extra-provider-section', selected)[0] == 0
    assert references('extra-provider-section') == {'multiple_selected'}
    # The empty .text section must not produce a successful empty DOF.
    assert original['.text'][1] == b''
    assert generate('no-provider-sites', original['.text'][0])[0] != 0
finally:
    provider_path.write_bytes(provider_original)
for n, value in enumerate(['', '0', '-1', '+1', ' 1', '1x', '4294967296', '99999999999999999999999', '4294967295', original['.comment'][0]]):
    assert generate('invalid-' + str(n), value)[0] != 0
    assert records[-1]['before'] == records[-1]['after']
assert generate('multiple-inputs', selected, count=2)[0] != 0
assert records[-1]['before'] == records[-1]['after']
# The member helper must preserve existing outputs and private scratch paths,
# including symlinks to the immutable original input.
member_command = [str(checked(args[0])), str(out / 'input.o'), 'member.o',
                  str(checked(args[3])), '--'] + base + [
    '-G', '-o', 'member.o.dof.o', '-s', str(out / 'provider.d'),
    'member.o.rewrite.o']
for number, collision in enumerate([None, 'member.o', 'member.o.rewrite.o',
                                    'member.o.dof.0.o', 'member.o.linked.o',
                                    'output-symlink', 'copy-symlink']):
    directory = out / ('member-case-' + str(number))
    directory.mkdir()
    existing = None
    if collision is not None:
        if collision.endswith('-symlink'):
            existing = directory / ('member.o' if collision == 'output-symlink' else 'member.o.rewrite.o')
            existing.symlink_to(out / 'input.o')
        else:
            existing = directory / collision
            existing.write_bytes(b'preserve existing artifact\n')
        preserved = digest(existing)
    result = subprocess.run(member_command, cwd=directory, env=env,
                            capture_output=True, text=True, timeout=30)
    record = dict(name='member-' + str(number), argv=member_command,
                  cwd=str(directory), returncode=result.returncode,
                  stdout=result.stdout, stderr=result.stderr)
    records.append(record)
    (out / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
    if collision is None:
        assert result.returncode == 0 and (directory / 'member.o').is_file()
    else:
        assert result.returncode != 0
        assert digest(existing) == preserved, 'existing file changed: ' + str(existing)
        if collision.endswith('-symlink'):
            assert existing.is_symlink()
    assert digest(out / 'input.o') == inputs[args[1]]['digest']['hash']

for path, expected in used.items():
    assert digest(Path(path)) == expected, 'input changed: ' + path
(out / 'receipt.json').write_text(json.dumps(dict(status='passed', scope='default and section-scoped generation; unselected code untouched; sequential/repeated generation; invalid requests rejected before mutation; member output/scratch collision preservation', inputs=used, cases=len(records), limitations=['No live tracing or section association.', 'Fixture parser restricted to ELF64 little-endian.', 'Tools used from execution root with action-log hash checks before and after.']), indent=2) + '\n')
shutil.copyfile(__file__, out / 'verify.py')
print('PASS:', len(records), 'DTrace section-filter cases')
