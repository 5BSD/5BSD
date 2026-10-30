#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compile ordinary clients against captured staged capability library payloads.

Checks installed-archive selection and shared loading; not live channel IPC.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile

p = argparse.ArgumentParser(description=__doc__)
for name in ('qualification', 'compiler', 'linker', 'sysroot', 'resource-dir', 'source', 'dof-verifier', 'output'):
    p.add_argument('--' + name, type=Path, required=True)
p.add_argument('--target', required=True)
a = p.parse_args()
out = a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out == Path('/usr/obj'):
    p.error('fresh output below /usr/obj required')
q = a.qualification.resolve(strict=True)
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
m = q / 'artifacts/manifest.json'
assert digest(m) == json.loads((q / 'receipt.json').read_text())['artifacts']['sha256']
manifest = json.loads(m.read_text())
out.mkdir()
inputs = {str(path.resolve()): digest(path) for path in (a.compiler, a.linker, a.source, a.dof_verifier, m)}
stages = {}
for lib, label in [('capsulert', '//lib/libcapsulert:install_archive'), ('channel', '//lib/libchannel:library_install_archive')]:
    target = next(t for t in manifest['targets'] if t['target']['label'] == label)
    records = [r for r in target['outputs'] if r['name'].endswith('.tar')]
    assert len(records) == 1
    record = records[0]; blob = q / 'artifacts' / record['file']
    assert digest(blob) == record['sha256']; inputs[str(blob)] = record['sha256']
    stage = out / 'stage' / lib; stage.mkdir(parents=True)
    with tarfile.open(blob) as archive: archive.extractall(stage, filter='tar')
    stages[lib] = stage
sysroot = a.sysroot.resolve(strict=True)
resource = a.resource_dir.resolve(strict=True)
commands, cases = [], {}
spec = importlib.util.spec_from_file_location('dof', a.dof_verifier)
dof = importlib.util.module_from_spec(spec); spec.loader.exec_module(dof)
def run(name, argv, env):
    result = subprocess.run(argv, env=env, cwd=out, capture_output=True, text=True, timeout=60)
    (out / (name + '.stdout')).write_text(result.stdout)
    (out / (name + '.stderr')).write_text(result.stderr)
    commands.append({'name': name, 'argv': argv, 'environment': env, 'returncode': result.returncode})
    (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    assert result.returncode == 0, (name, result.stderr)
    return result.stdout + result.stderr
expected_providers = {provider['name'] for lib, stage in stages.items()
    for provider in dof.inventory(stage / ('usr/lib/lib' + lib + '.so.1'))['providers']}
base = [str(a.compiler.resolve()), '--target=' + a.target, '--sysroot=' + str(sysroot),
        '-resource-dir=' + str(resource), '--ld-path=' + str(a.linker.resolve()),
        '-O2', '-g', '-ffunction-sections', '-fdata-sections']
for stage in stages.values(): base += ['-I' + str(stage / 'usr/include')]
base += ['-L' + str(stages['capsulert'] / 'usr/lib'), '-L' + str(stages['channel'] / 'usr/lib')]
env = {'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'}
for name, flags in [('static', ['-static']), ('static-gc', ['-static', '-Wl,--gc-sections']),
                    ('unused-static', ['-static', '-Wl,--gc-sections', '-DCLIENT_UNUSED']),
                    ('shared', ['-fPIE', '-pie'])]:
    binary = out / name
    depfile = out / (name + '.d')
    cmd = base + flags + ['-MD', '-MF', str(depfile), '-Wl,-t', str(a.source.resolve()),
                          '-lcapsulert', '-lchannel', '-lprivateucl', '-lm', '-o', str(binary)]
    trace = run(name + '-link', cmd, env)
    # Reject unintended host header/library input; keep hashes of actual inputs.
    deps = shlex.split(depfile.read_text().replace('\\\n', ' ').split(':', 1)[1])
    allowed = [sysroot, resource, out / 'stage']
    for word in deps:
        path = Path(word).resolve(strict=True)
        assert path == a.source.resolve() or any(path.is_relative_to(root) for root in allowed), str(path)
        inputs[str(path)] = digest(path)
    for line in trace.splitlines():
        path = Path(line.split('(', 1)[0])
        if not path.is_absolute() or not path.is_file(): continue
        resolved = path.resolve(strict=True)
        assert resolved.is_relative_to(out) or resolved.is_relative_to(sysroot) or resolved.is_relative_to(resource), str(path)
        inputs[str(resolved)] = digest(resolved)
    if name == 'shared':
        runtime = dict(env, LD_LIBRARY_PATH=':'.join([str(stages['capsulert'] / 'usr/lib'),
            str(stages['channel'] / 'usr/lib'), str(sysroot / 'lib'), str(sysroot / 'usr/lib')]))
        loader = run(name + '-loader', [str(binary)], dict(runtime, LD_TRACE_LOADED_OBJECTS='1'))
        for lib in ('capsulert', 'channel'):
            soname = 'lib' + lib + '.so.1'; expected = str(stages[lib] / 'usr/lib' / soname)
            assert any(line.strip().split()[:3] == [soname, '=>', expected] for line in loader.splitlines()), soname
        for line in loader.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[1] == '=>' and fields[2].startswith('/'):
                path = Path(fields[2]).resolve(strict=True)
                assert path.is_relative_to(out) or path.is_relative_to(sysroot), str(path)
                inputs[str(path)] = digest(path)
    else: runtime = env
    output = run(name + '-run', [str(binary)], runtime)
    assert output == 'PASS\n', (name, output)
    check = None
    observed_providers = []
    if name in ('static', 'static-gc'):
        metadata = dof.inventory(binary)
        observed_providers = sorted(p['name'] for p in metadata['providers'])
        assert expected_providers <= set(observed_providers)
        check = dof.validate_amd64_sites(binary, binary, metadata)
    elif name == 'unused-static':
        try:
            metadata = dof.inventory(binary)
            observed_providers = sorted(p['name'] for p in metadata['providers'])
        except ValueError as error:
            assert str(error) == 'no emitted probe metadata'
        assert expected_providers.isdisjoint(observed_providers), 'unused target archive supplied DOF'
    cases[name] = {'sha256': digest(binary), 'bytes': binary.stat().st_size, 'site_checks': check, 'observed_providers': observed_providers}
for path, expected in inputs.items(): assert digest(Path(path)) == expected, path
(out / 'receipt.json').write_text(json.dumps({'status': 'passed', 'scope': __doc__, 'inputs': inputs,
    'cases': cases, 'limitations': ['No live channel IPC, privileged operation, or DTrace firing.',
    'Uses selected staged SDK for libprivateucl and system libraries.',
    'Not an installed-host upgrade or a complete binary pkg repository test.']}, indent=2) + '\n')
(out / 'verify.py').write_bytes(Path(__file__).read_bytes())
print(json.dumps(cases, indent=2))
