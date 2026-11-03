#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise explicit bzip2/bzip2recover binaries with multiblock corruption."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def verify(program, recover, library, runtime_dirs, work):
    inputs = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in (program, recover, library)}
    env = {'PATH': '/bin:/usr/bin', 'LC_ALL': 'C',
           'LD_LIBRARY_PATH': ':'.join(str(p) for p in [library.parent, *runtime_dirs])}
    trace = subprocess.check_output([str(program)], env=dict(env, LD_TRACE_LOADED_OBJECTS='1'), text=True)
    match = re.search(r'^\s*' + re.escape(library.name) + r' => (\S+)', trace, re.M)
    if not match or Path(match.group(1)).resolve() != library.resolve():
        raise ValueError('program did not load the selected library')
    commands = []
    def run(argv, cwd, data=None):
        result = subprocess.run([str(p) for p in argv], input=data, cwd=cwd,
                                env=env, capture_output=True, timeout=60)
        commands.append({'argv': [str(p) for p in argv], 'cwd': str(cwd),
                         'status': result.returncode,
                         'stderr': result.stderr.decode('utf-8', errors='replace')})
        return result
    # Deterministic incompressible input exceeds the requested 100 KB block size.
    raw = b''.join(hashlib.sha256(i.to_bytes(8, 'big')).digest() for i in range(12000))
    encoded = run([program, '-1c'], work, raw)
    if encoded.returncode:
        raise ValueError('fixture compression failed')
    compressed = encoded.stdout
    baseline = run([program, '-dc'], work, compressed)
    if baseline.returncode or baseline.stdout != raw:
        raise ValueError('fixture round trip failed')
    def recover_blocks(name, data):
        directory = work / name
        directory.mkdir()
        source = directory / 'input.bz2'
        source.write_bytes(data)
        result = run([recover, source.name], directory)
        if result.returncode:
            raise ValueError('recovery failed: ' + name)
        files = sorted(directory.glob('rec*input.bz2'))
        if len(files) < 2:
            raise ValueError('fixture did not exercise multiple recovered blocks')
        return [run([program, '-dc', p.name], directory) for p in files]
    healthy = recover_blocks('healthy', compressed)
    if any(r.returncode for r in healthy) or b''.join(r.stdout for r in healthy) != raw:
        raise ValueError('healthy recovered blocks differ from input')
    # BZhN is followed by a six-byte block marker and four-byte block CRC.
    # Damage the first block CRC without changing boundaries or later blocks.
    if compressed[:3] != b'BZh' or compressed[4:10] != bytes.fromhex('314159265359'):
        raise ValueError('unexpected bzip2 stream framing')
    damaged = bytearray(compressed)
    damaged[10] ^= 1
    whole = run([program, '-dc'], work, damaged)
    if whole.returncode == 0:
        raise ValueError('corrupt whole stream was accepted')
    recovered = recover_blocks('damaged', damaged)
    if len(recovered) != len(healthy) or recovered[0].returncode == 0:
        raise ValueError('first damaged block was not rejected')
    for expected, actual in zip(healthy[1:], recovered[1:]):
        if actual.returncode or actual.stdout != expected.stdout:
            raise ValueError('undamaged recovered block differs')
    missing = run([recover, 'does-not-exist.bz2'], work)
    if missing.returncode == 0:
        raise ValueError('missing input was accepted')
    for name, expected in inputs.items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
            raise ValueError('executable/library changed during qualification')
    return {'status': 'passed', 'scope': 'explicit packaged program recovery runtime',
            'inputs': inputs, 'input_bytes': len(raw), 'recovered_blocks': len(healthy),
            'healthy_exact_roundtrip': True, 'damaged_stream_rejected': True,
            'damaged_first_block_rejected': True,
            'intact_blocks_recovered_exactly': len(healthy)-1,
            'missing_input_rejected': True, 'loader_trace': trace, 'commands': commands,
            'limitations': ['Uses external selected libc/libsys and host loader/kernel.',
                            'Not a package-manager installation or dependency-solver test.']}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('program', 'recover', 'library'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    runtime = [Path(d) for d in os.environ.get('LD_LIBRARY_PATH', '').split(':') if d]
    with tempfile.TemporaryDirectory(prefix='recovery-', dir=os.environ['TEST_TMPDIR']) as temporary:
        result = verify(a.program.resolve(strict=True), a.recover.resolve(strict=True),
                        a.library.absolute(), runtime, Path(temporary))
    output = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']) / 'recovery.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print('healthy multiblock recovery, CRC rejection and intact block recovery: passed')
