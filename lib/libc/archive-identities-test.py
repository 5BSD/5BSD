# SPDX-License-Identifier: BSD-2-Clause
"""Check real libc archive extraction and source-owned member identities."""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--archive', type=Path, required=True)
p.add_argument('--ar', type=Path, required=True)
p.add_argument('--nm', type=Path, required=True)
a = p.parse_args()
archive = a.archive.resolve(strict=True)
# Resolve runfiles before extraction changes the subprocess working directory.
ar = a.ar.resolve(strict=True)
nm = a.nm.resolve(strict=True)
names = subprocess.check_output([str(ar), 't', str(archive)], text=True).splitlines()
assert names and all(Path(name).name == name for name in names)
duplicates = {name: count for name, count in Counter(names).items() if count > 1}
assert not duplicates, ('duplicate archive member names', duplicates)
folded = {name: count for name, count in Counter(name.casefold() for name in names).items() if count > 1}
assert not folded, ('case-folding archive member collision', folded)
expected = {'div.o', 'jemalloc_div.o', 'gdtoa_misc.o', 'C99_Exit.o', '_exit.o'}
assert expected <= set(names), expected - set(names)
with tempfile.TemporaryDirectory() as root:
    root = Path(root)
    subprocess.run([str(ar), 'x', str(archive), *sorted(expected)], cwd=root, check=True)
    assert {v.name for v in root.iterdir()} == expected
    assert all(v.read_bytes().startswith(b'\x7fELF') for v in root.iterdir())
    assert hashlib.sha256((root/'div.o').read_bytes()).digest() != hashlib.sha256((root/'jemalloc_div.o').read_bytes()).digest()
    def symbols(name):
        result = subprocess.check_output([str(nm), '--defined-only', '--extern-only', '--format=posix', str(root/name)], text=True)
        return {line.split()[0] for line in result.splitlines() if line.split()}
    public = symbols('div.o')
    allocator = symbols('jemalloc_div.o')
    assert 'div' in public and '__je_div_init' not in public
    assert '__je_div_init' in allocator and 'div' not in allocator
print('PASS: unique case-safe archive members; independent public and allocator div extraction')
